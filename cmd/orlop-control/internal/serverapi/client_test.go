package serverapi_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/serverapi"
)

// testCA holds a self-signed CA and a server leaf cert for httptest TLS setup.
type testCA struct {
	cert       *x509.Certificate
	pool       *x509.CertPool
	serverLeaf tls.Certificate
}

func newTestCA(t *testing.T) testCA {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	svrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	svrTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	svrDER, err := x509.CreateCertificate(rand.Reader, svrTmpl, caCert, &svrKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	svrCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: svrDER})
	svrKeyDER, err := x509.MarshalECPrivateKey(svrKey)
	if err != nil {
		t.Fatal(err)
	}
	svrKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: svrKeyDER})
	serverLeaf, err := tls.X509KeyPair(svrCertPEM, svrKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return testCA{cert: caCert, pool: pool, serverLeaf: serverLeaf}
}

// clientCreds returns a self-signed client cert+key (not part of any CA; the
// test server uses RequireAnyClientCert so no CA verification is done on the
// client cert, which is fine — the real validation is the server's SPIFFE check).
func clientCreds(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "orlop-control"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return
}

// startMTLSServer starts an httptest server configured for mTLS using the given CA.
func startMTLSServer(t *testing.T, handler http.Handler, ca testCA) *httptest.Server {
	t.Helper()
	clientCAPool := x509.NewCertPool()
	clientCAPool.AddCert(ca.cert)
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{ca.serverLeaf},
		// Structural check only; SPIFFE validation happens in orlop-server, not tested here.
		ClientAuth: tls.RequireAnyClientCert,
		MinVersion: tls.VersionTLS13,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// newClient builds a serverapi.Client trusting the given CA pool.
func newClient(t *testing.T, caPool *x509.CertPool) *serverapi.Client {
	t.Helper()
	certPEM, keyPEM := clientCreds(t)
	c, err := serverapi.New(serverapi.Config{
		ClientCertPEM: certPEM,
		ClientKeyPEM:  keyPEM,
		ServerCAPool:  caPool,
		Timeout:       5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRegisterTenantHappyPath(t *testing.T) {
	ca := newTestCA(t)
	var gotBody map[string]any
	srv := startMTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/control/tenants" {
			http.Error(w, "unexpected", http.StatusBadRequest)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tenant_id":  "t1",
			"project_id": 42,
			"size_bytes": int64(1 << 30),
		})
	}), ca)

	host := srv.Listener.Addr().String()
	client := newClient(t, ca.pool)

	projectID, err := client.RegisterTenant(context.Background(), host, "t1", "u_t1", "Test Tenant", 1<<30)
	if err != nil {
		t.Fatalf("RegisterTenant: %v", err)
	}
	if projectID != 42 {
		t.Fatalf("project_id = %d, want 42", projectID)
	}
	if gotBody["tenant_id"] != "t1" {
		t.Fatalf("posted tenant_id = %v, want t1", gotBody["tenant_id"])
	}
}

func TestResizeTenantHappyPath(t *testing.T) {
	ca := newTestCA(t)
	var gotBody map[string]any
	var gotMethod, gotPath string
	srv := startMTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tenant_id":  "t1",
			"project_id": 42,
			"size_bytes": int64(4 << 30),
		})
	}), ca)

	host := srv.Listener.Addr().String()
	client := newClient(t, ca.pool)

	projectID, err := client.ResizeTenant(context.Background(), host, "t1", 4<<30)
	if err != nil {
		t.Fatalf("ResizeTenant: %v", err)
	}
	if projectID != 42 {
		t.Fatalf("project_id = %d, want 42", projectID)
	}
	if gotMethod != http.MethodPatch || gotPath != "/control/tenants/t1" {
		t.Fatalf("request = %s %s, want PATCH /control/tenants/t1", gotMethod, gotPath)
	}
	if gotBody["size_bytes"] != float64(4<<30) {
		t.Fatalf("posted size_bytes = %v, want %v", gotBody["size_bytes"], float64(4<<30))
	}
}

func TestResizeTenantQuotaUnavailable(t *testing.T) {
	ca := newTestCA(t)
	srv := startMTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{
				"code":   "fs_quota_unavailable",
				"detail": "setquota failed",
			},
		})
	}), ca)

	host := srv.Listener.Addr().String()
	client := newClient(t, ca.pool)

	if _, err := client.ResizeTenant(context.Background(), host, "t1", 4<<30); !errors.As(err, new(serverapi.ErrQuotaUnavailable)) {
		t.Fatalf("err type = %T, want ErrQuotaUnavailable; err = %v", err, err)
	}
}

func TestRegisterTenantSizeMismatch(t *testing.T) {
	ca := newTestCA(t)
	srv := startMTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{
				"code":                "size_mismatch",
				"message":             "existing allocation differs",
				"existing_size_bytes": float64(2 << 30),
			},
		})
	}), ca)

	host := srv.Listener.Addr().String()
	client := newClient(t, ca.pool)

	_, err := client.RegisterTenant(context.Background(), host, "t1", "u_t1", "T", 1<<30)
	if err == nil {
		t.Fatal("expected error")
	}
	var mm serverapi.ErrSizeMismatch
	if !errors.As(err, &mm) {
		t.Fatalf("err type = %T, want ErrSizeMismatch; err = %v", err, err)
	}
	if mm.Existing != int64(2<<30) {
		t.Fatalf("Existing = %d, want %d", mm.Existing, int64(2<<30))
	}
}

func TestRegisterTenantQuotaUnavailable(t *testing.T) {
	ca := newTestCA(t)
	srv := startMTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{
				"code":   "fs_quota_unavailable",
				"detail": "setquota failed",
			},
		})
	}), ca)

	host := srv.Listener.Addr().String()
	client := newClient(t, ca.pool)

	_, err := client.RegisterTenant(context.Background(), host, "t1", "u_t1", "T", 1<<30)
	if err == nil {
		t.Fatal("expected error")
	}
	var qu serverapi.ErrQuotaUnavailable
	if !errors.As(err, &qu) {
		t.Fatalf("err type = %T, want ErrQuotaUnavailable; err = %v", err, err)
	}
	if qu.Detail != "setquota failed" {
		t.Fatalf("Detail = %q, want %q", qu.Detail, "setquota failed")
	}
}

func TestRegisterTenantOtherError(t *testing.T) {
	ca := newTestCA(t)
	srv := startMTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{
				"code":    "temporarily_unavailable",
				"message": "try again",
			},
		})
	}), ca)

	host := srv.Listener.Addr().String()
	client := newClient(t, ca.pool)

	_, err := client.RegisterTenant(context.Background(), host, "t1", "u_t1", "T", 1<<30)
	if err == nil {
		t.Fatal("expected error")
	}
	var ae serverapi.ErrAdmin
	if !errors.As(err, &ae) {
		t.Fatalf("err type = %T, want ErrAdmin; err = %v", err, err)
	}
	if ae.Status != http.StatusServiceUnavailable {
		t.Fatalf("Status = %d, want 503", ae.Status)
	}
	if ae.Code != "temporarily_unavailable" {
		t.Fatalf("Code = %q", ae.Code)
	}
}

func TestRegisterTenantContextCanceled(t *testing.T) {
	ca := newTestCA(t)
	srv := startMTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}), ca)

	host := srv.Listener.Addr().String()
	client := newClient(t, ca.pool)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := client.RegisterTenant(ctx, host, "t1", "u_t1", "T", 1<<30)
	if err == nil {
		t.Fatal("expected error from canceled context")
	}
}

func TestQueryJournalHappyPath(t *testing.T) {
	ca := newTestCA(t)
	v := uint64(3)
	srv := startMTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
			return
		}
		wantPath := "/control/tenants/t1/journal"
		if r.URL.Path != wantPath {
			http.Error(w, "unexpected path: "+r.URL.Path, http.StatusBadRequest)
			return
		}
		if r.URL.Query().Get("allocation_id") != "alloc_1" {
			http.Error(w, "missing allocation_id", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"entries": []map[string]any{
				{
					"session_id":    "sess_1",
					"allocation_id": "alloc_1",
					"seq":           uint64(1),
					"ts_unix_ms":    int64(1000),
					"path":          "/foo.txt",
					"op":            "create",
					"agent_id":      "agent_a",
					"after_version": v,
				},
			},
			"next_cursor": "1000.5",
		})
	}), ca)

	host := srv.Listener.Addr().String()
	client := newClient(t, ca.pool)

	res, err := client.QueryJournal(context.Background(), host, "t1", "alloc_1", 10, "")
	if err != nil {
		t.Fatalf("QueryJournal: %v", err)
	}
	if len(res.Entries) != 1 {
		t.Fatalf("entries len = %d, want 1", len(res.Entries))
	}
	e := res.Entries[0]
	if e.SessionID != "sess_1" {
		t.Errorf("session_id = %q, want sess_1", e.SessionID)
	}
	if e.AllocationID != "alloc_1" {
		t.Errorf("allocation_id = %q, want alloc_1", e.AllocationID)
	}
	if e.Path != "/foo.txt" {
		t.Errorf("path = %q, want /foo.txt", e.Path)
	}
	if e.Op != "create" {
		t.Errorf("op = %q, want create", e.Op)
	}
	if res.NextCursor != "1000.5" {
		t.Errorf("next_cursor = %q, want 1000.5", res.NextCursor)
	}
}

func TestQueryJournalUnknownTenant404(t *testing.T) {
	ca := newTestCA(t)
	srv := startMTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{
				"code":    "tenant_not_found",
				"message": "no such tenant",
			},
		})
	}), ca)

	host := srv.Listener.Addr().String()
	client := newClient(t, ca.pool)

	_, err := client.QueryJournal(context.Background(), host, "ghost", "", 50, "")
	if err == nil {
		t.Fatal("expected error for 404")
	}
	var ae serverapi.ErrAdmin
	if !errors.As(err, &ae) {
		t.Fatalf("err type = %T, want ErrAdmin; err = %v", err, err)
	}
	if ae.Status != http.StatusNotFound {
		t.Fatalf("Status = %d, want 404", ae.Status)
	}
}

// TestStreamJournalDecodesFrames — the SSE consumer parses `data: <json>`
// frames, skips `:` keepalive comments, and closes the channel on body EOF.
func TestStreamJournalDecodesFrames(t *testing.T) {
	ca := newTestCA(t)
	gotAllocID := make(chan string, 1)
	srv := startMTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAllocID <- r.URL.Query().Get("allocation_id")
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(200)
		flusher := w.(http.Flusher)
		_, _ = w.Write([]byte(": keepalive\n\n"))
		flusher.Flush()
		_, _ = w.Write([]byte(`data: {"session_id":"sess","allocation_id":"alloc","seq":1,"ts_unix_ms":100,"path":"/a","op":"create","agent_id":"agentX"}` + "\n\n"))
		flusher.Flush()
		_, _ = w.Write([]byte(`data: {"session_id":"sess","allocation_id":"alloc","seq":2,"ts_unix_ms":200,"path":"/b","op":"update","agent_id":"agentX"}` + "\n\n"))
		flusher.Flush()
		// Body EOF after both frames; channel must close.
	}), ca)
	host := srv.Listener.Addr().String()
	client := newClient(t, ca.pool)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch, err := client.StreamJournal(ctx, host, "t1", "alloc", 0)
	if err != nil {
		t.Fatalf("StreamJournal: %v", err)
	}
	if got := <-gotAllocID; got != "alloc" {
		t.Fatalf("allocation_id forwarded=%q, want alloc", got)
	}

	first, ok := <-ch
	if !ok {
		t.Fatal("channel closed before first frame")
	}
	if first.Seq != 1 || first.Path != "/a" {
		t.Fatalf("first entry = %+v", first)
	}
	second, ok := <-ch
	if !ok {
		t.Fatal("channel closed before second frame")
	}
	if second.Seq != 2 || second.Op != "update" {
		t.Fatalf("second entry = %+v", second)
	}
	// Channel must close once the body EOFs.
	if _, ok := <-ch; ok {
		t.Fatal("expected channel close after body EOF")
	}
}

// TestStreamJournalContextCancel — cancelling the ctx returns from the
// goroutine and closes the channel.
func TestStreamJournalContextCancel(t *testing.T) {
	ca := newTestCA(t)
	srv := startMTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		flusher := w.(http.Flusher)
		_, _ = w.Write([]byte(": keepalive\n\n"))
		flusher.Flush()
		<-r.Context().Done()
	}), ca)
	host := srv.Listener.Addr().String()
	client := newClient(t, ca.pool)

	ctx, cancel := context.WithCancel(context.Background())
	ch, err := client.StreamJournal(ctx, host, "t1", "alloc", 0)
	if err != nil {
		t.Fatalf("StreamJournal: %v", err)
	}
	cancel()
	// Drain to close. Use a deadline so a hang fails loudly.
	timeout := time.After(2 * time.Second)
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				return
			}
		case <-timeout:
			t.Fatal("channel did not close after ctx cancel")
		}
	}
}

// TestStreamJournalNon200Errors — non-200 status surfaces as an error
// before the goroutine starts.
func TestStreamJournalNon200Errors(t *testing.T) {
	ca := newTestCA(t)
	srv := startMTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	}), ca)
	host := srv.Listener.Addr().String()
	client := newClient(t, ca.pool)

	_, err := client.StreamJournal(context.Background(), host, "t1", "alloc", 0)
	if err == nil {
		t.Fatal("expected error for 403")
	}
}

// TestRevertJournalPathHappyPath — POST body shape and {ok:true} pass-through.
func TestRevertJournalPathHappyPath(t *testing.T) {
	ca := newTestCA(t)
	var gotBody map[string]any
	srv := startMTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/control/tenants/t1/journal/revert" {
			http.Error(w, "unexpected", http.StatusBadRequest)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}), ca)
	host := srv.Listener.Addr().String()
	client := newClient(t, ca.pool)

	res, err := client.RevertJournalPath(context.Background(), host, "t1", "alloc_1", "sess_a", "/p", 7, true, "user:42")
	if err != nil {
		t.Fatalf("revert: %v", err)
	}
	if !res.Ok {
		t.Fatalf("ok=false, want true: %+v", res)
	}
	if gotBody["path"] != "/p" || gotBody["allocation_id"] != "alloc_1" {
		t.Fatalf("body mismatch: %+v", gotBody)
	}
	if gotBody["force"] != true {
		t.Fatalf("force=%v, want true", gotBody["force"])
	}
}

// TestRevertJournalPathConflict — server returns {ok:false, conflict:{...}}.
func TestRevertJournalPathConflict(t *testing.T) {
	ca := newTestCA(t)
	srv := startMTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": false,
			"conflict": map[string]any{
				"reason": "concurrent_writer",
			},
		})
	}), ca)
	host := srv.Listener.Addr().String()
	client := newClient(t, ca.pool)

	res, err := client.RevertJournalPath(context.Background(), host, "t1", "a1", "sess_b", "/p", 1, false, "")
	if err != nil {
		t.Fatalf("revert: %v", err)
	}
	if res.Ok {
		t.Fatalf("ok=true, want false")
	}
	if res.Conflict == nil || res.Conflict.Reason != "concurrent_writer" {
		t.Fatalf("conflict mismatch: %+v", res.Conflict)
	}
}

// TestQueryJournalAfterSeqForwardsCursor — the after_seq query param is
// passed through.
func TestQueryJournalAfterSeqForwardsCursor(t *testing.T) {
	ca := newTestCA(t)
	srv := startMTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("after_seq") != "42" {
			http.Error(w, "missing after_seq", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"entries": []any{}})
	}), ca)
	host := srv.Listener.Addr().String()
	client := newClient(t, ca.pool)

	res, err := client.QueryJournalAfterSeq(context.Background(), host, "t1", "a1", 50, 42)
	if err != nil {
		t.Fatalf("QueryJournalAfterSeq: %v", err)
	}
	if len(res.Entries) != 0 {
		t.Fatalf("entries=%d, want 0", len(res.Entries))
	}
}
