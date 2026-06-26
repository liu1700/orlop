package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// fakeControl is a minimal stand-in for orlop-control's
// POST /control/sign-server-cert: it signs CSRs with its own ed25519 root and
// can be told to fail the first failN calls (to exercise boot retry).
type fakeControl struct {
	t        *testing.T
	rootCert *x509.Certificate
	rootKey  ed25519.PrivateKey
	rootPEM  []byte
	token    string
	ttl      time.Duration

	calls atomic.Int32
	failN int32 // first failN calls return 503
	allow string
}

func newFakeControl(t *testing.T, token string) *fakeControl {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeControl{
		t:        t,
		rootCert: cert,
		rootKey:  priv,
		rootPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		token:    token,
		ttl:      time.Hour,
		allow:    "orlop-server",
	}
}

func (f *fakeControl) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		n := f.calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+f.token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if n <= f.failN {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		var req signServerCertRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		block, _ := pem.Decode([]byte(req.CSRPEM))
		if block == nil || block.Type != "CERTIFICATE REQUEST" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil || csr.CheckSignature() != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		leafTmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(int64(n) + 100),
			Subject:               pkix.Name{CommonName: f.allow},
			DNSNames:              []string{f.allow},
			NotBefore:             time.Now().Add(-time.Minute),
			NotAfter:              time.Now().Add(f.ttl),
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}
		certDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, f.rootCert, csr.PublicKey, f.rootKey)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		resp := signServerCertResponse{
			CertPEM:     string(certPEM),
			ClientCAPEM: string(f.rootPEM),
			Serial:      "TESTSERIAL",
			ExpiresAt:   leafTmpl.NotAfter.UTC().Format(time.RFC3339),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func testProvisioner(controlURL, token string) *certProvisioner {
	return &certProvisioner{
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		controlURL: controlURL,
		fqdn:       "orlop-server",
		token:      token,
		client:     &http.Client{Timeout: 5 * time.Second},
		maxBackoff: 10 * time.Millisecond,
		now:        time.Now,
	}
}

func TestSignOnceProducesUsableServerCert(t *testing.T) {
	const token = "svc-secret"
	fc := newFakeControl(t, token)
	srv := httptest.NewServer(fc.handler())
	defer srv.Close()

	p := testProvisioner(srv.URL, token)
	sc, err := p.signOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if sc.tlsCert.Leaf == nil {
		t.Fatal("leaf not parsed")
	}
	if len(sc.tlsCert.Leaf.DNSNames) != 1 || sc.tlsCert.Leaf.DNSNames[0] != "orlop-server" {
		t.Fatalf("DNSNames = %v", sc.tlsCert.Leaf.DNSNames)
	}
	if sc.notAfter.IsZero() {
		t.Fatal("notAfter zero")
	}
	// The returned client CA must verify the leaf as server-auth — this is the
	// pool the server hands to clients and uses to verify their certs.
	if _, err := sc.tlsCert.Leaf.Verify(x509.VerifyOptions{
		Roots:     sc.clientCA,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSName:   "orlop-server",
	}); err != nil {
		t.Fatalf("verify leaf against returned client CA: %v", err)
	}
}

func TestSignOnceRejectsBadToken(t *testing.T) {
	fc := newFakeControl(t, "right")
	srv := httptest.NewServer(fc.handler())
	defer srv.Close()

	p := testProvisioner(srv.URL, "wrong")
	if _, err := p.signOnce(context.Background()); err == nil {
		t.Fatal("expected auth failure")
	}
}

func TestProvisionRetriesColdControlPlane(t *testing.T) {
	const token = "svc-secret"
	fc := newFakeControl(t, token)
	fc.failN = 3 // first three calls 503, fourth succeeds
	srv := httptest.NewServer(fc.handler())
	defer srv.Close()

	p := testProvisioner(srv.URL, token)
	sc, err := p.provision(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if sc.tlsCert.Leaf == nil {
		t.Fatal("no cert after retries")
	}
	if got := fc.calls.Load(); got != 4 {
		t.Fatalf("calls = %d, want 4 (3 fail + 1 ok)", got)
	}
}

func TestProvisionRespectsContextCancel(t *testing.T) {
	const token = "svc-secret"
	fc := newFakeControl(t, token)
	fc.failN = 1 << 30 // never succeeds
	srv := httptest.NewServer(fc.handler())
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	p := testProvisioner(srv.URL, token)
	if _, err := p.provision(ctx); err == nil {
		t.Fatal("expected ctx error")
	}
}

func TestSelfProvisionTLSConfigServesCert(t *testing.T) {
	const token = "svc-secret"
	fc := newFakeControl(t, token)
	srv := httptest.NewServer(fc.handler())
	defer srv.Close()

	cfg := Config{TLSSelfProvision: true, ControlURL: srv.URL, ServiceToken: token, ServerFQDN: "orlop-server"}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tlsConfig, err := selfProvisionTLSConfig(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if tlsConfig.ClientAuth != 0 && tlsConfig.GetCertificate == nil {
		t.Fatal("GetCertificate not set")
	}
	cert, err := tlsConfig.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil || cert == nil || cert.Leaf == nil {
		t.Fatalf("GetCertificate returned %v, %v", cert, err)
	}
	if cert.Leaf.DNSNames[0] != "orlop-server" {
		t.Fatalf("served cert DNS = %v", cert.Leaf.DNSNames)
	}
	if tlsConfig.ClientCAs == nil {
		t.Fatal("ClientCAs nil")
	}
	if tlsConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion = %x", tlsConfig.MinVersion)
	}
}

func TestNewCertProvisionerValidates(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := newCertProvisioner(logger, Config{ServiceToken: "x"}); err == nil {
		t.Fatal("expected error without control_url")
	}
	if _, err := newCertProvisioner(logger, Config{ControlURL: "http://x"}); err == nil {
		t.Fatal("expected error without service token")
	}
	p, err := newCertProvisioner(logger, Config{ControlURL: "http://x", ServiceToken: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if p.fqdn != defaultServerFQDN {
		t.Fatalf("fqdn default = %q", p.fqdn)
	}
}

func TestRotateAfterFlooredAndProportional(t *testing.T) {
	p := testProvisioner("http://x", "t")
	base := time.Unix(1_700_000_000, 0)
	p.now = func() time.Time { return base }

	// 90 days out -> ~60 days (two-thirds).
	got := p.rotateAfter(base.Add(90 * 24 * time.Hour))
	if want := 60 * 24 * time.Hour; got != want {
		t.Fatalf("rotateAfter(90d) = %s, want %s", got, want)
	}
	// Already near expiry -> floored at one minute (never busy-loop).
	if got := p.rotateAfter(base.Add(10 * time.Second)); got != time.Minute {
		t.Fatalf("rotateAfter(near) = %s, want 1m", got)
	}
}
