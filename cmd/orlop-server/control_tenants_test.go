package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/liu1700/orlop/cmd/orlop-server/internal/quota"
)

// fakeExec records every exec.Run call and returns nil (success).
type fakeExec struct {
	calls []fakeExecCall
}

type fakeExecCall struct {
	name string
	args []string
}

func (f *fakeExec) Run(_ context.Context, name string, args ...string) error {
	f.calls = append(f.calls, fakeExecCall{name: name, args: args})
	return nil
}

// newAdminTestState builds a serverState with TenantsRoot and quota wired up.
func newAdminTestState(t *testing.T, exec quota.Exec) (*serverState, string) {
	t.Helper()
	root := t.TempDir()
	tenantsRoot := filepath.Join(root, "tenants")
	if err := os.MkdirAll(tenantsRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	storeRoot := filepath.Join(root, "static-store")
	mustMkdirAll(t, storeRoot)
	dbPath := filepath.Join(root, "routes.db")
	createSchema(t, dbPath)

	registeredPath := filepath.Join(root, "registered_tenants.json")
	quotaStatePath := filepath.Join(root, "quota_state.json")

	qm, err := quota.NewManager(quotaStatePath, tenantsRoot, exec, nil, true)
	if err != nil {
		t.Fatalf("quota.NewManager: %v", err)
	}

	cfg := Config{
		AuditLog:              filepath.Join(root, "audit.log"),
		StoreRoot:             storeRoot,
		RoutesDB:              dbPath,
		TenantID:              testTenant,
		TrustDomain:           "orlop.example",
		Tenants:               []TenantConfig{{ID: testTenant, Name: testTenant, StoreRoot: storeRoot, RoutesDB: dbPath}},
		TenantsRoot:           tenantsRoot,
		RegisteredTenantsPath: registeredPath,
	}
	state, err := newServerState(cfg, contextIdentifier{}, nil)
	if err != nil {
		t.Fatalf("newServerState: %v", err)
	}
	// Replace quota manager with our injected fake-exec one.
	state.quota = qm
	t.Cleanup(func() { _ = state.Close() })
	return state, root
}

func doAdminRequest(state *serverState, method, target string, body any) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		panic(err)
	}
	req := httptest.NewRequest(method, target, &buf)
	req = req.WithContext(WithIdentity(req.Context(), Identity{
		AgentID:  "orlop-control",
		TenantID: controlPlaneTenantID,
	}))
	rr := httptest.NewRecorder()
	newRouter(state).ServeHTTP(rr, req)
	return rr
}

func TestRegisterTenantHappyPath(t *testing.T) {
	exec := &fakeExec{}
	state, _ := newAdminTestState(t, exec)

	body := registerTenantRequest{TenantID: "acme", Name: "Acme Corp", SizeBytes: 1 << 30}
	rr := doAdminRequest(state, http.MethodPost, "/control/tenants", body)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rr.Code, rr.Body.String())
	}

	var resp registerTenantResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.TenantID != "acme" {
		t.Errorf("tenant_id = %q", resp.TenantID)
	}
	if resp.ProjectID == 0 {
		t.Errorf("project_id = 0")
	}
	if resp.SizeBytes != 1<<30 {
		t.Errorf("size_bytes = %d", resp.SizeBytes)
	}

	// Tenant must be live in state.
	if _, ok := state.tenant("acme"); !ok {
		t.Error("tenant not registered in state")
	}

	// Quota must have a record for the registered tenant.
	pid, size, ok := state.quota.Lookup("acme")
	if !ok {
		t.Error("quota.Lookup(acme) returned not-ok")
	}
	if pid == 0 {
		t.Error("quota project_id = 0")
	}
	if size != 1<<30 {
		t.Errorf("quota size = %d, want %d", size, 1<<30)
	}
}

func TestResizeTenantGrowsQuota(t *testing.T) {
	exec := &fakeExec{}
	state, _ := newAdminTestState(t, exec)

	reg := registerTenantRequest{TenantID: "acme", Name: "Acme Corp", SizeBytes: 1 << 30}
	if rr := doAdminRequest(state, http.MethodPost, "/control/tenants", reg); rr.Code != http.StatusOK {
		t.Fatalf("register: status = %d body = %s", rr.Code, rr.Body.String())
	}

	rr := doAdminRequest(state, http.MethodPatch, "/control/tenants/acme", resizeTenantRequest{SizeBytes: 4 << 30})
	if rr.Code != http.StatusOK {
		t.Fatalf("resize: status = %d body = %s", rr.Code, rr.Body.String())
	}
	var resp registerTenantResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.SizeBytes != 4<<30 {
		t.Errorf("size_bytes = %d, want %d", resp.SizeBytes, int64(4<<30))
	}
	// The kernel-quota record must reflect the new size; project ID preserved.
	if _, size, ok := state.quota.Lookup("acme"); !ok || size != 4<<30 {
		t.Errorf("quota.Lookup(acme) size=%d ok=%v, want %d", size, ok, int64(4<<30))
	}
}

func TestResizeTenantUnknown(t *testing.T) {
	exec := &fakeExec{}
	state, _ := newAdminTestState(t, exec)
	rr := doAdminRequest(state, http.MethodPatch, "/control/tenants/ghost", resizeTenantRequest{SizeBytes: 1 << 30})
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d body = %s, want 404", rr.Code, rr.Body.String())
	}
}

func TestResizeTenantInvalidSize(t *testing.T) {
	exec := &fakeExec{}
	state, _ := newAdminTestState(t, exec)
	reg := registerTenantRequest{TenantID: "acme", Name: "Acme Corp", SizeBytes: 1 << 30}
	if rr := doAdminRequest(state, http.MethodPost, "/control/tenants", reg); rr.Code != http.StatusOK {
		t.Fatalf("register: status = %d body = %s", rr.Code, rr.Body.String())
	}
	rr := doAdminRequest(state, http.MethodPatch, "/control/tenants/acme", resizeTenantRequest{SizeBytes: 0})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body = %s, want 400", rr.Code, rr.Body.String())
	}
}

func TestUnregisterTenantDropsStateAndPersistence(t *testing.T) {
	// Acceptance criterion for the anonymous per-session-tenant cleanup
	// path: DELETE /control/tenants/{id} must drop the tenant from
	// in-memory state, remove it from registered_tenants.json, and
	// delete the on-disk tenant directory.
	exec := &fakeExec{}
	state, root := newAdminTestState(t, exec)

	// First: register a tenant so we have something to remove.
	body := registerTenantRequest{TenantID: "anon_abc123", Name: "Anonymous abc", SizeBytes: 1 << 30}
	if rr := doAdminRequest(state, http.MethodPost, "/control/tenants", body); rr.Code != http.StatusOK {
		t.Fatalf("register: status = %d body = %s", rr.Code, rr.Body.String())
	}
	if _, ok := state.tenant("anon_abc123"); !ok {
		t.Fatal("precondition: tenant not registered")
	}

	// Delete it.
	rr := doAdminRequest(state, http.MethodDelete, "/control/tenants/anon_abc123", nil)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("delete: status = %d body = %s", rr.Code, rr.Body.String())
	}

	// In-memory state dropped.
	if _, ok := state.tenant("anon_abc123"); ok {
		t.Error("tenant still in state after delete")
	}

	// On-disk directory removed.
	tenantDir := filepath.Join(state.adminCfg.TenantsRoot, "anon_abc123")
	if _, err := os.Stat(tenantDir); !os.IsNotExist(err) {
		t.Errorf("tenant dir still on disk: stat err = %v", err)
	}

	// registered_tenants.json no longer contains the entry.
	registered, err := loadRegisteredTenants(filepath.Join(root, "registered_tenants.json"))
	if err != nil {
		t.Fatalf("load registered_tenants: %v", err)
	}
	for _, rt := range registered {
		if rt.ID == "anon_abc123" {
			t.Error("registered_tenants.json still lists anon_abc123")
		}
	}

	// Second delete is idempotent — returns 404 but does not error.
	rr = doAdminRequest(state, http.MethodDelete, "/control/tenants/anon_abc123", nil)
	if rr.Code != http.StatusNotFound {
		t.Errorf("second delete: status = %d, want 404", rr.Code)
	}
}

func TestRegisterTenantValidation(t *testing.T) {
	exec := &fakeExec{}
	state, _ := newAdminTestState(t, exec)

	cases := []struct {
		name string
		body registerTenantRequest
	}{
		{"empty tenant_id", registerTenantRequest{TenantID: "", Name: "n", SizeBytes: 100}},
		{"bad chars (slash)", registerTenantRequest{TenantID: "has/slash", Name: "n", SizeBytes: 100}},
		{"bad chars (dot)", registerTenantRequest{TenantID: "has.dot", Name: "n", SizeBytes: 100}},
		{"starts with dash", registerTenantRequest{TenantID: "-bad", Name: "n", SizeBytes: 100}},
		{"empty name", registerTenantRequest{TenantID: "ok", Name: "", SizeBytes: 100}},
		{"zero size", registerTenantRequest{TenantID: "ok", Name: "n", SizeBytes: 0}},
		{"negative size", registerTenantRequest{TenantID: "ok", Name: "n", SizeBytes: -1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := doAdminRequest(state, http.MethodPost, "/control/tenants", tc.body)
			if rr.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400; body = %s", rr.Code, rr.Body.String())
			}
		})
	}
}

func TestRegisterTenantIdempotent(t *testing.T) {
	exec := &fakeExec{}
	state, _ := newAdminTestState(t, exec)

	body := registerTenantRequest{TenantID: "beta", Name: "Beta", SizeBytes: 512 << 20}

	rr1 := doAdminRequest(state, http.MethodPost, "/control/tenants", body)
	if rr1.Code != http.StatusOK {
		t.Fatalf("first POST status = %d body = %s", rr1.Code, rr1.Body.String())
	}
	var resp1 registerTenantResponse
	_ = json.NewDecoder(rr1.Body).Decode(&resp1)

	rr2 := doAdminRequest(state, http.MethodPost, "/control/tenants", body)
	if rr2.Code != http.StatusOK {
		t.Fatalf("second POST status = %d body = %s", rr2.Code, rr2.Body.String())
	}
	var resp2 registerTenantResponse
	_ = json.NewDecoder(rr2.Body).Decode(&resp2)

	if resp1.ProjectID != resp2.ProjectID {
		t.Errorf("project_id mismatch: %d vs %d", resp1.ProjectID, resp2.ProjectID)
	}
}

// Re-registering an account with a different budget re-asserts the shared quota
// (a resize), not a size-mismatch conflict — the account budget legitimately changes
// on a buy/upgrade, and placement re-asserts the current budget each time.
func TestRegisterTenantReregisterResizes(t *testing.T) {
	exec := &fakeExec{}
	state, _ := newAdminTestState(t, exec)

	body := registerTenantRequest{TenantID: "gamma", Name: "Gamma", SizeBytes: 1 << 30}
	rr := doAdminRequest(state, http.MethodPost, "/control/tenants", body)
	if rr.Code != http.StatusOK {
		t.Fatalf("first POST status = %d", rr.Code)
	}

	body.SizeBytes = 2 << 30
	rr = doAdminRequest(state, http.MethodPost, "/control/tenants", body)
	if rr.Code != http.StatusOK {
		t.Fatalf("re-register status = %d body = %s", rr.Code, rr.Body.String())
	}
	if _, sz, ok := state.quota.Lookup("gamma"); !ok || sz != 2<<30 {
		t.Fatalf("account quota not resized: size=%d ok=%v, want 2 GiB", sz, ok)
	}
}

func TestRegisterTenantDisabled(t *testing.T) {
	// State without TenantsRoot set.
	state := newTestState(t, nil, nil)

	body := registerTenantRequest{TenantID: "delta", Name: "Delta", SizeBytes: 1 << 30}
	rr := doAdminRequest(state, http.MethodPost, "/control/tenants", body)
	if rr.Code != http.StatusNotImplemented {
		t.Errorf("status = %d, want 501; body = %s", rr.Code, rr.Body.String())
	}
}

func TestRegisterTenantRestartReloads(t *testing.T) {
	exec := &fakeExec{}
	state, root := newAdminTestState(t, exec)

	body := registerTenantRequest{TenantID: "delta", Name: "Delta Inc", SizeBytes: 256 << 20}
	rr := doAdminRequest(state, http.MethodPost, "/control/tenants", body)
	if rr.Code != http.StatusOK {
		t.Fatalf("register status = %d body = %s", rr.Code, rr.Body.String())
	}
	var origResp registerTenantResponse
	_ = json.NewDecoder(rr.Body).Decode(&origResp)

	_ = state.Close()

	// Rebuild state from same config + registered_tenants.json.
	tenantsRoot := filepath.Join(root, "tenants")
	storeRoot := filepath.Join(root, "static-store")
	dbPath := filepath.Join(root, "routes.db")
	registeredPath := filepath.Join(root, "registered_tenants.json")
	quotaStatePath := filepath.Join(root, "quota_state.json")

	qm, err := quota.NewManager(quotaStatePath, tenantsRoot, exec, nil, true)
	if err != nil {
		t.Fatalf("quota.NewManager: %v", err)
	}

	cfg := Config{
		AuditLog:              filepath.Join(root, "audit.log"),
		StoreRoot:             storeRoot,
		RoutesDB:              dbPath,
		TenantID:              testTenant,
		Tenants:               []TenantConfig{{ID: testTenant, Name: testTenant, StoreRoot: storeRoot, RoutesDB: dbPath}},
		TenantsRoot:           tenantsRoot,
		RegisteredTenantsPath: registeredPath,
	}
	state2, err := newServerState(cfg, contextIdentifier{}, nil)
	if err != nil {
		t.Fatalf("newServerState after restart: %v", err)
	}
	state2.quota = qm
	t.Cleanup(func() { _ = state2.Close() })

	// delta must be present from registered_tenants.json.
	if _, ok := state2.tenant("delta"); !ok {
		t.Fatal("tenant delta not loaded after restart")
	}

	// Idempotent register should return 200 with same project_id.
	rr2 := doAdminRequest(state2, http.MethodPost, "/control/tenants", body)
	if rr2.Code != http.StatusOK {
		t.Fatalf("idempotent after restart status = %d body = %s", rr2.Code, rr2.Body.String())
	}
	var resp2 registerTenantResponse
	_ = json.NewDecoder(rr2.Body).Decode(&resp2)
	if resp2.ProjectID != origResp.ProjectID {
		t.Errorf("project_id after restart = %d, want %d", resp2.ProjectID, origResp.ProjectID)
	}
}

func TestRegisterTenantForbiddenForNonControlPlane(t *testing.T) {
	exec := &fakeExec{}
	state, _ := newAdminTestState(t, exec)

	// Use a tenant cert (not the control-plane sentinel).
	body := registerTenantRequest{TenantID: "acme", Name: "Acme", SizeBytes: 1 << 30}
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(body)
	req := httptest.NewRequest(http.MethodPost, "/control/tenants", &buf)
	// Inject a regular tenant identity — not the control plane.
	req = req.WithContext(WithIdentity(req.Context(), testIdentity()))
	rr := httptest.NewRecorder()
	newRouter(state).ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403; body = %s", rr.Code, rr.Body.String())
	}
}

func TestControlPlaneOnlyMiddlewareRejectsMTLSTenantCert(t *testing.T) {
	exec := &fakeExec{}
	state, _ := newAdminTestState(t, exec)
	state.identifier = certIdentifier{trustDomain: "orlop.example"}

	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(registerTenantRequest{TenantID: "x", Name: "x", SizeBytes: 100})
	req := httptest.NewRequest(http.MethodPost, "/control/tenants", &buf)
	// Attach a regular tenant cert.
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{
		Subject:      pkix.Name{CommonName: testAgent},
		SerialNumber: big.NewInt(55),
		URIs:         []*url.URL{mustParseURL(t, "spiffe://orlop.example/tenant/"+testTenant)},
	}}}
	rr := httptest.NewRecorder()
	newRouter(state).ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rr.Code)
	}
}

func TestControlPlaneOnlyMiddlewareAcceptsMTLSControlPlaneCert(t *testing.T) {
	exec := &fakeExec{}
	state, _ := newAdminTestState(t, exec)
	state.identifier = certIdentifier{trustDomain: "orlop.example"}

	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(registerTenantRequest{TenantID: "epsilon", Name: "Eps", SizeBytes: 100})
	req := httptest.NewRequest(http.MethodPost, "/control/tenants", &buf)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{
		Subject:      pkix.Name{CommonName: "orlop-control"},
		SerialNumber: big.NewInt(1),
		URIs:         []*url.URL{mustParseURL(t, controlPlaneSPIFFE("orlop.example"))},
	}}}
	rr := httptest.NewRecorder()
	newRouter(state).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body = %s", rr.Code, rr.Body.String())
	}
}

func TestRegisterTenantConcurrentSameTenantNoLeak(t *testing.T) {
	exec := &fakeExec{}
	state, _ := newAdminTestState(t, exec)

	const n = 10
	body := registerTenantRequest{TenantID: "acme", Name: "Acme Corp", SizeBytes: 1 << 30}

	type result struct {
		code      int
		projectID uint32
	}
	results := make([]result, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := range n {
		go func() {
			defer wg.Done()
			rr := doAdminRequest(state, http.MethodPost, "/control/tenants", body)
			var resp registerTenantResponse
			_ = json.NewDecoder(rr.Body).Decode(&resp)
			results[i] = result{code: rr.Code, projectID: resp.ProjectID}
		}()
	}
	wg.Wait()

	// Exactly one tenantState in the map.
	state.mu.RLock()
	count := 0
	for id := range state.tenants {
		if id == "acme" {
			count++
		}
	}
	state.mu.RUnlock()
	if count != 1 {
		t.Errorf("tenants[acme] count = %d, want 1", count)
	}

	// Quota has a record.
	pid, size, ok := state.quota.Lookup("acme")
	if !ok || pid == 0 || size != 1<<30 {
		t.Errorf("quota.Lookup(acme) = (%d, %d, %v), want (non-zero, %d, true)", pid, size, ok, 1<<30)
	}

	// All responses are 200 with the same project_id.
	firstPID := results[0].projectID
	for i, r := range results {
		if r.code != http.StatusOK {
			t.Errorf("result[%d] code = %d, want 200", i, r.code)
		}
		if r.projectID != firstPID {
			t.Errorf("result[%d] project_id = %d, want %d", i, r.projectID, firstPID)
		}
	}
}
