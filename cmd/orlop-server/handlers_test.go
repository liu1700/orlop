package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const testAgent = "yuchen@example.com"
const testTenant = "tenant-a"

func newTestState(t *testing.T, allow, deny []string) *serverState {
	t.Helper()
	root := t.TempDir()
	storeRoot := filepath.Join(root, "store")
	mustMkdirAll(t, filepath.Join(storeRoot, "docs"))
	mustWriteFile(t, filepath.Join(storeRoot, "docs", "profile.json"), `{"name":"Yuchen"}`)
	mustWriteFile(t, filepath.Join(storeRoot, "docs", "secret.txt"), "shh")

	dbPath := filepath.Join(root, "routes.db")
	createSchema(t, dbPath)

	cfg := Config{
		AuditLog:    filepath.Join(root, "audit.log"),
		StoreRoot:   storeRoot,
		RoutesDB:    dbPath,
		TenantID:    testTenant,
		TrustDomain: "orlop.example",
		Tenants: []TenantConfig{{
			ID:        testTenant,
			Name:      testTenant,
			StoreRoot: storeRoot,
			RoutesDB:  dbPath,
		}},
		Allow: allow,
		Deny:  deny,
	}
	state, err := newServerState(cfg, contextIdentifier{}, nil)
	if err != nil {
		t.Fatalf("newServerState: %v", err)
	}
	t.Cleanup(func() { _ = state.Close() })
	return state
}

func createSchema(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(testSchemaSQL); err != nil {
		t.Fatalf("create schema: %v", err)
	}
}

func doRequest(state *serverState, method, target string, body io.Reader) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, body)
	req = req.WithContext(WithIdentity(context.Background(), testIdentity()))
	rr := httptest.NewRecorder()
	newRouter(state).ServeHTTP(rr, req)
	return rr
}

func decodeBody[T any](t *testing.T, rr *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.NewDecoder(rr.Body).Decode(&v); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return v
}

func testIdentity() Identity {
	return Identity{
		AgentID:     testAgent,
		TenantID:    testTenant,
		CertSerial:  "123",
		CertSubject: "CN=" + testAgent,
	}
}

func TestUnauthenticatedRequestRejected(t *testing.T) {
	state := newTestState(t, nil, nil)
	req := httptest.NewRequest("GET", "/audit", nil) // no identity in context
	rr := httptest.NewRecorder()
	newRouter(state).ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestAuditEndpointReturnsRecordedEvents(t *testing.T) {
	state := newTestState(t, nil, nil)
	state.audit.Record(AuditRecord{
		Event:    "get_file",
		Path:     "/docs/profile.json",
		AgentID:  testAgent,
		TenantID: testTenant,
		Allowed:  true,
	})
	if err := state.audit.file.Sync(); err != nil {
		t.Fatalf("sync: %v", err)
	}

	rr := doRequest(state, "GET", "/audit", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	resp := decodeBody[auditResp](t, rr)
	if len(resp.Events) == 0 {
		t.Fatalf("no events returned")
	}
}

func TestPolicyPathStripsMountSegment(t *testing.T) {
	cases := map[string]string{
		"/docs/profile.json": "profile.json",
		"/docs":              "",
		"/docs/":             "",
		"/":                  "",
	}
	for in, want := range cases {
		if got := policyPath(in); got != want {
			t.Errorf("policyPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPolicyDenyTakesPrecedence(t *testing.T) {
	p, err := NewPolicy([]string{"**"}, []string{"**/secrets/**"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Permits("docs/secrets/foo") {
		t.Errorf("deny pattern not enforced")
	}
	if !p.Permits("docs/profile.json") {
		t.Errorf("allow pattern not honored")
	}
}

func mustWriteFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func mustMkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}

func readAuditEvents(t *testing.T, path string) []map[string]any {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		events, err := ReadEvents(path)
		if err != nil {
			t.Fatalf("read audit: %v", err)
		}
		if len(events) > 0 {
			return events
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("audit log empty after wait")
	return nil
}
