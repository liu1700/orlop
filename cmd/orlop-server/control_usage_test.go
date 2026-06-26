package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestTenantUsage_HappyPath(t *testing.T) {
	exec := &fakeExec{}
	state, root := newAdminTestState(t, exec)

	// Register a tenant so it's known + has a quota record.
	body := registerTenantRequest{TenantID: "acme", Name: "Acme Corp", SizeBytes: 1 << 30}
	if rr := doAdminRequest(state, http.MethodPost, "/control/tenants", body); rr.Code != http.StatusOK {
		t.Fatalf("register status=%d body=%s", rr.Code, rr.Body.String())
	}

	// Drop a regular file under the tenant store and confirm the walker picks it up.
	storeRoot := filepath.Join(root, "tenants", "acme", "store")
	if err := os.WriteFile(filepath.Join(storeRoot, "blob.bin"), make([]byte, 4096), 0o644); err != nil {
		t.Fatalf("write blob: %v", err)
	}

	rr := doAdminRequest(state, http.MethodGet, "/control/tenants/acme/usage", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var resp tenantUsageResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.TenantID != "acme" {
		t.Fatalf("tenant_id = %q, want acme", resp.TenantID)
	}
	if resp.UsedBytes != 4096 {
		t.Fatalf("used_bytes = %d, want 4096", resp.UsedBytes)
	}
	if resp.SizeBytes != 1<<30 {
		t.Fatalf("size_bytes = %d, want %d", resp.SizeBytes, 1<<30)
	}
}

func TestTenantUsage_UnknownTenantReturns404(t *testing.T) {
	exec := &fakeExec{}
	state, _ := newAdminTestState(t, exec)

	rr := doAdminRequest(state, http.MethodGet, "/control/tenants/ghost/usage", nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestTenantUsage_InvalidIDReturns400(t *testing.T) {
	exec := &fakeExec{}
	state, _ := newAdminTestState(t, exec)

	rr := doAdminRequest(state, http.MethodGet, "/control/tenants/has..dots/usage", nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestTenantUsage_RequiresControlPlaneCert(t *testing.T) {
	exec := &fakeExec{}
	state, _ := newAdminTestState(t, exec)

	// No control-plane identity in context => middleware rejects.
	req := httptest.NewRequest(http.MethodGet, "/control/tenants/acme/usage", nil)
	rr := httptest.NewRecorder()
	newRouter(state).ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}
