package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// insertJournalRowDirect appends a create row into the given tenantState's journal.
func insertJournalRowDirect(t *testing.T, ts *tenantState, sessionID, allocationID, agentID, path string) {
	t.Helper()
	db := ts.db.DB()
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	if err := appendJournal(tx, sessionID, allocationID, agentID, SessionOpCreate, path,
		nil, nil, nil, "", nil); err != nil {
		_ = tx.Rollback()
		t.Fatalf("appendJournal: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

func TestControlJournalQuery_HappyPath(t *testing.T) {
	exec := &fakeExec{}
	state, _ := newAdminTestState(t, exec)

	// Register a dynamic tenant so it appears in the tenants map.
	body := registerTenantRequest{TenantID: "acme", Name: "Acme Corp", SizeBytes: 1 << 30}
	if rr := doAdminRequest(state, http.MethodPost, "/control/tenants", body); rr.Code != http.StatusOK {
		t.Fatalf("register status=%d body=%s", rr.Code, rr.Body.String())
	}

	ts, ok := state.tenant("acme")
	if !ok {
		t.Fatal("tenant acme not found after registration")
	}
	insertJournalRowDirect(t, ts, "sess_1", "alloc_1", "agent_a", "/file.txt")

	rr := doAdminRequest(state, http.MethodGet, "/control/tenants/acme/journal?allocation_id=alloc_1", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}

	var resp controlJournalResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Entries) != 1 {
		t.Fatalf("entries len = %d, want 1", len(resp.Entries))
	}
	e := resp.Entries[0]
	if e.SessionID != "sess_1" {
		t.Errorf("session_id = %q, want sess_1", e.SessionID)
	}
	if e.AllocationID != "alloc_1" {
		t.Errorf("allocation_id = %q, want alloc_1", e.AllocationID)
	}
	if e.Path != "/file.txt" {
		t.Errorf("path = %q, want /file.txt", e.Path)
	}
	if e.Op != string(SessionOpCreate) {
		t.Errorf("op = %q, want create", e.Op)
	}
}

func TestControlJournalQuery_UnknownTenantReturns404(t *testing.T) {
	exec := &fakeExec{}
	state, _ := newAdminTestState(t, exec)

	rr := doAdminRequest(state, http.MethodGet, "/control/tenants/ghost/journal", nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestControlJournalQuery_RequiresControlPlaneCert(t *testing.T) {
	exec := &fakeExec{}
	state, _ := newAdminTestState(t, exec)

	// No control-plane identity in context => middleware rejects.
	req := httptest.NewRequest(http.MethodGet, "/control/tenants/acme/journal", nil)
	rr := httptest.NewRecorder()
	newRouter(state).ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestControlJournalQuery_InvalidIDReturns400(t *testing.T) {
	exec := &fakeExec{}
	state, _ := newAdminTestState(t, exec)

	rr := doAdminRequest(state, http.MethodGet, "/control/tenants/has..dots/journal", nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}
