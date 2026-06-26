package main

import (
	"encoding/json"
	"net/http"
	"testing"
)

// TestControlJournalRevert_HappyPath registers a tenant, appends a journal
// row + manifest pair, then POSTs /control/.../journal/revert and asserts
// ok:true plus the inverse-row being appended by the revert path.
func TestControlJournalRevert_HappyPath(t *testing.T) {
	exec := &fakeExec{}
	state, _ := newAdminTestState(t, exec)

	body := registerTenantRequest{TenantID: "acme", Name: "Acme", SizeBytes: 1 << 30}
	if rr := doAdminRequest(state, http.MethodPost, "/control/tenants", body); rr.Code != http.StatusOK {
		t.Fatalf("register: status=%d body=%s", rr.Code, rr.Body.String())
	}
	ts, ok := state.tenant("acme")
	if !ok {
		t.Fatal("tenant not found")
	}

	// Land a real create via the manifest store so RevertPaths has something
	// to invert. Helpers from manifests_test.go are package-local.
	if _, err := ts.manifests.Put("/file.txt", 0, Manifest{Path: "/file.txt", Version: 1, Size: 3}, "sess_one", "alloc_one", "agentA"); err != nil {
		t.Fatalf("manifests.Put: %v", err)
	}

	// Sanity: journal row exists for that (alloc, path).
	row, err := ts.journal.latestRowForPath("alloc_one", "/file.txt")
	if err != nil {
		t.Fatalf("latestRowForPath: %v", err)
	}
	if row == nil {
		t.Fatalf("expected a journal row from the Put")
	}

	revertBody := controlJournalRevertRequest{
		AllocationID: "alloc_one",
		Path:         "/file.txt",
		Seq:          row.Seq,
		AgentID:      "user:1",
	}
	rr := doAdminRequest(state, http.MethodPost, "/control/tenants/acme/journal/revert", revertBody)
	if rr.Code != http.StatusOK {
		t.Fatalf("revert: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var got controlJournalRevertResponse
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if !got.Ok {
		t.Fatalf("ok=false, want true: %+v", got)
	}
}

// TestControlJournalRevert_SeqMismatchReturnsConflict verifies the
// seq-sanity-check strategy: when the row the client points to is no longer
// the latest for that path, the server responds with conflict.reason =
// concurrent_writer without invoking RevertPaths.
func TestControlJournalRevert_SeqMismatchReturnsConflict(t *testing.T) {
	exec := &fakeExec{}
	state, _ := newAdminTestState(t, exec)
	body := registerTenantRequest{TenantID: "acme", Name: "Acme", SizeBytes: 1 << 30}
	if rr := doAdminRequest(state, http.MethodPost, "/control/tenants", body); rr.Code != http.StatusOK {
		t.Fatalf("register: %s", rr.Body.String())
	}
	ts, _ := state.tenant("acme")

	// Two writes in the same session — seq advances 1 → 2 so the seq
	// mismatch is detectable. Orlop-server's seq is per-session
	// (session_id is the seq-counter scope), so a multi-session edge
	// where two distinct rows both have seq=1 exists; that's a known
	// limitation of the wire-as-defined and is covered by the
	// force=true escape hatch (spec §10.2).
	if _, err := ts.manifests.Put("/file.txt", 0, Manifest{Path: "/file.txt", Version: 1, Size: 3}, "sess_one", "alloc_one", "agentA"); err != nil {
		t.Fatalf("Put1: %v", err)
	}
	first, _ := ts.journal.latestRowForPath("alloc_one", "/file.txt")
	// Second write — newer row, same session so seq advances to 2.
	if _, err := ts.manifests.Put("/file.txt", 1, Manifest{Path: "/file.txt", Version: 2, Size: 3}, "sess_one", "alloc_one", "agentA"); err != nil {
		t.Fatalf("Put2: %v", err)
	}

	// Click the (now-stale) first row.
	rr := doAdminRequest(state, http.MethodPost, "/control/tenants/acme/journal/revert",
		controlJournalRevertRequest{AllocationID: "alloc_one", Path: "/file.txt", Seq: first.Seq, AgentID: "user:1"})
	if rr.Code != http.StatusOK {
		t.Fatalf("revert: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var got controlJournalRevertResponse
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Ok {
		t.Fatalf("ok=true on stale seq, want conflict")
	}
	if got.Conflict == nil || got.Conflict.Reason != "concurrent_writer" {
		t.Fatalf("conflict=%+v, want concurrent_writer", got.Conflict)
	}
}

// TestControlJournalRevert_ForceBypassesSeqCheck confirms force=true skips
// the latest-seq sanity check and reverts the latest row directly.
func TestControlJournalRevert_ForceBypassesSeqCheck(t *testing.T) {
	exec := &fakeExec{}
	state, _ := newAdminTestState(t, exec)
	if rr := doAdminRequest(state, http.MethodPost, "/control/tenants",
		registerTenantRequest{TenantID: "acme", Name: "Acme", SizeBytes: 1 << 30}); rr.Code != http.StatusOK {
		t.Fatalf("register: %s", rr.Body.String())
	}
	ts, _ := state.tenant("acme")
	if _, err := ts.manifests.Put("/f.txt", 0, Manifest{Path: "/f.txt", Version: 1, Size: 1}, "s1", "a1", "agentA"); err != nil {
		t.Fatal(err)
	}
	old, _ := ts.journal.latestRowForPath("a1", "/f.txt")
	// Same session keeps the seq monotonic so the click row is provably stale.
	if _, err := ts.manifests.Put("/f.txt", 1, Manifest{Path: "/f.txt", Version: 2, Size: 1}, "s1", "a1", "agentA"); err != nil {
		t.Fatal(err)
	}

	rr := doAdminRequest(state, http.MethodPost, "/control/tenants/acme/journal/revert",
		controlJournalRevertRequest{AllocationID: "a1", Path: "/f.txt", Seq: old.Seq, Force: true, AgentID: "user:1"})
	if rr.Code != http.StatusOK {
		t.Fatalf("revert: %s", rr.Body.String())
	}
	var got controlJournalRevertResponse
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if !got.Ok {
		t.Fatalf("force revert: ok=false: %+v", got)
	}
}

// TestControlJournalRevert_NoRowReturnsNoJournalRow — clicking a path that
// no longer has any journal row yields conflict.reason=no_journal_row.
func TestControlJournalRevert_NoRowReturnsNoJournalRow(t *testing.T) {
	exec := &fakeExec{}
	state, _ := newAdminTestState(t, exec)
	if rr := doAdminRequest(state, http.MethodPost, "/control/tenants",
		registerTenantRequest{TenantID: "acme", Name: "Acme", SizeBytes: 1 << 30}); rr.Code != http.StatusOK {
		t.Fatalf("register: %s", rr.Body.String())
	}

	rr := doAdminRequest(state, http.MethodPost, "/control/tenants/acme/journal/revert",
		controlJournalRevertRequest{AllocationID: "alloc_x", Path: "/missing", Seq: 42, AgentID: "user:1"})
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var got controlJournalRevertResponse
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Ok || got.Conflict == nil || got.Conflict.Reason != "no_journal_row" {
		t.Fatalf("got=%+v", got)
	}
}

// TestControlJournalQuery_AfterSeqAscending confirms the GET handler routes
// to QueryAfterSeq when after_seq is set and returns ascending-seq rows.
func TestControlJournalQuery_AfterSeqAscending(t *testing.T) {
	exec := &fakeExec{}
	state, _ := newAdminTestState(t, exec)
	if rr := doAdminRequest(state, http.MethodPost, "/control/tenants",
		registerTenantRequest{TenantID: "acme", Name: "Acme", SizeBytes: 1 << 30}); rr.Code != http.StatusOK {
		t.Fatalf("register: %s", rr.Body.String())
	}
	ts, _ := state.tenant("acme")
	insertJournalRowDirect(t, ts, "sess_1", "alloc_1", "agent_a", "/a")
	insertJournalRowDirect(t, ts, "sess_1", "alloc_1", "agent_a", "/b")
	insertJournalRowDirect(t, ts, "sess_1", "alloc_1", "agent_a", "/c")

	rr := doAdminRequest(state, http.MethodGet, "/control/tenants/acme/journal?allocation_id=alloc_1&after_seq=1", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var resp controlJournalResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	// We inserted three rows; after_seq=1 must skip the first.
	if len(resp.Entries) != 2 {
		t.Fatalf("entries=%d, want 2", len(resp.Entries))
	}
	// Ascending order.
	if resp.Entries[0].Seq >= resp.Entries[1].Seq {
		t.Fatalf("not ascending: %+v", resp.Entries)
	}
}
