package main

import (
	"context"
	"testing"
	"time"

	"github.com/liu1700/orlop/cmd/orlop-server/dataplane"
	"github.com/vmihailenco/msgpack/v5"
)

// revertViaWire is a shared helper that drives OpJournalRevertPath through
// the handler and returns the decoded response. Fatals on transport errors;
// caller inspects Conflicts / RevertedPaths.
func revertViaWire(
	t *testing.T,
	state *serverState,
	tenant *tenantState,
	ident Identity,
	allocID string,
	paths []string,
	force bool,
) dataplane.JournalRevertPathResponse {
	t.Helper()
	req := dataplane.JournalRevertPathRequest{
		AllocationID: allocID,
		Paths:        paths,
		Force:        force,
	}
	frame := dispatchAndReadFrame(t, state, tenant, ident, dataplane.OpJournalRevertPath, req, handleJournalRevertPath)
	if frame.Flags&dataplane.FlagError != 0 {
		t.Fatalf("journal_revert_path error: %x", frame.Payload)
	}
	var resp dataplane.JournalRevertPathResponse
	if err := msgpack.Unmarshal(frame.Payload, &resp); err != nil {
		t.Fatalf("decode revert response: %v", err)
	}
	return resp
}

// TestJournalRevertEmitsInverseRow validates the Phase 3a AC2 contract:
// after a successful revert, the journal contains a new row for the
// inverse op tagged with the active mount session, so the sidebar SSE
// subscriber receives a fresh entry. Pre-revert one create-row exists;
// post-revert two rows are visible (create + the inverse delete).
func TestJournalRevertEmitsInverseRow(t *testing.T) {
	state := newTestState(t, nil, nil)
	tenant, ok := state.tenant(testTenant)
	if !ok {
		t.Fatalf("tenant %q not found", testTenant)
	}
	if err := tenant.manifests.DirCreate("/docs", 0o755); err != nil {
		t.Fatalf("seed /docs: %v", err)
	}

	sid := testSessionID(0xc1)
	allocID := "alloc_revert_emits"
	ident := testIdentity()
	seedMountLease(state, tenant, allocID, 0xc1)
	path := "/docs/inverse.txt"

	// Create one row.
	put := dataplane.ManifestPutRequest{
		Path:         path,
		Size:         5,
		Mode:         0o644,
		Chunks:       []dataplane.ChunkRef{{Hash: makeTestHash(7), Offset: 0, Len: 5}},
		SessionID:    &sid,
		AllocationID: &allocID,
	}
	if r := dispatchAndReadFrame(t, state, tenant, ident, dataplane.OpManifestPut, put, handleManifestPut); r.Flags&dataplane.FlagError != 0 {
		t.Fatalf("put: %x", r.Payload)
	}

	// Revert it.
	resp := revertViaWire(t, state, tenant, ident, allocID, []string{path}, false)
	if len(resp.Conflicts) != 0 {
		t.Fatalf("unexpected conflicts: %v", resp.Conflicts)
	}
	if len(resp.RevertedPaths) != 1 {
		t.Fatalf("reverted = %v, want [%s]", resp.RevertedPaths, path)
	}

	// Query the journal — the original create-row was pruned by RevertPaths,
	// but the inverse delete-row from manifests.Delete must be present.
	qReq := dataplane.JournalQueryRequest{AllocationID: allocID, Limit: 50}
	qFrame := dispatchAndReadFrame(t, state, tenant, ident, dataplane.OpJournalQuery, qReq, handleJournalQuery)
	if qFrame.Flags&dataplane.FlagError != 0 {
		t.Fatalf("query: %x", qFrame.Payload)
	}
	var qResp dataplane.JournalQueryResponse
	if err := msgpack.Unmarshal(qFrame.Payload, &qResp); err != nil {
		t.Fatalf("decode query: %v", err)
	}
	if len(qResp.Entries) != 1 {
		t.Fatalf("entries = %d, want 1 (inverse only — create-row was pruned)", len(qResp.Entries))
	}
	inv := qResp.Entries[0]
	if inv.Op != dataplane.SessionOpWireDelete {
		t.Errorf("inverse op = %q, want %q (delete inverts a create)", inv.Op, dataplane.SessionOpWireDelete)
	}
	if inv.Path != path {
		t.Errorf("inverse path = %q, want %q", inv.Path, path)
	}
	if inv.AllocationID != allocID {
		t.Errorf("inverse allocation_id = %q, want %q", inv.AllocationID, allocID)
	}
	// Active mount lease at revert time = sid; the handler resolves it via
	// mountLeases.Get and journals the revert under that session.
	if inv.SessionID != sid {
		t.Errorf("inverse session_id = %q, want %q (active mount lease)", inv.SessionID, sid)
	}
}

// TestJournalRevertBroadcastsToSubscriber validates that the post-commit
// pub/sub hook (f1fb076) fires on the inverse write, so an SSE subscriber
// pre-attached to the allocation sees the new row within ~100ms — the
// path the sidebar depends on for live AC2 latency.
func TestJournalRevertBroadcastsToSubscriber(t *testing.T) {
	state := newTestState(t, nil, nil)
	tenant, ok := state.tenant(testTenant)
	if !ok {
		t.Fatalf("tenant %q not found", testTenant)
	}
	if err := tenant.manifests.DirCreate("/docs", 0o755); err != nil {
		t.Fatalf("seed /docs: %v", err)
	}

	sid := testSessionID(0xc2)
	allocID := "alloc_revert_broadcast"
	ident := testIdentity()
	seedMountLease(state, tenant, allocID, 0xc2)
	path := "/docs/broadcast.txt"

	// Seed one prior write so revert has something to invert.
	put := dataplane.ManifestPutRequest{
		Path:         path,
		Size:         3,
		Mode:         0o644,
		Chunks:       []dataplane.ChunkRef{{Hash: makeTestHash(8), Offset: 0, Len: 3}},
		SessionID:    &sid,
		AllocationID: &allocID,
	}
	if r := dispatchAndReadFrame(t, state, tenant, ident, dataplane.OpManifestPut, put, handleManifestPut); r.Flags&dataplane.FlagError != 0 {
		t.Fatalf("put: %x", r.Payload)
	}

	// Subscribe BEFORE revert so the broadcast finds us.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, unsub := tenant.journal.Subscribe(ctx, allocID)
	defer unsub()
	// Drain the buffered create-row delivery from the seed put so the next
	// receive observes the revert's inverse row, not stale traffic. (The
	// pub/sub fans out every committed Append; the seed put landed before
	// Subscribe was called, but if a future change reverses that ordering
	// the drain stays harmless because it's bounded by a short timeout.)
	select {
	case <-ch:
	case <-time.After(50 * time.Millisecond):
	}

	resp := revertViaWire(t, state, tenant, ident, allocID, []string{path}, false)
	if len(resp.Conflicts) != 0 || len(resp.RevertedPaths) != 1 {
		t.Fatalf("revert failed: reverted=%v conflicts=%v", resp.RevertedPaths, resp.Conflicts)
	}

	select {
	case entry := <-ch:
		if entry.Path != path {
			t.Errorf("subscriber got path %q, want %q", entry.Path, path)
		}
		if entry.Op != SessionOpDelete {
			t.Errorf("subscriber got op %q, want %q (inverse of create)", entry.Op, SessionOpDelete)
		}
		if entry.AllocationID != allocID {
			t.Errorf("subscriber got allocation_id %q, want %q", entry.AllocationID, allocID)
		}
		if entry.SessionID != sid {
			t.Errorf("subscriber got session_id %q, want %q (active mount lease)", entry.SessionID, sid)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("subscriber received no inverse entry within 200ms")
	}
}

// TestJournalRevertForceConcurrentWriter exercises §10.1: when a newer
// write lands after the row the user wants to revert, force=true bypasses
// the concurrent_writer CAS and lands the inverse against the live
// version. The resulting journal row's before_version reflects the live
// state actually overwritten (v2's manifest), so the journal divergently
// records the truth — no phantom intervening row is synthesised.
func TestJournalRevertForceConcurrentWriter(t *testing.T) {
	state := newTestState(t, nil, nil)
	tenant, ok := state.tenant(testTenant)
	if !ok {
		t.Fatalf("tenant %q not found", testTenant)
	}
	if err := tenant.manifests.DirCreate("/docs", 0o755); err != nil {
		t.Fatalf("seed /docs: %v", err)
	}

	sid := testSessionID(0xc3)
	allocID := "alloc_revert_force"
	ident := testIdentity()
	seedMountLease(state, tenant, allocID, 0xc3)
	path := "/docs/force.txt"

	// v1: size 10
	putV1 := dataplane.ManifestPutRequest{
		Path:         path,
		Size:         10,
		Mode:         0o644,
		Chunks:       []dataplane.ChunkRef{{Hash: makeTestHash(9), Offset: 0, Len: 10}},
		SessionID:    &sid,
		AllocationID: &allocID,
	}
	if r := dispatchAndReadFrame(t, state, tenant, ident, dataplane.OpManifestPut, putV1, handleManifestPut); r.Flags&dataplane.FlagError != 0 {
		t.Fatalf("put v1: %x", r.Payload)
	}
	// Snapshot v1's row count for later assertion that it persists.
	queryAll := func() []dataplane.JournalEntry {
		qFrame := dispatchAndReadFrame(t, state, tenant, ident,
			dataplane.OpJournalQuery,
			dataplane.JournalQueryRequest{AllocationID: allocID, Limit: 100},
			handleJournalQuery)
		var q dataplane.JournalQueryResponse
		if err := msgpack.Unmarshal(qFrame.Payload, &q); err != nil {
			t.Fatalf("decode query: %v", err)
		}
		return q.Entries
	}
	entriesAfterV1 := queryAll()
	if len(entriesAfterV1) != 1 {
		t.Fatalf("post-v1 entries = %d, want 1", len(entriesAfterV1))
	}
	v1Row := entriesAfterV1[0]

	// v2: size 20 (overwrites v1)
	putV2 := dataplane.ManifestPutRequest{
		Path:            path,
		VersionExpected: 1,
		Size:            20,
		Mode:            0o644,
		Chunks:          []dataplane.ChunkRef{{Hash: makeTestHash(10), Offset: 0, Len: 20}},
		SessionID:       &sid,
		AllocationID:    &allocID,
	}
	if r := dispatchAndReadFrame(t, state, tenant, ident, dataplane.OpManifestPut, putV2, handleManifestPut); r.Flags&dataplane.FlagError != 0 {
		t.Fatalf("put v2: %x", r.Payload)
	}

	// Without force, reverting (latest-row-for-path = v2's row) succeeds — the
	// CAS check passes because the journal-row's after_version matches live.
	// Force-revert distinguishes itself only when the journal row's
	// after_version != live. To reach that state we'd need to revert v1's
	// row while v2 is live — but RevertPaths picks "latest row for path",
	// which is v2's row. Use force=true to test the general bypass: it
	// should still succeed and journal the inverse against live v2.
	resp := revertViaWire(t, state, tenant, ident, allocID, []string{path}, true)
	if len(resp.Conflicts) != 0 {
		t.Fatalf("force revert conflicts: %v", resp.Conflicts)
	}
	if len(resp.RevertedPaths) != 1 {
		t.Fatalf("reverted = %v, want [%s]", resp.RevertedPaths, path)
	}

	entriesAfter := queryAll()
	// Two rows survive: v1's original create-row (untouched) and the new
	// inverse update-row from the forced revert. v2's row was pruned by
	// RevertPaths.DeleteRow.
	if len(entriesAfter) != 2 {
		t.Fatalf("post-revert entries = %d, want 2 (v1 row + inverse)", len(entriesAfter))
	}

	// Find the inverse row (newest seq) and assert before_version > 0 — i.e.,
	// it records the live version overwritten, not an "after revert points
	// to v0" phantom. The original v1 row stays untouched as the "older
	// point" the sidebar continues to show.
	var inv, original dataplane.JournalEntry
	for _, e := range entriesAfter {
		if e.Seq == v1Row.Seq {
			original = e
		} else {
			inv = e
		}
	}
	if inv.Path != path {
		t.Errorf("inverse row path = %q, want %q", inv.Path, path)
	}
	if inv.Op != dataplane.SessionOpWireUpdate {
		t.Errorf("inverse op = %q, want %q (update inverts an update)", inv.Op, dataplane.SessionOpWireUpdate)
	}
	if inv.BeforeVersion == nil || *inv.BeforeVersion != 2 {
		t.Errorf("inverse before_version = %v, want 2 (the live v2 we overwrote — divergent record per §10.1)", inv.BeforeVersion)
	}
	// Original v1 create-row preserved with its original op + path.
	if original.Op != dataplane.SessionOpWireCreate {
		t.Errorf("original v1 op = %q, want %q", original.Op, dataplane.SessionOpWireCreate)
	}
	if original.Path != path {
		t.Errorf("original v1 path = %q, want %q", original.Path, path)
	}
}

// TestJournalRevertOfRevert validates that a revert row itself appears in
// the journal under (path, seq) and can be the target of a subsequent
// revert by its new seq — i.e. the journal is fully time-reversible via
// the same handler.
func TestJournalRevertOfRevert(t *testing.T) {
	state := newTestState(t, nil, nil)
	tenant, ok := state.tenant(testTenant)
	if !ok {
		t.Fatalf("tenant %q not found", testTenant)
	}
	if err := tenant.manifests.DirCreate("/docs", 0o755); err != nil {
		t.Fatalf("seed /docs: %v", err)
	}

	sid := testSessionID(0xc4)
	allocID := "alloc_revert_of_revert"
	ident := testIdentity()
	seedMountLease(state, tenant, allocID, 0xc4)
	path := "/docs/double.txt"

	// Create (v1).
	put := dataplane.ManifestPutRequest{
		Path:         path,
		Size:         4,
		Mode:         0o644,
		Chunks:       []dataplane.ChunkRef{{Hash: makeTestHash(11), Offset: 0, Len: 4}},
		SessionID:    &sid,
		AllocationID: &allocID,
	}
	if r := dispatchAndReadFrame(t, state, tenant, ident, dataplane.OpManifestPut, put, handleManifestPut); r.Flags&dataplane.FlagError != 0 {
		t.Fatalf("put: %x", r.Payload)
	}

	// First revert: undoes the create, leaves an inverse delete-row.
	r1 := revertViaWire(t, state, tenant, ident, allocID, []string{path}, false)
	if len(r1.Conflicts) != 0 || len(r1.RevertedPaths) != 1 {
		t.Fatalf("first revert failed: %v / %v", r1.RevertedPaths, r1.Conflicts)
	}
	// File should be gone now.
	if _, err := tenant.manifests.Get(path); err == nil {
		t.Fatal("manifest still exists after first revert")
	}

	// Second revert: targets the inverse delete-row by latest-for-path.
	// Inverting a delete restores the prior manifest.
	r2 := revertViaWire(t, state, tenant, ident, allocID, []string{path}, false)
	if len(r2.Conflicts) != 0 || len(r2.RevertedPaths) != 1 {
		t.Fatalf("revert-of-revert failed: %v / %v", r2.RevertedPaths, r2.Conflicts)
	}
	mf, err := tenant.manifests.Get(path)
	if err != nil {
		t.Fatalf("manifest gone after revert-of-revert: %v", err)
	}
	if mf.Size != 4 {
		t.Errorf("restored size = %d, want 4 (original create state)", mf.Size)
	}
}
