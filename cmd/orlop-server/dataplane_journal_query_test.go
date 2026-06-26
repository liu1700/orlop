package main

import (
	"bytes"
	"testing"

	"github.com/liu1700/orlop/cmd/orlop-server/dataplane"
	"github.com/vmihailenco/msgpack/v5"
)

// dispatchAndReadFrame runs handler and returns the single response frame
// it wrote. Closes the writer to flush the goroutine before reading.
func dispatchAndReadFrame(
	t *testing.T,
	state *serverState,
	tenant *tenantState,
	ident Identity,
	op dataplane.Op,
	payload any,
	handler func(*serverState, *tenantState, Identity, *frameWriter, dataplane.Frame),
) dataplane.Frame {
	t.Helper()
	raw, err := msgpack.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal %v: %v", op, err)
	}
	var buf bytes.Buffer
	w := newFrameWriter(&buf)
	w.connID = testConnID
	handler(state, tenant, ident, w, dataplane.Frame{Op: op, RID: 42, Payload: raw})
	w.close() // flushes the writer goroutine
	frame, err := dataplane.ReadFrame(&buf)
	if err != nil {
		t.Fatalf("read response frame: %v", err)
	}
	if frame.Op != op {
		t.Fatalf("response op = %v, want %v", frame.Op, op)
	}
	if frame.RID != 42 {
		t.Fatalf("response rid = %d, want 42", frame.RID)
	}
	if frame.Flags&dataplane.FlagResponse == 0 {
		t.Fatal("response missing FlagResponse")
	}
	return frame
}

// journalQuery is a helper that sends a JournalQueryRequest via the wire
// handler and returns the decoded JournalQueryResponse. It fatals on any error.
func journalQuery(
	t *testing.T,
	state *serverState,
	tenant *tenantState,
	ident Identity,
	req dataplane.JournalQueryRequest,
) dataplane.JournalQueryResponse {
	t.Helper()
	frame := dispatchAndReadFrame(t, state, tenant, ident, dataplane.OpJournalQuery, req, handleJournalQuery)
	if frame.Flags&dataplane.FlagError != 0 {
		t.Fatalf("journal_query error: %x", frame.Payload)
	}
	var resp dataplane.JournalQueryResponse
	if err := msgpack.Unmarshal(frame.Payload, &resp); err != nil {
		t.Fatalf("decode journal_query response: %v", err)
	}
	return resp
}

// manifestPutTagged sends one manifest_put with the given session_id and
// allocation_id through the data plane handler and fatals on error.
func manifestPutTagged(
	t *testing.T,
	state *serverState,
	tenant *tenantState,
	ident Identity,
	path string,
	hashSeed byte,
	sid *string,
	allocID *string,
) {
	t.Helper()
	req := dataplane.ManifestPutRequest{
		Path:         path,
		Size:         4,
		Mode:         0o644,
		Chunks:       []dataplane.ChunkRef{{Hash: makeTestHash(hashSeed), Offset: 0, Len: 4}},
		SessionID:    sid,
		AllocationID: allocID,
	}
	r := dispatchAndReadFrame(t, state, tenant, ident, dataplane.OpManifestPut, req, handleManifestPut)
	if r.Flags&dataplane.FlagError != 0 {
		t.Fatalf("manifest_put(%q) error: %x", path, r.Payload)
	}
}

// TestJournalQueryEndToEnd writes 5 manifest_puts tagged with the same
// session_id and allocation_id, then queries the journal for that allocation
// and verifies all 5 entries are returned, newest-first, with correct
// allocation_id and a populated agent_id.
func TestJournalQueryEndToEnd(t *testing.T) {
	state := newTestState(t, nil, nil)
	tenant, ok := state.tenant(testTenant)
	if !ok {
		t.Fatalf("tenant %q not found", testTenant)
	}
	if err := tenant.manifests.DirCreate("/files", 0o755); err != nil {
		t.Fatalf("seed /files: %v", err)
	}

	sid := testSessionID(0x01)
	allocID := "alloc_e2e_test"
	ident := testIdentity()
	seedMountLease(state, tenant, allocID, 0x01)

	for i := range 5 {
		path := "/files/f" + string(rune('a'+i)) + ".txt"
		manifestPutTagged(t, state, tenant, ident, path, byte(i+1), &sid, &allocID)
	}

	resp := journalQuery(t, state, tenant, ident, dataplane.JournalQueryRequest{
		AllocationID: allocID,
		Limit:        10,
	})

	if len(resp.Entries) != 5 {
		t.Fatalf("entries = %d, want 5", len(resp.Entries))
	}

	// Verify newest-first ordering (ts_unix_ms descending or equal).
	for i := 1; i < len(resp.Entries); i++ {
		if resp.Entries[i].TsUnixMs > resp.Entries[i-1].TsUnixMs {
			t.Errorf("entries not newest-first at index %d: ts[%d]=%d > ts[%d]=%d",
				i, i, resp.Entries[i].TsUnixMs, i-1, resp.Entries[i-1].TsUnixMs)
		}
	}

	// All entries belong to the queried allocation with an agent_id set.
	for _, e := range resp.Entries {
		if e.AllocationID != allocID {
			t.Errorf("entry allocation_id = %q, want %q", e.AllocationID, allocID)
		}
		if e.AgentID == "" {
			t.Errorf("entry at path %q has empty agent_id", e.Path)
		}
	}
}

// TestJournalQueryFiltersByAllocation writes to two distinct allocations
// and verifies that querying by one allocation_id returns only its rows.
func TestJournalQueryFiltersByAllocation(t *testing.T) {
	state := newTestState(t, nil, nil)
	tenant, ok := state.tenant(testTenant)
	if !ok {
		t.Fatalf("tenant %q not found", testTenant)
	}
	if err := tenant.manifests.DirCreate("/alpha", 0o755); err != nil {
		t.Fatalf("seed /alpha: %v", err)
	}
	if err := tenant.manifests.DirCreate("/beta", 0o755); err != nil {
		t.Fatalf("seed /beta: %v", err)
	}

	sidA := testSessionID(0x10)
	sidB := testSessionID(0x20)
	allocA := "alloc_filter_A"
	allocB := "alloc_filter_B"
	ident := testIdentity()
	seedMountLease(state, tenant, allocA, 0x10)
	seedMountLease(state, tenant, allocB, 0x20)

	manifestPutTagged(t, state, tenant, ident, "/alpha/one.txt", 0x11, &sidA, &allocA)
	manifestPutTagged(t, state, tenant, ident, "/alpha/two.txt", 0x12, &sidA, &allocA)
	manifestPutTagged(t, state, tenant, ident, "/beta/one.txt", 0x21, &sidB, &allocB)

	resp := journalQuery(t, state, tenant, ident, dataplane.JournalQueryRequest{
		AllocationID: allocA,
		Limit:        10,
	})

	if len(resp.Entries) != 2 {
		t.Fatalf("entries = %d, want 2 (only allocA rows)", len(resp.Entries))
	}
	for _, e := range resp.Entries {
		if e.AllocationID != allocA {
			t.Errorf("entry allocation_id = %q, want %q", e.AllocationID, allocA)
		}
	}
}

// TestJournalQueryMergedFeed writes to two allocations then queries with an
// empty AllocationID, verifying that rows from both allocations are returned.
func TestJournalQueryMergedFeed(t *testing.T) {
	state := newTestState(t, nil, nil)
	tenant, ok := state.tenant(testTenant)
	if !ok {
		t.Fatalf("tenant %q not found", testTenant)
	}
	if err := tenant.manifests.DirCreate("/merged", 0o755); err != nil {
		t.Fatalf("seed /merged: %v", err)
	}

	sidA := testSessionID(0x30)
	sidB := testSessionID(0x31)
	allocA := "alloc_merged_A"
	allocB := "alloc_merged_B"
	ident := testIdentity()
	seedMountLease(state, tenant, allocA, 0x30)
	seedMountLease(state, tenant, allocB, 0x31)

	manifestPutTagged(t, state, tenant, ident, "/merged/a.txt", 0x31, &sidA, &allocA)
	manifestPutTagged(t, state, tenant, ident, "/merged/b.txt", 0x32, &sidB, &allocB)
	manifestPutTagged(t, state, tenant, ident, "/merged/c.txt", 0x33, &sidA, &allocA)

	// Empty AllocationID → merged feed across all tenant allocations.
	resp := journalQuery(t, state, tenant, ident, dataplane.JournalQueryRequest{
		Limit: 20,
	})

	if len(resp.Entries) < 3 {
		t.Fatalf("merged feed entries = %d, want >= 3", len(resp.Entries))
	}

	sawA, sawB := false, false
	for _, e := range resp.Entries {
		if e.AllocationID == allocA {
			sawA = true
		}
		if e.AllocationID == allocB {
			sawB = true
		}
	}
	if !sawA {
		t.Error("merged feed missing rows for allocA")
	}
	if !sawB {
		t.Error("merged feed missing rows for allocB")
	}
}

// TestJournalQueryCursorPaginates writes 10 entries and pages through them with
// the opaque keyset cursor over the msgpack data-plane protocol: limit=5 yields
// page 1 + a cursor; the cursor yields the older 5. The two pages must cover all
// 10 with no overlap — robust even when every write lands in the same
// millisecond (rowid breaks the tie).
func TestJournalQueryCursorPaginates(t *testing.T) {
	state := newTestState(t, nil, nil)
	tenant, ok := state.tenant(testTenant)
	if !ok {
		t.Fatalf("tenant %q not found", testTenant)
	}
	if err := tenant.manifests.DirCreate("/ts", 0o755); err != nil {
		t.Fatalf("seed /ts: %v", err)
	}

	sid := testSessionID(0x40)
	allocID := "alloc_ts_test"
	ident := testIdentity()
	seedMountLease(state, tenant, allocID, 0x40)

	for i := range 10 {
		path := "/ts/f" + string(rune('a'+i)) + ".txt"
		manifestPutTagged(t, state, tenant, ident, path, byte(0x41+i), &sid, &allocID)
	}

	page1 := journalQuery(t, state, tenant, ident, dataplane.JournalQueryRequest{
		AllocationID: allocID,
		Limit:        5,
	})
	if len(page1.Entries) != 5 {
		t.Fatalf("page1 = %d entries, want 5", len(page1.Entries))
	}
	if page1.NextCursor == "" {
		t.Fatal("page1 NextCursor empty, want a cursor (10 entries > limit 5)")
	}

	page2 := journalQuery(t, state, tenant, ident, dataplane.JournalQueryRequest{
		AllocationID: allocID,
		Limit:        5,
		Cursor:       page1.NextCursor,
	})
	if len(page2.Entries) != 5 {
		t.Fatalf("page2 = %d entries, want 5", len(page2.Entries))
	}

	// The two pages must cover all 10 distinct paths with no overlap.
	seen := map[string]bool{}
	for _, e := range page1.Entries {
		seen[e.Path] = true
	}
	for _, e := range page2.Entries {
		if seen[e.Path] {
			t.Errorf("path %s appears on both pages", e.Path)
		}
		seen[e.Path] = true
	}
	if len(seen) != 10 {
		t.Fatalf("distinct paths across pages = %d, want 10", len(seen))
	}
}

// TestJournalQueryRejectsCrossTenant verifies that data written under tenant A
// is invisible to a separate server state (tenant B). Because each tenant has
// its own SQLite DB, querying B's state with A's allocation_id returns 0 rows.
func TestJournalQueryRejectsCrossTenant(t *testing.T) {
	// Tenant A: write one file.
	stateA := newTestState(t, nil, nil)
	tenantA, ok := stateA.tenant(testTenant)
	if !ok {
		t.Fatalf("tenant A %q not found", testTenant)
	}
	if err := tenantA.manifests.DirCreate("/secret", 0o755); err != nil {
		t.Fatalf("seed /secret: %v", err)
	}

	allocID := "alloc_cross_tenant"
	sidA := testSessionID(0x50)
	identA := testIdentity()
	seedMountLease(stateA, tenantA, allocID, 0x50)
	manifestPutTagged(t, stateA, tenantA, identA, "/secret/data.txt", 0x51, &sidA, &allocID)

	// Tenant B: a completely separate server state with its own empty DB.
	stateB := newTestState(t, nil, nil)
	tenantB, ok := stateB.tenant(testTenant)
	if !ok {
		t.Fatalf("tenant B %q not found", testTenant)
	}
	identB := testIdentity()
	identB.AgentID = "agent-b@example.com"

	// Query B for A's allocation_id — the per-tenant DB isolation means 0 rows.
	resp := journalQuery(t, stateB, tenantB, identB, dataplane.JournalQueryRequest{
		AllocationID: allocID,
		Limit:        10,
	})

	if len(resp.Entries) != 0 {
		t.Errorf("cross-tenant query returned %d entries, want 0 — tenant DB isolation broken",
			len(resp.Entries))
	}
}
