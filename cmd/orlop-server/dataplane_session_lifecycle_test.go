package main

import (
	"testing"

	"github.com/liu1700/orlop/cmd/orlop-server/dataplane"
	"github.com/vmihailenco/msgpack/v5"
)

// testSessionID returns an implicit-session ID in the "mount:<32 hex>" format
// the client produces from a 16-byte lease UUID. Each suffix byte gives a
// distinct ID; the returned hex tail (without the "mount:" prefix) is what
// the server's mountLeases registry needs to recognise the session as active.
// testSessionIDHex returns just the hex tail for the same suffix, used to seed
// the registry alongside the matching write.
func testSessionID(suffix byte) string {
	return sessionMountPrefix + testSessionIDHex(suffix)
}

func testSessionIDHex(suffix byte) string {
	const hexChars = "0123456789abcdef"
	out := make([]byte, 32)
	for i := 0; i < 16; i++ {
		out[i*2] = hexChars[suffix>>4]
		out[i*2+1] = hexChars[suffix&0xf]
	}
	return string(out)
}

// testConnID is the synthetic connection identity tests pretend to be holding
// when driving frames through the handlers. Chosen far above the
// connRegistry's monotonic counter so a test seed can never collide with a
// real Register() id even if a future change reorders allocation.
const testConnID uint64 = 0xCAFE_BEEF_DEAD_0001

// testLeaseID returns the 16-byte lease id corresponding to testSessionIDHex(suffix).
// Tests pre-fabricate session_ids from a single suffix byte; the lease id is
// the same byte repeated 16 times so decodeLeaseHex round-trips back to it.
func testLeaseID(suffix byte) [16]byte {
	var id [16]byte
	for i := range id {
		id[i] = suffix
	}
	return id
}

// seedMountLease pre-installs the suffix-derived session as the active lease
// for allocID, AND seeds a synthetic lease record in tenant.leases so the
// forgery check accepts the fabricated session_id. Production code installs
// via Grant; tests skip the wire dance and seed both registries directly.
func seedMountLease(state *serverState, tenant *tenantState, allocID string, suffix byte) {
	tenant.leases.installForTest(testLeaseID(suffix), "test-holder", testConnID, "/", dataplane.LeaseExclusiveWrite)
	state.mountLeases.Install(allocID, testSessionIDHex(suffix))
}

// TestImplicitSessionWriteTagging drives a manifest_put with an explicit
// session_id + allocation_id pair through the data plane, then queries the
// journal and asserts the row has the right session_id and allocation_id.
func TestImplicitSessionWriteTagging(t *testing.T) {
	state := newTestState(t, nil, nil)
	tenant, ok := state.tenant(testTenant)
	if !ok {
		t.Fatalf("tenant %q not found", testTenant)
	}
	if err := tenant.manifests.DirCreate("/docs", 0o755); err != nil {
		t.Fatalf("seed /docs: %v", err)
	}

	sid := testSessionID(0xaa)
	allocID := "alloc_implicit_test"
	ident := testIdentity()
	seedMountLease(state, tenant, allocID, 0xaa)

	putReq := dataplane.ManifestPutRequest{
		Path:         "/docs/note.txt",
		Size:         4,
		Mode:         0o644,
		Chunks:       []dataplane.ChunkRef{{Hash: makeTestHash(1), Offset: 0, Len: 4}},
		SessionID:    &sid,
		AllocationID: &allocID,
	}
	resp := dispatchAndReadFrame(t, state, tenant, ident, dataplane.OpManifestPut, putReq, handleManifestPut)
	if resp.Flags&dataplane.FlagError != 0 {
		t.Fatalf("manifest_put error: %x", resp.Payload)
	}

	// Query journal for this allocation — expect exactly one row.
	queryReq := dataplane.JournalQueryRequest{
		AllocationID: allocID,
		Limit:        10,
	}
	qResp := dispatchAndReadFrame(t, state, tenant, ident, dataplane.OpJournalQuery, queryReq, handleJournalQuery)
	if qResp.Flags&dataplane.FlagError != 0 {
		t.Fatalf("journal_query error: %x", qResp.Payload)
	}
	var qr dataplane.JournalQueryResponse
	if err := msgpack.Unmarshal(qResp.Payload, &qr); err != nil {
		t.Fatalf("decode journal_query response: %v", err)
	}
	if len(qr.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(qr.Entries))
	}
	e := qr.Entries[0]
	if e.SessionID != sid {
		t.Errorf("session_id = %q, want %q", e.SessionID, sid)
	}
	if e.AllocationID != allocID {
		t.Errorf("allocation_id = %q, want %q", e.AllocationID, allocID)
	}
	if e.Path != "/docs/note.txt" {
		t.Errorf("path = %q, want /docs/note.txt", e.Path)
	}
	if e.Op != dataplane.SessionOpWireCreate {
		t.Errorf("op = %q, want %q", e.Op, dataplane.SessionOpWireCreate)
	}
}

// TestImplicitSessionTakeoverNewLease verifies that two distinct sessions
// (representing successive mounts of the same allocation) each write their
// rows to the journal independently, and both are retrievable via
// JournalQuery against the allocation.
func TestImplicitSessionTakeoverNewLease(t *testing.T) {
	state := newTestState(t, nil, nil)
	tenant, ok := state.tenant(testTenant)
	if !ok {
		t.Fatalf("tenant %q not found", testTenant)
	}
	if err := tenant.manifests.DirCreate("/docs", 0o755); err != nil {
		t.Fatalf("seed /docs: %v", err)
	}

	allocID := "alloc_takeover_test"
	sidA := testSessionID(0x11)
	sidB := testSessionID(0x22)
	ident := testIdentity()

	// Session A takes the lease, writes, then the dashboard hands the lease
	// to session B which writes. Each is registered with mountLeases at the
	// point of writing so the data-plane fence accepts the matching session_id.
	seedMountLease(state, tenant, allocID, 0x11)
	// Session A writes /docs/a.txt.
	putA := dataplane.ManifestPutRequest{
		Path:         "/docs/a.txt",
		Size:         4,
		Mode:         0o644,
		Chunks:       []dataplane.ChunkRef{{Hash: makeTestHash(1), Offset: 0, Len: 4}},
		SessionID:    &sidA,
		AllocationID: &allocID,
	}
	if r := dispatchAndReadFrame(t, state, tenant, ident, dataplane.OpManifestPut, putA, handleManifestPut); r.Flags&dataplane.FlagError != 0 {
		t.Fatalf("session A put error: %x", r.Payload)
	}

	// Dashboard takes the lease away from A: clear fences session A. Session
	// B obtains a fresh lease (post-Phase 1.5: client must hold a real lease
	// record, not just a fabricated hex) before its first write.
	state.mountLeases.Clear(allocID)
	seedMountLease(state, tenant, allocID, 0x22)
	// Session B (new mount, after A released) writes /docs/b.txt.
	putB := dataplane.ManifestPutRequest{
		Path:         "/docs/b.txt",
		Size:         4,
		Mode:         0o644,
		Chunks:       []dataplane.ChunkRef{{Hash: makeTestHash(2), Offset: 0, Len: 4}},
		SessionID:    &sidB,
		AllocationID: &allocID,
	}
	if r := dispatchAndReadFrame(t, state, tenant, ident, dataplane.OpManifestPut, putB, handleManifestPut); r.Flags&dataplane.FlagError != 0 {
		t.Fatalf("session B put error: %x", r.Payload)
	}

	// Query should return both rows for the allocation (newest first).
	queryReq := dataplane.JournalQueryRequest{
		AllocationID: allocID,
		Limit:        10,
	}
	qResp := dispatchAndReadFrame(t, state, tenant, ident, dataplane.OpJournalQuery, queryReq, handleJournalQuery)
	if qResp.Flags&dataplane.FlagError != 0 {
		t.Fatalf("journal_query error: %x", qResp.Payload)
	}
	var qr dataplane.JournalQueryResponse
	if err := msgpack.Unmarshal(qResp.Payload, &qr); err != nil {
		t.Fatalf("decode journal_query response: %v", err)
	}
	if len(qr.Entries) != 2 {
		t.Fatalf("entries = %d, want 2 (one per session)", len(qr.Entries))
	}
	// Both entries belong to the same allocation.
	for _, e := range qr.Entries {
		if e.AllocationID != allocID {
			t.Errorf("entry allocation_id = %q, want %q", e.AllocationID, allocID)
		}
	}
	// Paths are distinct.
	paths := map[string]bool{qr.Entries[0].Path: true, qr.Entries[1].Path: true}
	if !paths["/docs/a.txt"] || !paths["/docs/b.txt"] {
		t.Errorf("paths = %v, want {/docs/a.txt, /docs/b.txt}", paths)
	}
}

// TestJournalRevertPathRestoresPriorContent creates a file via the data
// plane, updates it, then issues JournalRevertPath for that path. After
// revert the manifest must be back to the first version.
func TestJournalRevertPathRestoresPriorContent(t *testing.T) {
	state := newTestState(t, nil, nil)
	tenant, ok := state.tenant(testTenant)
	if !ok {
		t.Fatalf("tenant %q not found", testTenant)
	}
	if err := tenant.manifests.DirCreate("/docs", 0o755); err != nil {
		t.Fatalf("seed /docs: %v", err)
	}

	sid := testSessionID(0xbb)
	allocID := "alloc_revert_test"
	ident := testIdentity()
	seedMountLease(state, tenant, allocID, 0xbb)
	path := "/docs/revert_me.txt"

	// Create (version 1, size 10).
	putV1 := dataplane.ManifestPutRequest{
		Path:         path,
		Size:         10,
		Mode:         0o644,
		Chunks:       []dataplane.ChunkRef{{Hash: makeTestHash(3), Offset: 0, Len: 10}},
		SessionID:    &sid,
		AllocationID: &allocID,
	}
	r1 := dispatchAndReadFrame(t, state, tenant, ident, dataplane.OpManifestPut, putV1, handleManifestPut)
	if r1.Flags&dataplane.FlagError != 0 {
		t.Fatalf("put v1 error: %x", r1.Payload)
	}

	// Update (version 2, size 20).
	putV2 := dataplane.ManifestPutRequest{
		Path:            path,
		VersionExpected: 1,
		Size:            20,
		Mode:            0o644,
		Chunks:          []dataplane.ChunkRef{{Hash: makeTestHash(4), Offset: 0, Len: 20}},
		SessionID:       &sid,
		AllocationID:    &allocID,
	}
	r2 := dispatchAndReadFrame(t, state, tenant, ident, dataplane.OpManifestPut, putV2, handleManifestPut)
	if r2.Flags&dataplane.FlagError != 0 {
		t.Fatalf("put v2 error: %x", r2.Payload)
	}

	// Confirm current state is v2 (size 20).
	mfBefore, err := tenant.manifests.Get(path)
	if err != nil {
		t.Fatalf("Get before revert: %v", err)
	}
	if mfBefore.Size != 20 {
		t.Fatalf("pre-revert size = %d, want 20", mfBefore.Size)
	}
	if mfBefore.Version != 2 {
		t.Fatalf("pre-revert version = %d, want 2", mfBefore.Version)
	}

	// Revert the last write to /docs/revert_me.txt.
	revertReq := dataplane.JournalRevertPathRequest{
		AllocationID: allocID,
		Paths:        []string{path},
	}
	rResp := dispatchAndReadFrame(t, state, tenant, ident, dataplane.OpJournalRevertPath, revertReq, handleJournalRevertPath)
	if rResp.Flags&dataplane.FlagError != 0 {
		t.Fatalf("journal_revert_path error: %x", rResp.Payload)
	}
	var revertOut dataplane.JournalRevertPathResponse
	if err := msgpack.Unmarshal(rResp.Payload, &revertOut); err != nil {
		t.Fatalf("decode revert response: %v", err)
	}
	if len(revertOut.Conflicts) != 0 {
		t.Fatalf("revert conflicts = %v, want none", revertOut.Conflicts)
	}
	if len(revertOut.RevertedPaths) != 1 || revertOut.RevertedPaths[0] != path {
		t.Fatalf("reverted_paths = %v, want [%s]", revertOut.RevertedPaths, path)
	}

	// After revert the file must be back at size 10 (the create-row state).
	mfAfter, err := tenant.manifests.Get(path)
	if err != nil {
		t.Fatalf("Get after revert: %v", err)
	}
	if mfAfter.Size != 10 {
		t.Fatalf("post-revert size = %d, want 10", mfAfter.Size)
	}
}

// TestJournalQueryHonorsLimit writes 100 journal rows and queries with
// limit=50, expecting exactly 50 rows and a non-empty NextCursor.
func TestJournalQueryHonorsLimit(t *testing.T) {
	db := openTestDB(t)
	store := NewManifestStore(db, nil)
	journal := NewSessionJournal(db, nil)

	if err := store.DirCreate("/f", 0o755); err != nil {
		t.Fatalf("DirCreate: %v", err)
	}

	const allocID = "alloc_limit_test"
	const sid = "mount:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	// Seed 100 files, each gets one create-row in the journal.
	for i := 0; i < 100; i++ {
		path := "/f/file_" + string(rune('a'+i/26)) + string(rune('a'+i%26)) + ".txt"
		var h [HashLen]byte
		h[0] = byte(i)
		if _, err := store.Put(path, 0, Manifest{Path: path, Chunks: []ChunkRef{{Hash: h, Len: 1}}}, sid, allocID, "agent_limit"); err != nil {
			t.Fatalf("Put %s: %v", path, err)
		}
	}

	rows, nextCursor, err := journal.Query(allocID, 50, "", nil)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(rows) != 50 {
		t.Fatalf("rows = %d, want 50", len(rows))
	}
	if nextCursor == "" {
		t.Fatal("nextCursor empty, want non-empty (more pages available)")
	}
}

// TestJournalQueryPaginationCursor verifies that the opaque keyset cursor from
// the first page fetches the remaining rows on the second page with no loss or
// overlap — even when many entries share a millisecond (rowid breaks the tie).
func TestJournalQueryPaginationCursor(t *testing.T) {
	db := openTestDB(t)
	store := NewManifestStore(db, nil)
	journal := NewSessionJournal(db, nil)

	if err := store.DirCreate("/g", 0o755); err != nil {
		t.Fatalf("DirCreate: %v", err)
	}

	const allocID = "alloc_page_test"
	const sid = "mount:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	// Seed 60 files.
	for i := 0; i < 60; i++ {
		path := "/g/f_" + string(rune('a'+i/26)) + string(rune('a'+i%26)) + ".txt"
		var h [HashLen]byte
		h[0] = byte(i + 100)
		if _, err := store.Put(path, 0, Manifest{Path: path, Chunks: []ChunkRef{{Hash: h, Len: 1}}}, sid, allocID, "agent_page"); err != nil {
			t.Fatalf("Put %s: %v", path, err)
		}
	}

	// Page 1: limit=50 → 50 rows + cursor.
	page1, nextCursor, err := journal.Query(allocID, 50, "", nil)
	if err != nil {
		t.Fatalf("Query page1: %v", err)
	}
	if len(page1) != 50 {
		t.Fatalf("page1 rows = %d, want 50", len(page1))
	}
	if nextCursor == "" {
		t.Fatal("page1 nextCursor empty, want cursor for page 2")
	}

	// Page 2: using cursor → 10 rows + no more pages.
	page2, nextCursor2, err := journal.Query(allocID, 50, nextCursor, nil)
	if err != nil {
		t.Fatalf("Query page2: %v", err)
	}
	if len(page2) != 10 {
		t.Fatalf("page2 rows = %d, want 10", len(page2))
	}
	if nextCursor2 != "" {
		t.Fatalf("page2 nextCursor = %q, want empty (no more pages)", nextCursor2)
	}

	// No overlap between pages — collect all paths.
	seen := map[string]bool{}
	for _, r := range page1 {
		if seen[r.Path] {
			t.Errorf("duplicate path on page1: %s", r.Path)
		}
		seen[r.Path] = true
	}
	for _, r := range page2 {
		if seen[r.Path] {
			t.Errorf("path %s appears on both pages", r.Path)
		}
		seen[r.Path] = true
	}
	if len(seen) != 60 {
		t.Fatalf("total distinct paths = %d, want 60", len(seen))
	}
}

// TestJournalQueryPaginationCrossSessionTie proves the cursor tiebreaks on rowid,
// not seq. Two sessions writing the same allocation each start at seq=1, so a row
// from session A and a row from session B can share BOTH ts_unix_ms AND seq. A
// (ts, seq) cursor drops one of them at the page boundary; the (ts, rowid) keyset
// returns both exactly once. Rows are inserted directly to force the collision
// deterministically (store.Put would stamp the live clock).
func TestJournalQueryPaginationCrossSessionTie(t *testing.T) {
	db := openTestDB(t)
	journal := NewSessionJournal(db, nil)
	if err := journal.EnsureSchema(); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}

	const allocID = "alloc_tie"
	const ts = int64(1_700_000_000_000)
	sessions := []string{
		"mount:sessAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"mount:sessBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
	}
	for i, sid := range sessions {
		if _, err := db.Exec(
			`insert into session_journal (session_id, seq, path, op, ts_unix_ms, allocation_id)
			 values (?, 1, ?, 'create', ?, ?)`,
			sid, "/p/tie_"+string(rune('a'+i))+".txt", ts, allocID,
		); err != nil {
			t.Fatalf("insert row %d: %v", i, err)
		}
	}

	// Page through one row at a time; both tied rows must appear exactly once.
	seen := map[string]bool{}
	cursor := ""
	for page := 0; page < 5; page++ {
		rows, next, err := journal.Query(allocID, 1, cursor, nil)
		if err != nil {
			t.Fatalf("page %d query: %v", page, err)
		}
		if len(rows) == 0 {
			break
		}
		for _, r := range rows {
			if seen[r.Path] {
				t.Errorf("path %s returned on more than one page", r.Path)
			}
			seen[r.Path] = true
		}
		if next == "" {
			break
		}
		cursor = next
	}
	if len(seen) != 2 {
		t.Fatalf("distinct rows across pages = %d, want 2 (a (ts,seq) cursor would drop one)", len(seen))
	}
}

func TestJournalCursorRoundTrip(t *testing.T) {
	for _, tc := range []struct{ ts, rowid int64 }{{0, 0}, {1, 2}, {1_700_000_000_123, 999999}} {
		enc := encodeJournalCursor(tc.ts, tc.rowid)
		if ts, rid := decodeJournalCursor(enc); ts != tc.ts || rid != tc.rowid {
			t.Errorf("round-trip %q: got (%d,%d), want (%d,%d)", enc, ts, rid, tc.ts, tc.rowid)
		}
	}
	// Empty / malformed cursors degrade to the first page (0,0).
	for _, bad := range []string{"", "garbage", "123", "abc.def", "12."} {
		if ts, rid := decodeJournalCursor(bad); ts != 0 || rid != 0 {
			t.Errorf("decode(%q) = (%d,%d), want (0,0)", bad, ts, rid)
		}
	}
}
