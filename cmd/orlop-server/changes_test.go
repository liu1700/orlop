package main

// Tests for the metadata change feed (issue #122): revision stamping across
// every mutation path, tombstone lifecycle, the (rev, path) cursor query,
// pruning + rebaseline, the conflating notifier, and the wire handlers.

import (
	"database/sql"
	"io"
	"testing"
	"time"

	"github.com/liu1700/orlop/cmd/orlop-server/dataplane"
	"github.com/vmihailenco/msgpack/v5"
)

func lastChangeRev(t *testing.T, db *sql.DB) uint64 {
	t.Helper()
	var rev uint64
	if err := db.QueryRow(`select last_rev from change_counter where singleton = 1`).Scan(&rev); err != nil {
		t.Fatalf("read last_rev: %v", err)
	}
	return rev
}

func pathRev(t *testing.T, db *sql.DB, table, path string) uint64 {
	t.Helper()
	var rev uint64
	if err := db.QueryRow(`select rev from `+table+` where path = ?`, path).Scan(&rev); err != nil {
		t.Fatalf("read %s rev for %s: %v", table, path, err)
	}
	return rev
}

func direntRev(t *testing.T, db *sql.DB, parent, name string) uint64 {
	t.Helper()
	var rev uint64
	if err := db.QueryRow(`select rev from dir_entries where parent = ? and name = ?`, parent, name).Scan(&rev); err != nil {
		t.Fatalf("read dirent rev for %s/%s: %v", parent, name, err)
	}
	return rev
}

func tombstoneRevOf(t *testing.T, db *sql.DB, path string) (uint64, bool) {
	t.Helper()
	var rev uint64
	err := db.QueryRow(`select rev from change_tombstones where path = ?`, path).Scan(&rev)
	if err == sql.ErrNoRows {
		return 0, false
	}
	if err != nil {
		t.Fatalf("read tombstone rev for %s: %v", path, err)
	}
	return rev, true
}

func mustTombstoneAt(t *testing.T, db *sql.DB, path string, want uint64) {
	t.Helper()
	rev, ok := tombstoneRevOf(t, db, path)
	if !ok {
		t.Fatalf("no tombstone for %s", path)
	}
	if rev != want {
		t.Fatalf("tombstone rev for %s = %d, want %d", path, rev, want)
	}
}

// TestChangeRevStampsEveryMutation walks every mutation path and checks that
// each one allocates exactly one revision, stamps the rows it touched, and
// rings the notifier. A mirror that misses even one of these serves stale
// data, so this is the load-bearing coverage matrix.
func TestChangeRevStampsEveryMutation(t *testing.T) {
	db := openTestDB(t)
	ms := NewManifestStore(db, nil)
	var notified []uint64
	ms.SetChangeNotify(func(rev uint64) { notified = append(notified, rev) })

	put := func(path string, expected uint64) uint64 {
		t.Helper()
		v, err := ms.Put(path, expected, Manifest{Path: path, Size: 4, Mode: 0o644, Mtime: 100}, "", "", "")
		if err != nil {
			t.Fatalf("put %s: %v", path, err)
		}
		return v
	}

	put("/f", 0) // rev 1: create
	if got := pathRev(t, db, "manifests", "/f"); got != 1 {
		t.Fatalf("create rev = %d, want 1", got)
	}
	put("/f", 1) // rev 2: update
	if got := pathRev(t, db, "manifests", "/f"); got != 2 {
		t.Fatalf("update rev = %d, want 2", got)
	}
	if err := ms.DirCreate("/d", 0o755); err != nil { // rev 3
		t.Fatal(err)
	}
	if got := direntRev(t, db, "/", "d"); got != 3 {
		t.Fatalf("mkdir rev = %d, want 3", got)
	}
	if err := ms.Symlink("/d/s", "/f", 0); err != nil { // rev 4
		t.Fatal(err)
	}
	if got := pathRev(t, db, "symlinks", "/d/s"); got != 4 {
		t.Fatalf("symlink rev = %d, want 4", got)
	}
	if err := ms.Mknod("/d/p", sIFIFO|0o644, 0); err != nil { // rev 5
		t.Fatal(err)
	}
	if got := pathRev(t, db, "special_nodes", "/d/p"); got != 5 {
		t.Fatalf("mknod rev = %d, want 5", got)
	}
	if _, err := ms.Link("/f", "/g", "", "", ""); err != nil { // rev 6
		t.Fatal(err)
	}
	// Hard link restamps every name of the inode (nlink changed for all).
	if got := pathRev(t, db, "manifests", "/f"); got != 6 {
		t.Fatalf("link source restamp = %d, want 6", got)
	}
	if got := pathRev(t, db, "manifests", "/g"); got != 6 {
		t.Fatalf("link target rev = %d, want 6", got)
	}
	if err := ms.Delete("/g", 2, "", "", ""); err != nil { // rev 7
		t.Fatal(err)
	}
	mustTombstoneAt(t, db, "/g", 7)
	if got := pathRev(t, db, "manifests", "/f"); got != 7 {
		t.Fatalf("surviving hard link restamp = %d, want 7", got)
	}
	if _, err := ms.Rename("/f", "/h", 2, 0, "", "", ""); err != nil { // rev 8
		t.Fatal(err)
	}
	mustTombstoneAt(t, db, "/f", 8)
	if got := pathRev(t, db, "manifests", "/h"); got != 8 {
		t.Fatalf("rename dest rev = %d, want 8", got)
	}
	if err := ms.SetMode("/d", 0o700, "", "", "", ""); err != nil { // rev 9
		t.Fatal(err)
	}
	if got := direntRev(t, db, "/", "d"); got != 9 {
		t.Fatalf("dir chmod rev = %d, want 9", got)
	}
	if err := ms.SetOwner("/h", 12, 34); err != nil { // rev 10
		t.Fatal(err)
	}
	if got := pathRev(t, db, "manifests", "/h"); got != 10 {
		t.Fatalf("chown rev = %d, want 10", got)
	}
	if err := ms.SetAtime("/d/s", 4242); err != nil { // rev 11
		t.Fatal(err)
	}
	if got := pathRev(t, db, "symlinks", "/d/s"); got != 11 {
		t.Fatalf("symlink atime rev = %d, want 11", got)
	}
	if err := ms.Delete("/d/s", 0, "", "", ""); err != nil { // rev 12: symlink unlink
		t.Fatal(err)
	}
	mustTombstoneAt(t, db, "/d/s", 12)
	if err := ms.Delete("/d/p", 0, "", "", ""); err != nil { // rev 13: special unlink
		t.Fatal(err)
	}
	mustTombstoneAt(t, db, "/d/p", 13)
	if err := ms.DirRemove("/d"); err != nil { // rev 14
		t.Fatal(err)
	}
	mustTombstoneAt(t, db, "/d", 14)

	// Re-creating a deleted path clears its tombstone.
	put("/g", 0) // rev 15
	if _, ok := tombstoneRevOf(t, db, "/g"); ok {
		t.Fatal("tombstone for /g survived re-create")
	}

	if got := lastChangeRev(t, db); got != 15 {
		t.Fatalf("last_rev = %d, want 15", got)
	}
	if len(notified) != 15 {
		t.Fatalf("notifier fired %d times, want 15 (%v)", len(notified), notified)
	}
	for i, rev := range notified {
		if rev != uint64(i+1) {
			t.Fatalf("notified[%d] = %d, want %d", i, rev, i+1)
		}
	}
}

// TestDirRenameSubtreeOneRev checks the case the compound cursor exists for:
// a directory rename stamps the whole subtree at ONE revision, tombstones
// every old path, and the feed delivers the entire move ordered by path
// within that revision.
func TestDirRenameSubtreeOneRev(t *testing.T) {
	db := openTestDB(t)
	ms := NewManifestStore(db, nil)

	mustDo := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	mustDo(ms.DirCreate("/d", 0o755))
	_, err := ms.Put("/d/f1", 0, Manifest{Path: "/d/f1", Size: 1}, "", "", "")
	mustDo(err)
	_, err = ms.Put("/d/f2", 0, Manifest{Path: "/d/f2", Size: 2}, "", "", "")
	mustDo(err)
	mustDo(ms.DirCreate("/d/sub", 0o755))
	_, err = ms.Put("/d/sub/f3", 0, Manifest{Path: "/d/sub/f3", Size: 3}, "", "", "")
	mustDo(err)

	before := lastChangeRev(t, db)
	if _, err := ms.Rename("/d", "/e", 0, 0, "", "", ""); err != nil {
		t.Fatalf("dir rename: %v", err)
	}
	rev := lastChangeRev(t, db)
	if rev != before+1 {
		t.Fatalf("dir rename allocated %d revs, want 1", rev-before)
	}

	for _, p := range []string{"/e/f1", "/e/f2", "/e/sub/f3"} {
		if got := pathRev(t, db, "manifests", p); got != rev {
			t.Fatalf("moved file %s rev = %d, want %d", p, got, rev)
		}
	}
	if got := direntRev(t, db, "/", "e"); got != rev {
		t.Fatalf("moved dir dirent rev = %d, want %d", got, rev)
	}
	if got := direntRev(t, db, "/e", "sub"); got != rev {
		t.Fatalf("moved subdir dirent rev = %d, want %d", got, rev)
	}
	for _, p := range []string{"/d", "/d/f1", "/d/f2", "/d/sub", "/d/sub/f3"} {
		mustTombstoneAt(t, db, p, rev)
	}

	// The feed delivers the whole move after the pre-rename cursor: five
	// tombstones plus five live entries, all at one revision, path-ordered.
	entries, err := queryChanges(db, "", before, "", 100, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 10 {
		t.Fatalf("feed delivered %d entries, want 10: %+v", len(entries), entries)
	}
	for i, e := range entries {
		if e.Rev != rev {
			t.Fatalf("entry %s rev = %d, want %d", e.Path, e.Rev, rev)
		}
		if i > 0 && entries[i-1].Path >= e.Path {
			t.Fatalf("entries not path-ordered within one rev: %q then %q", entries[i-1].Path, e.Path)
		}
	}

	// Cursor-resume mid-revision: page through with limit 3 and confirm the
	// same ten entries arrive exactly once.
	var paged []ChangeEntry
	curRev, curPath := before, ""
	for {
		page, err := queryChanges(db, "", curRev, curPath, 3, false)
		if err != nil {
			t.Fatal(err)
		}
		if len(page) == 0 {
			break
		}
		paged = append(paged, page...)
		curRev, curPath = page[len(page)-1].Rev, page[len(page)-1].Path
	}
	if len(paged) != 10 {
		t.Fatalf("paged feed delivered %d entries, want 10", len(paged))
	}
	seen := map[string]int{}
	for _, e := range paged {
		seen[e.Kind+":"+e.Path]++
	}
	for k, n := range seen {
		if n != 1 {
			t.Fatalf("entry %s delivered %d times", k, n)
		}
	}
}

// TestQueryChangesSubtreeAndChunks: the feed is confined to a subtree and can
// carry manifest chunk lists.
func TestQueryChangesSubtreeAndChunks(t *testing.T) {
	db := openTestDB(t)
	ms := NewManifestStore(db, nil)

	if err := ms.DirCreate("/a1", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ms.DirCreate("/a2", 0o755); err != nil {
		t.Fatal(err)
	}
	var h [HashLen]byte
	h[0] = 0xAB
	if _, err := ms.Put("/a1/f", 0, Manifest{
		Path: "/a1/f", Size: 4, Mode: 0o644, Mtime: 7,
		Chunks: []ChunkRef{{Hash: h, Offset: 0, Len: 4}},
	}, "", "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := ms.Put("/a2/g", 0, Manifest{Path: "/a2/g", Size: 1}, "", "", ""); err != nil {
		t.Fatal(err)
	}

	entries, err := queryChanges(db, "/a1", 0, "", 100, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("subtree feed = %d entries, want 2 (/a1 dir + /a1/f): %+v", len(entries), entries)
	}
	for _, e := range entries {
		if e.Path != "/a1" && e.Path != "/a1/f" {
			t.Fatalf("entry %s leaked outside subtree /a1", e.Path)
		}
	}
	var file *ChangeEntry
	for i := range entries {
		if entries[i].Kind == "file" {
			file = &entries[i]
		}
	}
	if file == nil {
		t.Fatal("no file entry in subtree feed")
	}
	if !file.HasChunks || len(file.Chunks) != 1 || file.Chunks[0].Hash != h {
		t.Fatalf("file entry chunks = %+v (has=%v), want the stored chunk", file.Chunks, file.HasChunks)
	}
	if file.Version != 1 || file.Mtime != 7 {
		t.Fatalf("file entry version/mtime = %d/%d, want 1/7", file.Version, file.Mtime)
	}
}

// TestPruneTombstonesAdvancesWatermark: pruning removes aged tombstones and
// advances pruned_before_rev so stale cursors are told to rebaseline.
func TestPruneTombstonesAdvancesWatermark(t *testing.T) {
	db := openTestDB(t)
	ms := NewManifestStore(db, nil)

	if _, err := ms.Put("/f", 0, Manifest{Path: "/f", Size: 1}, "", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := ms.Delete("/f", 1, "", "", ""); err != nil {
		t.Fatal(err)
	}
	tombRev, ok := tombstoneRevOf(t, db, "/f")
	if !ok {
		t.Fatal("no tombstone after delete")
	}

	n, err := pruneTombstones(db, time.Now().UnixMilli()+1)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("pruned %d tombstones, want 1", n)
	}
	_, prunedBefore, err := changeFeedState(db)
	if err != nil {
		t.Fatal(err)
	}
	if prunedBefore != tombRev+1 {
		t.Fatalf("pruned_before_rev = %d, want %d", prunedBefore, tombRev+1)
	}
	if _, ok := tombstoneRevOf(t, db, "/f"); ok {
		t.Fatal("tombstone survived pruning")
	}
	// Nothing to prune → no-op, watermark stays.
	if n, err := pruneTombstones(db, time.Now().UnixMilli()+1); err != nil || n != 0 {
		t.Fatalf("second prune = (%d, %v), want (0, nil)", n, err)
	}
}

// TestChangeNotifierConflation: doorbells conflate to the latest revision,
// subscriptions are replaced per connection, and nil receivers are inert.
func TestChangeNotifierConflation(t *testing.T) {
	n := newChangeNotifier()
	sub := n.Subscribe(7)

	n.Notify(3)
	n.Notify(5)
	select {
	case <-sub.signal:
	default:
		t.Fatal("no doorbell after notify")
	}
	if got := sub.rev.Load(); got != 5 {
		t.Fatalf("conflated rev = %d, want 5", got)
	}
	select {
	case <-sub.signal:
		t.Fatal("two signals queued; doorbell must conflate")
	default:
	}
	n.Notify(6)
	select {
	case <-sub.signal:
	default:
		t.Fatal("no doorbell after drain + notify")
	}
	if got := sub.rev.Load(); got != 6 {
		t.Fatalf("rev after re-ring = %d, want 6", got)
	}

	sub2 := n.Subscribe(7)
	select {
	case <-sub.done:
	default:
		t.Fatal("replaced subscription not terminated")
	}
	n.DropConn(7)
	select {
	case <-sub2.done:
	default:
		t.Fatal("dropped subscription not terminated")
	}

	var nilN *changeNotifier
	nilN.Notify(1)
	nilN.DropConn(1)
	if nilN.Subscribe(1) != nil {
		t.Fatal("nil notifier Subscribe must return nil")
	}
}

// TestPurgeAgentTombstonesSubtree: an agent purge (control-plane bulk delete,
// no lease fence) must be visible to the feed — every purged path tombstoned
// at one revision.
func TestPurgeAgentTombstonesSubtree(t *testing.T) {
	state := newTestState(t, nil, nil)
	tenant, ok := state.tenant(testTenant)
	if !ok {
		t.Fatal("test tenant missing")
	}
	ms := tenant.manifests
	if err := ms.DirCreate("/agent-A", 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := ms.Put("/agent-A/f", 0, Manifest{Path: "/agent-A/f", Size: 1}, "", "", ""); err != nil {
		t.Fatal(err)
	}

	if _, err := purgeAgentSubtree(tenant, "agent-A"); err != nil {
		t.Fatalf("purge: %v", err)
	}
	db := tenant.db.DB()
	rev := lastChangeRev(t, db)
	mustTombstoneAt(t, db, "/agent-A", rev)
	mustTombstoneAt(t, db, "/agent-A/f", rev)
}

// --- wire handlers -----------------------------------------------------

func changesFetch(t *testing.T, state *serverState, tenant *tenantState, ident Identity, req dataplane.ChangesFetchRequest) dataplane.ChangesFetchResponse {
	t.Helper()
	frame := dispatchAndReadFrame(t, state, tenant, ident, dataplane.OpChangesFetch, req, handleChangesFetch)
	if frame.Flags&dataplane.FlagError != 0 {
		t.Fatalf("changes_fetch error frame: %x", frame.Payload)
	}
	var resp dataplane.ChangesFetchResponse
	if err := msgpack.Unmarshal(frame.Payload, &resp); err != nil {
		t.Fatalf("decode changes_fetch response: %v", err)
	}
	return resp
}

// TestHandleChangesFetchSubtreeConfinement: the feed a scoped cert sees is
// derived from the cert, confined to its agent subtree, and the drained-page
// cursor jumps to the tenant counter so the client can prove freshness.
func TestHandleChangesFetchSubtreeConfinement(t *testing.T) {
	state := newTestState(t, nil, nil)
	tenant, _ := state.tenant(testTenant)
	ms := tenant.manifests
	for _, dir := range []string{"/agent-A", "/agent-B"} {
		if err := ms.DirCreate(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ms.Put("/agent-A/f", 0, Manifest{Path: "/agent-A/f", Size: 1}, "", "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := ms.Put("/agent-B/g", 0, Manifest{Path: "/agent-B/g", Size: 1}, "", "", ""); err != nil {
		t.Fatal(err)
	}

	ident := testIdentity()
	ident.ScopedAgentID = "agent-A"
	resp := changesFetch(t, state, tenant, ident, dataplane.ChangesFetchRequest{
		SyncProtocol: dataplane.SyncProtocolV1, Limit: 100,
	})
	if resp.SyncProtocol != dataplane.SyncProtocolV1 {
		t.Fatalf("sync_protocol echo = %d", resp.SyncProtocol)
	}
	if resp.Subtree != "/agent-A" {
		t.Fatalf("subtree = %q, want /agent-A", resp.Subtree)
	}
	if len(resp.Entries) != 2 {
		t.Fatalf("scoped feed = %d entries, want 2: %+v", len(resp.Entries), resp.Entries)
	}
	for _, e := range resp.Entries {
		if e.Path != "/agent-A" && e.Path != "/agent-A/f" {
			t.Fatalf("entry %s leaked outside agent subtree", e.Path)
		}
	}
	// All four mutations bumped the counter; the drained page reports the
	// counter (4) so the scoped client's watermark can reach CurrentRev even
	// though revisions 3 and 4 (agent-B's) are invisible to it.
	wantRev := lastChangeRev(t, tenant.db.DB())
	if resp.CurrentRev != wantRev || resp.NextRev != wantRev || resp.NextPath != "" {
		t.Fatalf("drained cursor = (%d, %q) current %d, want (%d, \"\") current %d",
			resp.NextRev, resp.NextPath, resp.CurrentRev, wantRev, wantRev)
	}
	if resp.ResyncRequired {
		t.Fatal("fresh fetch must not demand resync")
	}
}

// TestHandleChangesFetchNegotiationAndResync: unknown sync_protocol is
// EINVAL; a cursor below the prune watermark gets resync_required; the fresh
// (0, "") cursor is exempt.
func TestHandleChangesFetchNegotiationAndResync(t *testing.T) {
	state := newTestState(t, nil, nil)
	tenant, _ := state.tenant(testTenant)
	ident := testIdentity()
	ident.ScopedAgentID = "agent-A"

	frame := dispatchAndReadFrame(t, state, tenant, ident, dataplane.OpChangesFetch,
		dataplane.ChangesFetchRequest{SyncProtocol: 99}, handleChangesFetch)
	if frame.Flags&dataplane.FlagError == 0 {
		t.Fatal("unknown sync_protocol must be an error frame")
	}
	var ep dataplane.ErrorPayload
	if err := msgpack.Unmarshal(frame.Payload, &ep); err != nil {
		t.Fatal(err)
	}
	if ep.Errno != dataplane.ErrnoEINVAL {
		t.Fatalf("errno = %d, want EINVAL", ep.Errno)
	}

	if _, err := tenant.db.DB().Exec(
		`update change_counter set pruned_before_rev = 5, last_rev = 9 where singleton = 1`,
	); err != nil {
		t.Fatal(err)
	}
	resp := changesFetch(t, state, tenant, ident, dataplane.ChangesFetchRequest{
		SyncProtocol: dataplane.SyncProtocolV1, CursorRev: 3, CursorPath: "/agent-A/x",
	})
	if !resp.ResyncRequired {
		t.Fatal("cursor below prune watermark must demand resync")
	}
	if resp.NextRev != 3 || resp.NextPath != "/agent-A/x" || resp.CurrentRev != 9 {
		t.Fatalf("resync response cursor = (%d, %q) current %d", resp.NextRev, resp.NextPath, resp.CurrentRev)
	}
	fresh := changesFetch(t, state, tenant, ident, dataplane.ChangesFetchRequest{
		SyncProtocol: dataplane.SyncProtocolV1,
	})
	if fresh.ResyncRequired {
		t.Fatal("the fresh (0, \"\") cursor is a full rebaseline already; it must not loop on resync_required")
	}
}

// TestHandleChangesSubscribeDoorbell: subscribing returns the current
// revision and a later mutation pushes a CHANGES_EVENT doorbell carrying the
// new revision on the same connection.
func TestHandleChangesSubscribeDoorbell(t *testing.T) {
	state := newTestState(t, nil, nil)
	tenant, _ := state.tenant(testTenant)
	ident := testIdentity()
	ident.ScopedAgentID = "agent-A"
	if err := tenant.manifests.DirCreate("/agent-A", 0o755); err != nil {
		t.Fatal(err)
	}

	pr, pw := io.Pipe()
	w := newFrameWriter(pw)
	w.connID = testConnID
	defer func() {
		tenant.changes.DropConn(testConnID)
		w.close()
		_ = pr.Close()
	}()

	raw, err := msgpack.Marshal(dataplane.ChangesSubscribeRequest{SyncProtocol: dataplane.SyncProtocolV1})
	if err != nil {
		t.Fatal(err)
	}
	go handleChangesSubscribe(state, tenant, ident, w, testConnID, dataplane.Frame{Op: dataplane.OpChangesSubscribe, RID: 7, Payload: raw})

	respFrame, err := dataplane.ReadFrame(pr)
	if err != nil {
		t.Fatalf("read subscribe response: %v", err)
	}
	if respFrame.Op != dataplane.OpChangesSubscribe || respFrame.Flags&dataplane.FlagError != 0 {
		t.Fatalf("unexpected subscribe response: op %v flags %b", respFrame.Op, respFrame.Flags)
	}
	var resp dataplane.ChangesSubscribeResponse
	if err := msgpack.Unmarshal(respFrame.Payload, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.SyncProtocol != dataplane.SyncProtocolV1 {
		t.Fatalf("sync_protocol echo = %d", resp.SyncProtocol)
	}
	baseRev := resp.CurrentRev

	if _, err := tenant.manifests.Put("/agent-A/f", 0, Manifest{Path: "/agent-A/f", Size: 1}, "", "", ""); err != nil {
		t.Fatal(err)
	}

	pushFrame, err := dataplane.ReadFrame(pr)
	if err != nil {
		t.Fatalf("read doorbell push: %v", err)
	}
	if pushFrame.Op != dataplane.OpChangesEvent {
		t.Fatalf("push op = %v, want CHANGES_EVENT", pushFrame.Op)
	}
	if pushFrame.Flags&dataplane.FlagResponse != 0 {
		t.Fatal("push frame must not carry FlagResponse")
	}
	if pushFrame.RID < 1<<63 {
		t.Fatalf("push RID %d below push-RID base", pushFrame.RID)
	}
	var ev dataplane.ChangesEventPush
	if err := msgpack.Unmarshal(pushFrame.Payload, &ev); err != nil {
		t.Fatal(err)
	}
	if ev.CurrentRev != baseRev+1 {
		t.Fatalf("doorbell rev = %d, want %d", ev.CurrentRev, baseRev+1)
	}
}
