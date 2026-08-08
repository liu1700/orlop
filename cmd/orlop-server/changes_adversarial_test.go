package main

// Adversarial coverage for the change feed (issue #122 acceptance gate 2):
// external mutation while mounted (journal revert), duplicate delivery, and
// the per-session seq trap that motivated a rev-based feed in the first
// place. The client-side halves (reconnect generation, resync rebaseline,
// fail-closed wipe on torn state) live in src/backend/dataplane/mirror.rs.

import (
	"testing"

	"github.com/liu1700/orlop/cmd/orlop-server/dataplane"
)

// TestRevertRingsChangeFeed: a journal revert is an external writer that
// bypasses the mount's leases entirely. It must bump the revision counter,
// ring the doorbell, and surface the reverted state in the feed, or a mirror
// would serve the pre-revert file forever.
func TestRevertRingsChangeFeed(t *testing.T) {
	state := newTestState(t, nil, nil)
	tenant, _ := state.tenant(testTenant)
	ms := tenant.manifests
	db := tenant.db.DB()

	var notified []uint64
	ms.SetChangeNotify(func(rev uint64) { notified = append(notified, rev) })

	if err := ms.DirCreate("/agent-A", 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := ms.Put("/agent-A/f", 0,
		Manifest{Path: "/agent-A/f", Size: 3, Mode: 0o644, Mtime: 10},
		"sess-1", "alloc-1", "agent-A"); err != nil {
		t.Fatal(err)
	}
	if _, err := ms.Put("/agent-A/f", 1,
		Manifest{Path: "/agent-A/f", Size: 9, Mode: 0o644, Mtime: 20},
		"sess-1", "alloc-1", "agent-A"); err != nil {
		t.Fatal(err)
	}

	before := lastChangeRev(t, db)
	reverted, conflicts, err := tenant.journal.RevertPaths(
		"alloc-1", []string{"/agent-A/f"}, nil, nil, ms, "revert:test", "operator", false,
	)
	if err != nil {
		t.Fatalf("revert: %v", err)
	}
	if len(conflicts) != 0 || len(reverted) != 1 {
		t.Fatalf("revert result: reverted=%v conflicts=%+v", reverted, conflicts)
	}

	after := lastChangeRev(t, db)
	if after != before+1 {
		t.Fatalf("revert allocated %d revs, want 1 (before=%d after=%d)", after-before, before, after)
	}
	if len(notified) == 0 || notified[len(notified)-1] != after {
		t.Fatalf("doorbell after revert = %v, want trailing %d", notified, after)
	}

	entries, err := queryChanges(db, "/agent-A", before, "", 10, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Path != "/agent-A/f" || entries[0].Rev != after {
		t.Fatalf("feed after revert = %+v, want /agent-A/f at rev %d", entries, after)
	}
	// The revert restored the size-3 before-state under a bumped CAS version.
	if entries[0].Size != 3 || entries[0].Version <= 2 {
		t.Fatalf("reverted entry = size %d version %d, want size 3 with a bumped version",
			entries[0].Size, entries[0].Version)
	}
}

// TestChangesFetchDuplicateCursorIsIdempotent: re-fetching the same cursor
// (duplicate delivery, client retry after a timeout) returns the identical
// page — the feed is a pure function of (state, cursor).
func TestChangesFetchDuplicateCursorIsIdempotent(t *testing.T) {
	state := newTestState(t, nil, nil)
	tenant, _ := state.tenant(testTenant)
	ms := tenant.manifests
	if err := ms.DirCreate("/agent-A", 0o755); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/agent-A/a", "/agent-A/b", "/agent-A/c"} {
		if _, err := ms.Put(p, 0, Manifest{Path: p, Size: 1}, "", "", ""); err != nil {
			t.Fatal(err)
		}
	}
	ident := testIdentity()
	ident.ScopedAgentID = "agent-A"

	req := dataplane.ChangesFetchRequest{SyncProtocol: dataplane.SyncProtocolV1, Limit: 2}
	first := changesFetch(t, state, tenant, ident, req)
	second := changesFetch(t, state, tenant, ident, req)
	if len(first.Entries) != 2 || len(second.Entries) != len(first.Entries) {
		t.Fatalf("pages differ in length: %d vs %d", len(first.Entries), len(second.Entries))
	}
	for i := range first.Entries {
		if first.Entries[i].Path != second.Entries[i].Path || first.Entries[i].Rev != second.Entries[i].Rev {
			t.Fatalf("duplicate fetch diverged at %d: %+v vs %+v", i, first.Entries[i], second.Entries[i])
		}
	}
	if first.NextRev != second.NextRev || first.NextPath != second.NextPath {
		t.Fatalf("cursors diverged: (%d,%q) vs (%d,%q)",
			first.NextRev, first.NextPath, second.NextRev, second.NextPath)
	}
}

// TestFeedSurvivesSessionRollover: the historical trap that killed the
// journal-replay design — session_journal.seq restarts at 1 for every mount
// session, so a seq watermark silently skips rows across sessions. The
// rev-based feed must deliver writes from BOTH sessions.
func TestFeedSurvivesSessionRollover(t *testing.T) {
	state := newTestState(t, nil, nil)
	tenant, _ := state.tenant(testTenant)
	ms := tenant.manifests
	db := tenant.db.DB()
	if err := ms.DirCreate("/agent-A", 0o755); err != nil {
		t.Fatal(err)
	}
	// First mount session.
	if _, err := ms.Put("/agent-A/one", 0, Manifest{Path: "/agent-A/one", Size: 1},
		"sess-1", "alloc-1", "agent-A"); err != nil {
		t.Fatal(err)
	}
	// New mount session: journal seq restarts at 1 for it.
	if _, err := ms.Put("/agent-A/two", 0, Manifest{Path: "/agent-A/two", Size: 1},
		"sess-2", "alloc-1", "agent-A"); err != nil {
		t.Fatal(err)
	}

	entries, err := queryChanges(db, "/agent-A", 0, "", 100, false)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	var lastRev uint64
	for _, e := range entries {
		got[e.Path] = true
		if e.Rev < lastRev {
			t.Fatalf("feed out of rev order: %+v", entries)
		}
		lastRev = e.Rev
	}
	if !got["/agent-A/one"] || !got["/agent-A/two"] {
		t.Fatalf("feed missing cross-session writes: %+v", entries)
	}
}
