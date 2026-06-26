package main

import (
	"context"
	"strings"
	"testing"
)

func TestAppendJournalAssignsMonotonicSeqPerSession(t *testing.T) {
	db := openTestDB(t)

	for _, op := range []SessionOp{SessionOpCreate, SessionOpUpdate, SessionOpUpdate} {
		tx, err := db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		if err := appendJournal(tx, "s_a", "alloc_test", "agent_a", op, "/x", nil, nil, nil, "", nil); err != nil {
			t.Fatalf("append s_a: %v", err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	for _, op := range []SessionOp{SessionOpCreate, SessionOpDelete} {
		tx, err := db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		if err := appendJournal(tx, "s_b", "alloc_test", "agent_b", op, "/y", nil, nil, nil, "", nil); err != nil {
			t.Fatalf("append s_b: %v", err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}

	j := NewSessionJournal(db, nil)

	rowsA, _, err := j.Diff("s_a")
	if err != nil {
		t.Fatal(err)
	}
	if len(rowsA) != 3 {
		t.Fatalf("session A rows = %d, want 3", len(rowsA))
	}
	for i, row := range rowsA {
		if row.Seq != uint64(i+1) {
			t.Fatalf("session A seq[%d] = %d, want %d", i, row.Seq, i+1)
		}
		if row.Path != "/x" {
			t.Fatalf("session A path[%d] = %q, want /x", i, row.Path)
		}
	}

	rowsB, _, err := j.Diff("s_b")
	if err != nil {
		t.Fatal(err)
	}
	if len(rowsB) != 2 {
		t.Fatalf("session B rows = %d, want 2", len(rowsB))
	}
	if rowsB[0].Seq != 1 || rowsB[1].Seq != 2 {
		t.Fatalf("session B seqs = %d,%d, want 1,2", rowsB[0].Seq, rowsB[1].Seq)
	}
	if rowsB[0].Op != SessionOpCreate || rowsB[1].Op != SessionOpDelete {
		t.Fatalf("session B ops = %q,%q", rowsB[0].Op, rowsB[1].Op)
	}
}

func TestAppendJournalCarriesBeforeStateAndRenameFrom(t *testing.T) {
	db := openTestDB(t)

	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	priorMf := []byte{0xde, 0xad, 0xbe, 0xef}
	v := uint64(7)
	after := uint64(8)
	if err := appendJournal(tx, "s_test", "alloc_test", "agent_t", SessionOpUpdate, "/file", &v, &after, priorMf, "", nil); err != nil {
		t.Fatalf("append update: %v", err)
	}
	if err := appendJournal(
		tx, "s_test", "alloc_test", "agent_t", SessionOpRename, "/file2", &v, &after, priorMf, "/file", nil,
	); err != nil {
		t.Fatalf("append rename: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	rows, _, err := NewSessionJournal(db, nil).Diff("s_test")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(rows))
	}

	upd := rows[0]
	if upd.Op != SessionOpUpdate {
		t.Fatalf("op = %q, want update", upd.Op)
	}
	if upd.BeforeVersion == nil || *upd.BeforeVersion != 7 {
		t.Fatalf("before_version = %v, want *7", upd.BeforeVersion)
	}
	if string(upd.BeforeManifest) != string(priorMf) {
		t.Fatalf("before_manifest mismatch")
	}
	if upd.RenameFrom != "" {
		t.Fatalf("update row has rename_from = %q, want empty", upd.RenameFrom)
	}

	ren := rows[1]
	if ren.Op != SessionOpRename {
		t.Fatalf("op = %q, want rename", ren.Op)
	}
	if ren.RenameFrom != "/file" {
		t.Fatalf("rename_from = %q, want /file", ren.RenameFrom)
	}
	if ren.Path != "/file2" {
		t.Fatalf("path = %q, want /file2", ren.Path)
	}
}

func TestAppendJournalCreateOmitsBeforeState(t *testing.T) {
	db := openTestDB(t)

	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := appendJournal(tx, "s_c", "alloc_test", "agent_c", SessionOpCreate, "/new", nil, nil, nil, "", nil); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	rows, _, err := NewSessionJournal(db, nil).Diff("s_c")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	if rows[0].BeforeVersion != nil {
		t.Fatalf("before_version = %v, want nil", rows[0].BeforeVersion)
	}
	if rows[0].BeforeManifest != nil {
		t.Fatalf("before_manifest = %v, want nil", rows[0].BeforeManifest)
	}
}

func TestAppendJournalRejectsEmptySession(t *testing.T) {
	db := openTestDB(t)
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()

	err = appendJournal(tx, "", "alloc_test", "agent_x", SessionOpCreate, "/x", nil, nil, nil, "", nil)
	if err == nil || !strings.Contains(err.Error(), "empty session_id") {
		t.Fatalf("expected empty session_id error, got %v", err)
	}
}

func TestSessionJournalDiffUnknownSessionEmpty(t *testing.T) {
	rows, afters, err := NewSessionJournal(openTestDB(t), nil).Diff("never_existed")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 || len(afters) != 0 {
		t.Fatalf("rows=%d afters=%d, want both 0", len(rows), len(afters))
	}
}

// Issue #100: LookupLastWriter returns the most recent journal row for a
// path (greatest ts_unix_ms, ties broken by seq desc), and (nil, nil) when
// no row exists. The recovery hint at conflict time uses this to name the
// agent + session that landed the prior version.
func TestLookupLastWriterReturnsMostRecentByPath(t *testing.T) {
	db := openTestDB(t)
	store := NewManifestStore(db, nil)
	journal := NewSessionJournal(db, nil)

	if err := store.RegisterDir("/", "p"); err != nil {
		t.Fatal(err)
	}
	mf := Manifest{Path: "/p/file", Chunks: sampleChunks()}
	v, err := store.Put(mf.Path, 0, mf, "s_first", "alloc_test", "agent_first")
	if err != nil {
		t.Fatalf("first put: %v", err)
	}
	if _, err := store.Put(mf.Path, v, mf, "s_second", "alloc_test", "agent_second"); err != nil {
		t.Fatalf("second put: %v", err)
	}

	got, err := journal.LookupLastWriter("/p/file")
	if err != nil {
		t.Fatalf("LookupLastWriter: %v", err)
	}
	if got == nil {
		t.Fatal("expected a row, got nil")
	}
	if got.AgentID != "agent_second" {
		t.Errorf("agent_id = %q, want agent_second (most recent)", got.AgentID)
	}
	if got.SessionID != "s_second" {
		t.Errorf("session_id = %q, want s_second", got.SessionID)
	}
	if got.AtUnixMs == 0 {
		t.Error("at_unix_ms must be populated from the journal row")
	}

	missing, err := journal.LookupLastWriter("/never/written")
	if err != nil {
		t.Fatalf("LookupLastWriter on missing path: %v", err)
	}
	if missing != nil {
		t.Errorf("missing path returned %+v, want nil", missing)
	}
}

func TestSnapshotRowCountsGroupsByAllocation(t *testing.T) {
	db := openTestDB(t)

	writes := []struct {
		sid, alloc string
	}{
		{"s_a", "alloc_one"},
		{"s_a", "alloc_one"},
		{"s_b", "alloc_one"},
		{"s_c", "alloc_two"},
	}
	for _, w := range writes {
		tx, err := db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		if err := appendJournal(tx, w.sid, w.alloc, "agent_t", SessionOpCreate, "/x", nil, nil, nil, "", nil); err != nil {
			t.Fatalf("append %+v: %v", w, err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}

	counts, err := NewSessionJournal(db, nil).SnapshotRowCounts(context.Background())
	if err != nil {
		t.Fatalf("SnapshotRowCounts: %v", err)
	}
	if got := counts["alloc_one"]; got != 3 {
		t.Errorf("alloc_one = %d, want 3", got)
	}
	if got := counts["alloc_two"]; got != 1 {
		t.Errorf("alloc_two = %d, want 1", got)
	}
	if _, ok := counts["alloc_missing"]; ok {
		t.Errorf("alloc_missing should be absent")
	}
}
