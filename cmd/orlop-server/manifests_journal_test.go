package main

import (
	"testing"

	"github.com/vmihailenco/msgpack/v5"
)

// Acceptance from issue #104: 3 writes inside a session leave 3 rows in
// session_journal in seq order, with op=create on the first and op=update
// on the next two. before_version and before_manifest are populated for
// updates and nil for the create.
func TestManifestPutJournalsCreateThenUpdates(t *testing.T) {
	db := openTestDB(t)
	store := NewManifestStore(db, nil)
	journal := NewSessionJournal(db, nil)

	mf := Manifest{Path: "/file", Size: 100, Mode: 0o644, Mtime: 1, Chunks: sampleChunks()}
	v, err := store.Put(mf.Path, 0, mf, "s_1", "alloc_test", "agent_1")
	if err != nil {
		t.Fatalf("create put: %v", err)
	}
	mf.Size = 200
	v, err = store.Put(mf.Path, v, mf, "s_1", "alloc_test", "agent_1")
	if err != nil {
		t.Fatalf("update put 1: %v", err)
	}
	mf.Size = 300
	if _, err := store.Put(mf.Path, v, mf, "s_1", "alloc_test", "agent_1"); err != nil {
		t.Fatalf("update put 2: %v", err)
	}

	rows, _, err := journal.Diff("s_1")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want 3", len(rows))
	}
	wantOps := []SessionOp{SessionOpCreate, SessionOpUpdate, SessionOpUpdate}
	for i, row := range rows {
		if row.Seq != uint64(i+1) {
			t.Fatalf("rows[%d].Seq = %d, want %d", i, row.Seq, i+1)
		}
		if row.Op != wantOps[i] {
			t.Fatalf("rows[%d].Op = %q, want %q", i, row.Op, wantOps[i])
		}
		if row.Path != "/file" {
			t.Fatalf("rows[%d].Path = %q, want /file", i, row.Path)
		}
	}
	if rows[0].BeforeVersion != nil || rows[0].BeforeManifest != nil {
		t.Fatalf("create row carries before-state: ver=%v blob=%d", rows[0].BeforeVersion, len(rows[0].BeforeManifest))
	}
	if rows[1].BeforeVersion == nil || *rows[1].BeforeVersion != 1 {
		t.Fatalf("update[1] before_version = %v, want *1", rows[1].BeforeVersion)
	}
	if rows[2].BeforeVersion == nil || *rows[2].BeforeVersion != 2 {
		t.Fatalf("update[2] before_version = %v, want *2", rows[2].BeforeVersion)
	}
	var blob journalManifestBlob
	if err := msgpack.Unmarshal(rows[2].BeforeManifest, &blob); err != nil {
		t.Fatalf("decode before_manifest: %v", err)
	}
	if blob.Size != 200 || blob.Version != 2 {
		t.Fatalf("decoded prior manifest = %+v, want size=200 version=2", blob)
	}
}

// Acceptance: a rename inside a session writes one row with op=rename and
// rename_from pointing at the source path.
func TestManifestRenameJournalsWithRenameFrom(t *testing.T) {
	db := openTestDB(t)
	store := NewManifestStore(db, nil)
	journal := NewSessionJournal(db, nil)

	src := Manifest{Path: "/a", Mode: 0o644, Chunks: sampleChunks()}
	if _, err := store.Put(src.Path, 0, src, "", "", ""); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := store.Rename("/a", "/b", 1, 0, "s_rename", "alloc_test", "agent_r"); err != nil {
		t.Fatalf("rename: %v", err)
	}

	rows, _, err := journal.Diff("s_rename")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	r := rows[0]
	if r.Op != SessionOpRename {
		t.Fatalf("op = %q, want rename", r.Op)
	}
	if r.RenameFrom != "/a" {
		t.Fatalf("rename_from = %q, want /a", r.RenameFrom)
	}
	if r.Path != "/b" {
		t.Fatalf("path = %q, want /b (dest)", r.Path)
	}
	if r.BeforeVersion == nil || *r.BeforeVersion != 1 {
		t.Fatalf("before_version = %v, want *1", r.BeforeVersion)
	}
	if len(r.BeforeManifest) == 0 {
		t.Fatal("before_manifest empty — revert can't restore source")
	}
}

// Acceptance: a delete inside a session writes one row with op=delete and
// the full prior manifest captured.
func TestManifestDeleteJournalsPriorManifest(t *testing.T) {
	db := openTestDB(t)
	store := NewManifestStore(db, nil)
	journal := NewSessionJournal(db, nil)

	mf := Manifest{Path: "/d", Size: 7, Mode: 0o600, Mtime: 99, Chunks: sampleChunks()}
	if _, err := store.Put(mf.Path, 0, mf, "", "", ""); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := store.Delete(mf.Path, 1, "s_del", "alloc_test", "agent_d"); err != nil {
		t.Fatalf("delete: %v", err)
	}

	rows, _, err := journal.Diff("s_del")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	r := rows[0]
	if r.Op != SessionOpDelete {
		t.Fatalf("op = %q, want delete", r.Op)
	}
	if r.Path != "/d" {
		t.Fatalf("path = %q, want /d", r.Path)
	}
	if r.BeforeVersion == nil || *r.BeforeVersion != 1 {
		t.Fatalf("before_version = %v, want *1", r.BeforeVersion)
	}
	var blob journalManifestBlob
	if err := msgpack.Unmarshal(r.BeforeManifest, &blob); err != nil {
		t.Fatalf("decode before_manifest: %v", err)
	}
	if blob.Size != 7 || blob.Mode != 0o600 || blob.Mtime != 99 {
		t.Fatalf("decoded prior manifest = %+v, want size=7 mode=0o600 mtime=99", blob)
	}
	if len(blob.Chunks) != len(mf.Chunks) {
		t.Fatalf("chunk count = %d, want %d", len(blob.Chunks), len(mf.Chunks))
	}
}

// Acceptance: empty session_id is the existing path — no journal row written,
// no behaviour change for unsessioned writes.
func TestManifestPutWithoutSessionSkipsJournal(t *testing.T) {
	db := openTestDB(t)
	store := NewManifestStore(db, nil)
	if _, err := store.Put("/x", 0, Manifest{Path: "/x", Chunks: sampleChunks()}, "", "", ""); err != nil {
		t.Fatal(err)
	}
	rows, _, err := NewSessionJournal(db, nil).Diff("")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("rows = %d, want 0 (no journal for empty session)", len(rows))
	}
	var n int
	if err := db.QueryRow(`select count(*) from session_journal`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("session_journal has %d rows, want 0", n)
	}
}

// Acceptance: if the journal insert fails the manifest write rolls back too.
// We simulate the failure by dropping session_journal so appendJournal errors,
// then assert no manifest row was committed.
func TestManifestPutRollsBackWhenJournalInsertFails(t *testing.T) {
	db := openTestDB(t)
	store := NewManifestStore(db, nil)

	if _, err := db.Exec(`drop table session_journal`); err != nil {
		t.Fatal(err)
	}

	mf := Manifest{Path: "/wat", Chunks: sampleChunks()}
	if _, err := store.Put(mf.Path, 0, mf, "s_clash", "alloc_test", "agent_clash"); err == nil {
		t.Fatal("expected put to fail when journal table is missing")
	}

	var n int
	if err := db.QueryRow(`select count(*) from manifests where path = ?`, mf.Path).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("manifest row leaked through despite journal failure: count=%d", n)
	}
}
