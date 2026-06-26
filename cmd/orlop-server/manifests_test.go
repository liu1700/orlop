package main

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

// assertRefcount checks that the refcount for hash h in the chunks table equals want.
// If want == 0 and the row is absent, that is also acceptable.
func assertRefcount(t *testing.T, db *sql.DB, h [HashLen]byte, want int) {
	t.Helper()
	var got int
	err := db.QueryRow(`select refcount from chunks where hash = ?`, h[:]).Scan(&got)
	if err == sql.ErrNoRows && want == 0 {
		return
	}
	if err != nil {
		t.Fatalf("refcount query: %v", err)
	}
	if got != want {
		t.Fatalf("refcount[%x] = %d, want %d", h[:4], got, want)
	}
}

// testSchemaSQL mirrors the production schema set up by OpenTenantDB and
// the journal/sessions schemas. Single source of truth for test fixtures;
// setups that don't need every table still create them — overhead is one
// empty table per test DB.
const testSchemaSQL = `
	create table chunks (
	  hash blob primary key,
	  size integer not null,
	  refcount integer not null check (refcount >= 0),
	  added_at integer not null
	);
	create table manifests (
	  path text primary key,
	  size integer not null,
	  mode integer not null,
	  mtime integer not null,
	  version integer not null,
	  chunks blob not null,
	  uid integer not null default 0,
	  gid integer not null default 0,
	  atime integer not null default 0
	);
	create table dir_entries (
	  parent text not null,
	  name text not null,
	  mode integer not null default 493,
	  mtime integer not null default 0,
	  uid integer not null default 0,
	  gid integer not null default 0,
	  atime integer not null default 0,
	  primary key (parent, name)
	);
	create table symlinks (
	  path text primary key,
	  target text not null,
	  mode integer not null default 511,
	  mtime integer not null default 0,
	  uid integer not null default 0,
	  gid integer not null default 0,
	  atime integer not null default 0
	);
	create table special_nodes (
	  path text primary key,
	  mode integer not null,
	  rdev integer not null default 0,
	  mtime integer not null default 0,
	  uid integer not null default 0,
	  gid integer not null default 0,
	  atime integer not null default 0
	);
	create table session_journal (
	  session_id text not null,
	  seq integer not null,
	  path text not null,
	  op text not null,
	  before_version integer,
	  before_manifest blob,
	  rename_from text,
	  ts_unix_ms integer not null,
	  after_version integer,
	  agent_id text not null default '',
	  allocation_id text,
	  primary key (session_id, seq)
	);
	create index session_journal_by_path
	  on session_journal(path, ts_unix_ms desc);
	create index session_journal_by_allocation_ts
	  on session_journal(allocation_id, ts_unix_ms desc);
`

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(dir, "routes.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(testSchemaSQL); err != nil {
		t.Fatal(err)
	}
	return db
}

func sampleChunks() []ChunkRef {
	var h1, h2 [HashLen]byte
	for i := range h1 {
		h1[i] = byte(i)
	}
	for i := range h2 {
		h2[i] = byte(255 - i)
	}
	return []ChunkRef{
		{Hash: h1, Offset: 0, Len: 1024},
		{Hash: h2, Offset: 1024, Len: 2048},
	}
}

func TestManifestPutAndGet(t *testing.T) {
	db := openTestDB(t)
	store := NewManifestStore(db, nil)
	// Seed parent chain: /entities must exist under /, and /entities/a under /entities.
	if err := store.RegisterDir("/", "entities"); err != nil {
		t.Fatal(err)
	}
	if err := store.RegisterDir("/entities", "a"); err != nil {
		t.Fatal(err)
	}
	chunks := sampleChunks()
	m := Manifest{Path: "/entities/a/file.bin", Size: 3072, Mode: 0o644, Mtime: 12345, Chunks: chunks}

	v1, err := store.Put(m.Path, 0, m, "", "", "")
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if v1 != 1 {
		t.Fatalf("first version = %d, want 1", v1)
	}

	got, err := store.Get(m.Path)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Size != 3072 || got.Mode != 0o644 || got.Mtime != 12345 || got.Version != 1 {
		t.Fatalf("metadata mismatch: %+v", got)
	}
	if len(got.Chunks) != 2 || got.Chunks[0].Hash != chunks[0].Hash || got.Chunks[1].Len != 2048 {
		t.Fatalf("chunks mismatch: %+v", got.Chunks)
	}
}

func TestManifestPutInsertConflict(t *testing.T) {
	store := NewManifestStore(openTestDB(t), nil)
	m := Manifest{Path: "/x", Chunks: sampleChunks()}
	if _, err := store.Put(m.Path, 0, m, "", "", ""); err != nil {
		t.Fatal(err)
	}
	_, err := store.Put(m.Path, 0, m, "", "", "")
	if !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("expected conflict on second insert with version 0, got %v", err)
	}
}

func TestSetModeAndSymlink(t *testing.T) {
	store := NewManifestStore(openTestDB(t), nil)

	// Directory chmod — the operation that broke OpenClaw. DirCreate persists
	// the mode, SetMode updates it without touching any manifest, and DirInfo
	// reflects the new value.
	if err := store.DirCreate("/d", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := store.SetMode("/d", 0o700, "", "", "", ""); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}
	if mode, _, _, _, ok, err := store.DirInfo("/d"); err != nil || !ok || mode != 0o700 {
		t.Fatalf("DirInfo after chmod = (%o, %v, %v), want (0700, true, nil)", mode, ok, err)
	}

	// File chmod via SetMode bumps the manifest's stored mode.
	if _, err := store.Put("/d/f", 0, Manifest{Path: "/d/f", Mode: 0o644, Chunks: sampleChunks()}, "", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := store.SetMode("/d/f", 0o600, "", "", "", ""); err != nil {
		t.Fatalf("chmod file: %v", err)
	}
	if mf, err := store.Get("/d/f"); err != nil || mf.Mode != 0o600 {
		t.Fatalf("file mode after chmod = %o (err %v), want 0600", mf.Mode, err)
	}

	// Symlink create + readlink, and ListChildren classifies it.
	if err := store.Symlink("/d/lnk", "f", 0o777); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if target, err := store.Readlink("/d/lnk"); err != nil || target != "f" {
		t.Fatalf("readlink = (%q, %v), want (\"f\", nil)", target, err)
	}
	kinds := map[string]string{}
	children, err := store.ListChildren("/d")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range children {
		kinds[c.Name] = c.Kind
	}
	if kinds["lnk"] != "symlink" || kinds["f"] != "file" {
		t.Fatalf("ListChildren kinds = %v, want lnk=symlink, f=file", kinds)
	}
	if err := store.Symlink("/d/lnk", "f", 0o777); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("duplicate symlink err = %v, want ErrAlreadyExists", err)
	}
	// SetMode on a missing path is ENOENT-equivalent.
	if err := store.SetMode("/nope", 0o700, "", "", "", ""); !errors.Is(err, ErrManifestNotFound) {
		t.Fatalf("SetMode missing path err = %v, want ErrManifestNotFound", err)
	}
}

func TestManifestPutUpdateConflict(t *testing.T) {
	store := NewManifestStore(openTestDB(t), nil)
	m := Manifest{Path: "/y", Chunks: sampleChunks()}
	v1, err := store.Put(m.Path, 0, m, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	// Stale version should fail.
	_, err = store.Put(m.Path, v1+5, m, "", "", "")
	if !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("expected conflict on stale version, got %v", err)
	}
	// Correct version should succeed.
	v2, err := store.Put(m.Path, v1, m, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if v2 != v1+1 {
		t.Fatalf("v2 = %d, want %d", v2, v1+1)
	}
}

// Issue #103: a CAS conflict on Put returns *VersionConflictError carrying
// the server's actual current version, so the dataplane_server can attach it to
// the wire RecoveryHint.
func TestManifestPutConflictReturnsExistingVersion(t *testing.T) {
	store := NewManifestStore(openTestDB(t), nil)
	m := Manifest{Path: "/cas", Chunks: sampleChunks()}
	v1, err := store.Put(m.Path, 0, m, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	// Stale version: client thought version was v1+5 but server is at v1.
	_, err = store.Put(m.Path, v1+5, m, "", "", "")
	var conflict *VersionConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("expected *VersionConflictError, got %T: %v", err, err)
	}
	if !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("must still satisfy errors.Is(err, ErrVersionConflict) for legacy callers")
	}
	if conflict.Existing != v1 {
		t.Fatalf("Existing = %d, want %d (server's actual version)", conflict.Existing, v1)
	}
}

func TestManifestGetNotFound(t *testing.T) {
	store := NewManifestStore(openTestDB(t), nil)
	if _, err := store.Get("/missing"); !errors.Is(err, ErrManifestNotFound) {
		t.Fatalf("expected not-found, got %v", err)
	}
}

func TestManifestPutPopulatesDirEntries(t *testing.T) {
	db := openTestDB(t)
	store := NewManifestStore(db, nil)
	// Seed parent chain before Put.
	if err := store.RegisterDir("/", "entities"); err != nil {
		t.Fatal(err)
	}
	if err := store.RegisterDir("/entities", "foo"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put("/entities/foo/bar.txt", 0, Manifest{Path: "/entities/foo/bar.txt", Chunks: sampleChunks()}, "", "", ""); err != nil {
		t.Fatal(err)
	}
	row := db.QueryRow(`select count(*) from dir_entries where parent = ? and name = ?`, "/entities/foo", "bar.txt")
	var n int
	if err := row.Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("dir_entries row count = %d, want 1", n)
	}
}

func TestPackUnpackRoundTrip(t *testing.T) {
	chunks := sampleChunks()
	blob, _ := packChunks(chunks)
	if len(blob) != len(chunks)*chunkRefSize {
		t.Fatalf("packed size %d, want %d", len(blob), len(chunks)*chunkRefSize)
	}
	round, err := unpackChunks(blob)
	if err != nil {
		t.Fatal(err)
	}
	if len(round) != len(chunks) {
		t.Fatalf("len mismatch")
	}
	for i, c := range round {
		if c != chunks[i] {
			t.Fatalf("chunk %d mismatch: %+v vs %+v", i, c, chunks[i])
		}
	}
}

func TestPutInitialPopulatesChunkRefs(t *testing.T) {
	db := openTestDB(t)
	store := NewManifestStore(db, nil)
	var h1, h2 [HashLen]byte
	h1[0] = 1
	h1[1] = 2
	h1[2] = 3
	h2[0] = 4
	h2[1] = 5
	h2[2] = 6
	mf := Manifest{
		Path: "/a.txt", Size: 100, Mode: 0644,
		Chunks: []ChunkRef{
			{Hash: h1, Offset: 0, Len: 60},
			{Hash: h2, Offset: 60, Len: 40},
		},
	}
	if _, err := store.Put("/a.txt", 0, mf, "", "", ""); err != nil {
		t.Fatalf("Put: %v", err)
	}
	assertRefcount(t, db, h1, 1)
	assertRefcount(t, db, h2, 1)
}

func TestPutOverwriteAdjustsChunkRefs(t *testing.T) {
	db := openTestDB(t)
	store := NewManifestStore(db, nil)
	var h1, h2, h3 [HashLen]byte
	h1[0] = 1
	h2[0] = 2
	h3[0] = 3
	v, err := store.Put("/a.txt", 0, Manifest{
		Path:   "/a.txt",
		Chunks: []ChunkRef{{Hash: h1}, {Hash: h2}},
	}, "", "", "")
	if err != nil {
		t.Fatalf("initial Put: %v", err)
	}
	if _, err := store.Put("/a.txt", v, Manifest{
		Path:   "/a.txt",
		Chunks: []ChunkRef{{Hash: h2}, {Hash: h3}},
	}, "", "", ""); err != nil {
		t.Fatalf("overwrite Put: %v", err)
	}
	assertRefcount(t, db, h1, 0)
	assertRefcount(t, db, h2, 1)
	assertRefcount(t, db, h3, 1)
}

func TestPutRequiresExistingParent(t *testing.T) {
	db := openTestDB(t)
	store := NewManifestStore(db, nil)
	_, err := store.Put("/a/b/c.txt", 0, Manifest{Path: "/a/b/c.txt"}, "", "", "")
	if err == nil || !errors.Is(err, ErrParentNotFound) {
		t.Fatalf("expected ErrParentNotFound, got %v", err)
	}
}

func TestDeleteDecrementsChunkRefs(t *testing.T) {
	db := openTestDB(t)
	store := NewManifestStore(db, nil)
	var h1, h2 [HashLen]byte
	h1[0] = 1
	h2[0] = 2
	if _, err := store.Put("/a.txt", 0, Manifest{Path: "/a.txt", Chunks: []ChunkRef{{Hash: h1}, {Hash: h2}}}, "", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete("/a.txt", 1, "", "", ""); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	assertRefcount(t, db, h1, 0)
	assertRefcount(t, db, h2, 0)
	if _, err := store.Get("/a.txt"); !errors.Is(err, ErrManifestNotFound) {
		t.Fatalf("Get after Delete: want ErrManifestNotFound, got %v", err)
	}
}

func TestDeleteCASMismatch(t *testing.T) {
	db := openTestDB(t)
	store := NewManifestStore(db, nil)
	if _, err := store.Put("/a.txt", 0, Manifest{Path: "/a.txt"}, "", "", ""); err != nil {
		t.Fatal(err)
	}
	err := store.Delete("/a.txt", 999, "", "", "")
	if !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("want ErrVersionConflict, got %v", err)
	}
}

func TestDeleteAbsent(t *testing.T) {
	db := openTestDB(t)
	store := NewManifestStore(db, nil)
	err := store.Delete("/missing.txt", 0, "", "", "")
	if !errors.Is(err, ErrManifestNotFound) {
		t.Fatalf("want ErrManifestNotFound, got %v", err)
	}
}

func TestRenameMovesManifestPreservesRefcounts(t *testing.T) {
	db := openTestDB(t)
	store := NewManifestStore(db, nil)
	h := [HashLen]byte{1}
	if _, err := store.Put("/a.txt", 0, Manifest{Path: "/a.txt", Chunks: []ChunkRef{{Hash: h}}}, "", "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Rename("/a.txt", "/b.txt", 1, 0, "", "", ""); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if _, err := store.Get("/a.txt"); !errors.Is(err, ErrManifestNotFound) {
		t.Fatal("source still present")
	}
	if _, err := store.Get("/b.txt"); err != nil {
		t.Fatalf("dest missing: %v", err)
	}
	assertRefcount(t, db, h, 1)
}

func TestRenameOverwriteDecrementsDestChunks(t *testing.T) {
	db := openTestDB(t)
	store := NewManifestStore(db, nil)
	hSrc := [HashLen]byte{1}
	hDst := [HashLen]byte{2}
	if _, err := store.Put("/a.txt", 0, Manifest{Path: "/a.txt", Chunks: []ChunkRef{{Hash: hSrc}}}, "", "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put("/b.txt", 0, Manifest{Path: "/b.txt", Chunks: []ChunkRef{{Hash: hDst}}}, "", "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Rename("/a.txt", "/b.txt", 1, 1, "", "", ""); err != nil {
		t.Fatal(err)
	}
	assertRefcount(t, db, hSrc, 1) // moved
	assertRefcount(t, db, hDst, 0) // displaced
}

// TestRenameDestExistsOverwrites asserts POSIX overwrite: renaming a regular
// file onto an existing regular-file destination removes the dest and moves the
// source onto it (no ErrAlreadyExists). expectedTo=0 no longer means "dest must
// not exist" — overwrite is decided by type-compatibility, not CAS-as-gate.
func TestRenameDestExistsOverwrites(t *testing.T) {
	db := openTestDB(t)
	store := NewManifestStore(db, nil)
	if _, err := store.Put("/a.txt", 0, Manifest{Path: "/a.txt"}, "", "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put("/b.txt", 0, Manifest{Path: "/b.txt"}, "", "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Rename("/a.txt", "/b.txt", 1, 0, "", "", ""); err != nil {
		t.Fatalf("Rename overwrite: %v", err)
	}
	if _, err := store.Get("/a.txt"); !errors.Is(err, ErrManifestNotFound) {
		t.Fatal("source still present after overwrite rename")
	}
	if _, err := store.Get("/b.txt"); err != nil {
		t.Fatalf("dest missing after overwrite rename: %v", err)
	}
}

func TestDirCreate(t *testing.T) {
	db := openTestDB(t)
	store := NewManifestStore(db, nil)
	if err := store.DirCreate("/a", 0755); err != nil {
		t.Fatalf("DirCreate: %v", err)
	}
	var n int
	db.QueryRow(`select count(*) from dir_entries where parent='/' and name='a'`).Scan(&n)
	if n != 1 {
		t.Fatalf("dir_entries count = %d, want 1", n)
	}
}

func TestDirCreateMissingParent(t *testing.T) {
	db := openTestDB(t)
	store := NewManifestStore(db, nil)
	err := store.DirCreate("/a/b", 0755)
	if !errors.Is(err, ErrParentNotFound) {
		t.Fatalf("want ErrParentNotFound, got %v", err)
	}
}

func TestDirCreateAlreadyExists(t *testing.T) {
	db := openTestDB(t)
	store := NewManifestStore(db, nil)
	if err := store.DirCreate("/a", 0755); err != nil {
		t.Fatal(err)
	}
	err := store.DirCreate("/a", 0755)
	if !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("want ErrAlreadyExists, got %v", err)
	}
}

func TestIsDirEmptyDirAndOrphanRow(t *testing.T) {
	// Regression: an explicitly-created empty dir, or a dir_entries row left
	// behind after every child was deleted, must still stat as a directory.
	// Without this, mkdir -p sees EEXIST from DirCreate then ENOENT from
	// handleStat and aborts with "File exists".
	db := openTestDB(t)
	store := NewManifestStore(db, nil)

	if err := store.DirCreate("/a", 0755); err != nil {
		t.Fatal(err)
	}
	// Empty dir created via DirCreate: must be IsDir=true.
	isDir, err := store.IsDir("/a")
	if err != nil || !isDir {
		t.Fatalf("IsDir(/a) after DirCreate = (%v, %v), want (true, nil)", isDir, err)
	}

	// Drop to the orphan shape: row in dir_entries, no children, no manifest.
	// Mimics what happens after a child file is Put then Deleted.
	if _, err := store.Put("/a/x", 0, Manifest{Path: "/a/x"}, "", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete("/a/x", 1, "", "", ""); err != nil {
		t.Fatal(err)
	}
	isDir, err = store.IsDir("/a")
	if err != nil || !isDir {
		t.Fatalf("IsDir(/a) after drain = (%v, %v), want (true, nil)", isDir, err)
	}
	// DirCreate on the same path must still reject — the two checks must agree.
	if err := store.DirCreate("/a", 0755); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("DirCreate(/a) on existing = %v, want ErrAlreadyExists", err)
	}
}

func TestIsDirNonexistent(t *testing.T) {
	db := openTestDB(t)
	store := NewManifestStore(db, nil)
	isDir, err := store.IsDir("/nope")
	if err != nil || isDir {
		t.Fatalf("IsDir(/nope) = (%v, %v), want (false, nil)", isDir, err)
	}
}

func TestDirRemove(t *testing.T) {
	db := openTestDB(t)
	store := NewManifestStore(db, nil)
	if err := store.DirCreate("/a", 0755); err != nil {
		t.Fatal(err)
	}
	if err := store.DirRemove("/a"); err != nil {
		t.Fatalf("DirRemove: %v", err)
	}
}

func TestDirRemoveNotEmpty(t *testing.T) {
	db := openTestDB(t)
	store := NewManifestStore(db, nil)
	if err := store.DirCreate("/a", 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put("/a/file.txt", 0, Manifest{Path: "/a/file.txt"}, "", "", ""); err != nil {
		t.Fatal(err)
	}
	err := store.DirRemove("/a")
	if !errors.Is(err, ErrNotEmpty) {
		t.Fatalf("want ErrNotEmpty, got %v", err)
	}
}

// --- POSIX rename(2) full-matrix coverage -------------------------------

func TestRenameSourceMissingENOENT(t *testing.T) {
	db := openTestDB(t)
	store := NewManifestStore(db, nil)
	if _, err := store.Rename("/nope", "/x", 0, 0, "", "", ""); !errors.Is(err, ErrManifestNotFound) {
		t.Fatalf("want ErrManifestNotFound, got %v", err)
	}
}

func TestRenameSamePathNoop(t *testing.T) {
	db := openTestDB(t)
	store := NewManifestStore(db, nil)
	if _, err := store.Put("/a.txt", 0, Manifest{Path: "/a.txt"}, "", "", ""); err != nil {
		t.Fatal(err)
	}
	v, err := store.Rename("/a.txt", "/a.txt", 1, 1, "", "", "")
	if err != nil {
		t.Fatalf("same-path rename: %v", err)
	}
	if v != 1 {
		t.Fatalf("same-path version = %d, want 1", v)
	}
	if _, err := store.Get("/a.txt"); err != nil {
		t.Fatalf("source vanished after no-op: %v", err)
	}
}

func TestRenameSymlinkMoves(t *testing.T) {
	db := openTestDB(t)
	store := NewManifestStore(db, nil)
	if err := store.Symlink("/lnk", "target", 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Rename("/lnk", "/lnk2", 0, 0, "", "", ""); err != nil {
		t.Fatalf("symlink rename: %v", err)
	}
	if _, err := store.Readlink("/lnk"); !errors.Is(err, ErrManifestNotFound) {
		t.Fatal("old symlink still present")
	}
	tgt, err := store.Readlink("/lnk2")
	if err != nil || tgt != "target" {
		t.Fatalf("dest symlink target = %q err=%v, want \"target\"", tgt, err)
	}
}

func TestRenameSpecialNodeMoves(t *testing.T) {
	db := openTestDB(t)
	store := NewManifestStore(db, nil)
	if err := store.Mknod("/fifo", sIFIFO|0o644, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Rename("/fifo", "/fifo2", 0, 0, "", "", ""); err != nil {
		t.Fatalf("special node rename: %v", err)
	}
	if _, _, _, _, _, _, ok, _ := store.SpecialNodeInfo("/fifo"); ok {
		t.Fatal("old special node still present")
	}
	if _, _, _, _, _, _, ok, _ := store.SpecialNodeInfo("/fifo2"); !ok {
		t.Fatal("dest special node missing")
	}
}

func TestRenameRegularOverwritesSymlink(t *testing.T) {
	db := openTestDB(t)
	store := NewManifestStore(db, nil)
	if _, err := store.Put("/a.txt", 0, Manifest{Path: "/a.txt"}, "", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := store.Symlink("/b", "tgt", 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Rename("/a.txt", "/b", 1, 0, "", "", ""); err != nil {
		t.Fatalf("file-over-symlink rename: %v", err)
	}
	// /b is now a regular file, the symlink row is gone.
	if _, err := store.Readlink("/b"); !errors.Is(err, ErrManifestNotFound) {
		t.Fatal("symlink dest not displaced")
	}
	if _, err := store.Get("/b"); err != nil {
		t.Fatalf("dest file missing after overwrite: %v", err)
	}
}

func TestRenameSymlinkOverwritesSpecialNode(t *testing.T) {
	db := openTestDB(t)
	store := NewManifestStore(db, nil)
	if err := store.Symlink("/s", "tgt", 0o777); err != nil {
		t.Fatal(err)
	}
	if err := store.Mknod("/n", sIFIFO|0o644, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Rename("/s", "/n", 0, 0, "", "", ""); err != nil {
		t.Fatalf("symlink-over-special rename: %v", err)
	}
	if _, _, _, _, _, _, ok, _ := store.SpecialNodeInfo("/n"); ok {
		t.Fatal("special node dest not displaced")
	}
	if tgt, err := store.Readlink("/n"); err != nil || tgt != "tgt" {
		t.Fatalf("dest symlink target=%q err=%v", tgt, err)
	}
}

func TestRenameDirOntoNonDirENOTDIR(t *testing.T) {
	db := openTestDB(t)
	store := NewManifestStore(db, nil)
	if err := store.DirCreate("/d", 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put("/f.txt", 0, Manifest{Path: "/f.txt"}, "", "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Rename("/d", "/f.txt", 0, 0, "", "", ""); !errors.Is(err, ErrNotDir) {
		t.Fatalf("want ErrNotDir, got %v", err)
	}
}

func TestRenameNonDirOntoDirEISDIR(t *testing.T) {
	db := openTestDB(t)
	store := NewManifestStore(db, nil)
	if _, err := store.Put("/f.txt", 0, Manifest{Path: "/f.txt"}, "", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := store.DirCreate("/d", 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Rename("/f.txt", "/d", 1, 0, "", "", ""); !errors.Is(err, ErrIsDir) {
		t.Fatalf("want ErrIsDir, got %v", err)
	}
}

func TestRenameDirOntoNonEmptyDirENOTEMPTY(t *testing.T) {
	db := openTestDB(t)
	store := NewManifestStore(db, nil)
	if err := store.DirCreate("/src", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := store.DirCreate("/dst", 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put("/dst/child.txt", 0, Manifest{Path: "/dst/child.txt"}, "", "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Rename("/src", "/dst", 0, 0, "", "", ""); !errors.Is(err, ErrNotEmpty) {
		t.Fatalf("want ErrNotEmpty, got %v", err)
	}
}

func TestRenameDirOntoEmptyDirOverwrites(t *testing.T) {
	db := openTestDB(t)
	store := NewManifestStore(db, nil)
	if err := store.DirCreate("/src", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := store.DirCreate("/dst", 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Rename("/src", "/dst", 0, 0, "", "", ""); err != nil {
		t.Fatalf("dir-over-empty-dir rename: %v", err)
	}
	if ok, _ := store.IsDir("/src"); ok {
		t.Fatal("source dir still present")
	}
	if ok, _ := store.IsDir("/dst"); !ok {
		t.Fatal("dest dir missing")
	}
}

func TestRenameDirReparentsDescendants(t *testing.T) {
	db := openTestDB(t)
	store := NewManifestStore(db, nil)
	// /src, /src/sub, /src/a.txt, /src/sub/b.txt
	if err := store.DirCreate("/src", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := store.DirCreate("/src/sub", 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put("/src/a.txt", 0, Manifest{Path: "/src/a.txt"}, "", "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put("/src/sub/b.txt", 0, Manifest{Path: "/src/sub/b.txt"}, "", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := store.Symlink("/src/lnk", "x", 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Rename("/src", "/dst", 0, 0, "", "", ""); err != nil {
		t.Fatalf("dir rename: %v", err)
	}
	// Old paths gone, new paths present at the re-parented locations.
	if _, err := store.Get("/src/a.txt"); !errors.Is(err, ErrManifestNotFound) {
		t.Fatal("/src/a.txt still present")
	}
	if _, err := store.Get("/dst/a.txt"); err != nil {
		t.Fatalf("/dst/a.txt missing: %v", err)
	}
	if _, err := store.Get("/dst/sub/b.txt"); err != nil {
		t.Fatalf("/dst/sub/b.txt missing (nested re-parent failed): %v", err)
	}
	if tgt, err := store.Readlink("/dst/lnk"); err != nil || tgt != "x" {
		t.Fatalf("/dst/lnk target=%q err=%v", tgt, err)
	}
	if ok, _ := store.IsDir("/dst/sub"); !ok {
		t.Fatal("/dst/sub not a dir after re-parent")
	}
	// Listing /dst should surface a.txt, sub, lnk.
	kids, err := store.ListChildren("/dst")
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, k := range kids {
		names[k.Name] = true
	}
	for _, want := range []string{"a.txt", "sub", "lnk"} {
		if !names[want] {
			t.Fatalf("listing /dst missing %q (got %v)", want, names)
		}
	}
}
