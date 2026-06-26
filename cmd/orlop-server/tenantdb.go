package main

import (
	"database/sql"
	"fmt"
	"strings"

	_ "modernc.org/sqlite"
)

// TenantDB is the per-tenant SQLite handle that backs the chunk store,
// manifest store, session journal, and session table. The data it holds
// is the entire on-disk state for one tenant's namespace; a hosted tenant
// is a `<storeRoot>/routes.db` plus the chunk objects under
// `<storeRoot>/objects/`.
//
// The struct is just a typed wrapper around `*sql.DB` — schema setup happens
// on Open, and every consumer (ManifestStore, SessionStore, SessionJournal,
// the GC loop) shares the same underlying handle via DB().
type TenantDB struct {
	db *sql.DB
}

// OpenTenantDB opens the per-tenant SQLite database, creates the schema if
// missing, and returns a handle. Idempotent: re-running on an existing
// database is a no-op.
//
// Journal mode is WAL with synchronous=NORMAL. Each tenant DB has exactly one
// opener (this server; server_vms placement is sticky), so WAL's same-host
// requirement holds. The win is on networked tenant roots (JuiceFS): a
// DELETE-journal commit costs several metadata round-trips (journal create +
// fsync + unlink) — measured ~88ms/commit on JuiceFS-over-Postgres vs ~23ms
// with WAL+NORMAL. NORMAL means a crash can roll back the WAL tail (never
// corrupt): a just-acked manifest write may revert, leaving an orphan chunk —
// the same orphan class the GC already tolerates.
func OpenTenantDB(path string) (*TenantDB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open tenant db %s: %w", path, err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping tenant db %s: %w", path, err)
	}
	if _, err := db.Exec(`
		pragma journal_mode = wal;
		pragma synchronous = normal;
		pragma busy_timeout = 10000;
	`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("set tenant db pragmas %s: %w", path, err)
	}
	if err := ensureTenantSchema(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ensure tenant schema %s: %w", path, err)
	}
	return &TenantDB{db: db}, nil
}

// ensureTenantSchema creates the chunk-store and manifest tables if missing.
// Dynamic tenants (the admin/tenants flow) inherit an empty database here;
// without this every read/write on a fresh tenant would fail with
// "no such table". Idempotent.
func ensureTenantSchema(db *sql.DB) error {
	_, err := db.Exec(`
		create table if not exists chunks (
		  hash blob primary key,
		  size integer not null,
		  refcount integer not null default 0 check (refcount >= 0),
		  added_at integer not null
		);
		create table if not exists manifests (
		  path text primary key,
		  size integer not null,
		  mode integer not null,
		  mtime integer not null,
		  version integer not null,
		  chunks blob not null
		);
		create table if not exists dir_entries (
		  parent text not null,
		  name text not null,
		  primary key (parent, name)
		);
		create index if not exists dir_entries_parent on dir_entries(parent);
		create table if not exists symlinks (
		  path text primary key,
		  target text not null,
		  mode integer not null default 511,
		  mtime integer not null default 0
		);
		create table if not exists special_nodes (
		  path text primary key,
		  mode integer not null,
		  rdev integer not null default 0,
		  mtime integer not null default 0,
		  uid integer not null default 0,
		  gid integer not null default 0,
		  atime integer not null default 0
		);
	`)
	if err != nil {
		return err
	}
	// dir_entries gained mode/mtime columns after first ship; add them in place
	// so existing tenant DBs keep working (chmod on a directory persists here —
	// files carry mode in their manifest row instead). 493 = 0o755.
	//
	// uid/gid/atime were added for A-class POSIX work (chown + utimensat
	// store-and-readback). They live on all three metadata tables (manifests,
	// dir_entries, symlinks) so stat reads owner+atime back for every kind.
	// Default 0 = root-owned, the correct fallback on a single-identity (uid 0)
	// mount. All ALTERs tolerate "duplicate column name" so already-migrated
	// tenant DBs are a no-op.
	for _, alter := range []string{
		`alter table dir_entries add column mode integer not null default 493`,
		`alter table dir_entries add column mtime integer not null default 0`,
		`alter table manifests add column uid integer not null default 0`,
		`alter table manifests add column gid integer not null default 0`,
		`alter table manifests add column atime integer not null default 0`,
		`alter table dir_entries add column uid integer not null default 0`,
		`alter table dir_entries add column gid integer not null default 0`,
		`alter table dir_entries add column atime integer not null default 0`,
		`alter table symlinks add column uid integer not null default 0`,
		`alter table symlinks add column gid integer not null default 0`,
		`alter table symlinks add column atime integer not null default 0`,
	} {
		if _, err := db.Exec(alter); err != nil && !strings.Contains(err.Error(), "duplicate column name") {
			return err
		}
	}
	return nil
}

// Close releases the underlying SQLite handle.
func (t *TenantDB) Close() error {
	return t.db.Close()
}

// DB returns the raw *sql.DB. ManifestStore, SessionStore, SessionJournal,
// and the GC loop share the same handle rather than opening duplicate ones.
func (t *TenantDB) DB() *sql.DB {
	return t.db
}
