package main

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	_ "modernc.org/sqlite"
)

func TestOpenTenantDBMigratesStableInodeIDs(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "routes.db")
	legacy, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Exec(`
		create table manifests (
		  path text primary key,
		  size integer not null,
		  mode integer not null,
		  mtime integer not null,
		  version integer not null,
		  chunks blob not null
		);
		insert into manifests(path,size,mode,mtime,version,chunks)
		values('/a',0,420,0,1,x''),('/b',0,420,0,1,x'');
	`); err != nil {
		t.Fatal(err)
	}
	_ = legacy.Close()

	tenant, err := OpenTenantDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer tenant.Close()
	var a, b uint64
	if err := tenant.DB().QueryRow(`select inode_id from manifests where path='/a'`).Scan(&a); err != nil {
		t.Fatal(err)
	}
	if err := tenant.DB().QueryRow(`select inode_id from manifests where path='/b'`).Scan(&b); err != nil {
		t.Fatal(err)
	}
	if a == 0 || b == 0 || a == b {
		t.Fatalf("migrated inode ids = (%d,%d), want distinct non-zero", a, b)
	}
	store := NewManifestStore(tenant.DB(), nil)
	if _, err := store.Put("/c", 0, Manifest{Path: "/c"}, "", "", ""); err != nil {
		t.Fatal(err)
	}
	c, err := store.Get("/c")
	if err != nil {
		t.Fatal(err)
	}
	if c.InodeID <= max(a, b) {
		t.Fatalf("new inode id = %d, want greater than migrated max %d", c.InodeID, max(a, b))
	}
}

func TestConcurrentCreatesAllocateDistinctInodes(t *testing.T) {
	tenant, err := OpenTenantDB(filepath.Join(t.TempDir(), "routes.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer tenant.Close()
	store := NewManifestStore(tenant.DB(), nil)

	const count = 24
	errs := make(chan error, count)
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p := fmt.Sprintf("/file-%02d", i)
			_, err := store.Put(p, 0, Manifest{Path: p}, "", "", "")
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent create: %v", err)
		}
	}
	var total, distinct int
	if err := tenant.DB().QueryRow(`
		select count(*), count(distinct inode_id) from manifests
	`).Scan(&total, &distinct); err != nil {
		t.Fatal(err)
	}
	if total != count || distinct != count {
		t.Fatalf("manifest/inode counts = %d/%d, want %d/%d", total, distinct, count, count)
	}
}
