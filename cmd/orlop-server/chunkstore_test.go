package main

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"lukechampine.com/blake3"
)

func TestChunkStorePutGetRoundTrip(t *testing.T) {
	dir, err := os.MkdirTemp("", "chunkstore-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	cs, err := NewChunkStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("hello content-addressed world")
	hash := blake3.Sum256(data)

	stored, err := cs.Put(hash[:], data)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if !stored {
		t.Fatal("first put should report stored=true")
	}

	got, err := cs.Get(hash[:])
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("content mismatch")
	}
}

func TestChunkStorePutIsIdempotent(t *testing.T) {
	dir, _ := os.MkdirTemp("", "chunkstore-")
	defer os.RemoveAll(dir)
	cs, _ := NewChunkStore(dir)

	data := []byte("idempotent")
	hash := blake3.Sum256(data)

	if _, err := cs.Put(hash[:], data); err != nil {
		t.Fatal(err)
	}
	stored, err := cs.Put(hash[:], data)
	if err != nil {
		t.Fatalf("re-put: %v", err)
	}
	if stored {
		t.Fatal("second put should report stored=false")
	}
}

func TestChunkStoreRejectsHashMismatch(t *testing.T) {
	dir, _ := os.MkdirTemp("", "chunkstore-")
	defer os.RemoveAll(dir)
	cs, _ := NewChunkStore(dir)

	data := []byte("xxxxxxxx")
	wrong := blake3.Sum256([]byte("not the data"))
	if _, err := cs.Put(wrong[:], data); err == nil {
		t.Fatal("expected hash mismatch error")
	}
}

func TestChunkStoreHas(t *testing.T) {
	dir, _ := os.MkdirTemp("", "chunkstore-")
	defer os.RemoveAll(dir)
	cs, _ := NewChunkStore(dir)

	a := blake3.Sum256([]byte("a"))
	b := blake3.Sum256([]byte("b"))
	missing := blake3.Sum256([]byte("c"))

	cs.Put(a[:], []byte("a"))
	cs.Put(b[:], []byte("b"))

	out, err := cs.HasMany([][]byte{a[:], missing[:], b[:]})
	if err != nil {
		t.Fatal(err)
	}
	if !out[0] || out[1] || !out[2] {
		t.Fatalf("HasMany result = %v, want [true, false, true]", out)
	}
}

func TestChunkStoreRejectsWrongHashLen(t *testing.T) {
	dir, _ := os.MkdirTemp("", "chunkstore-")
	defer os.RemoveAll(dir)
	cs, _ := NewChunkStore(dir)

	if _, err := cs.Put([]byte("short"), []byte("data")); err == nil {
		t.Fatal("expected length error")
	}
}

// Issue #125: chunks must be readable by every process inside the storeRoot,
// not just by the writer. When `orlop-server -migrate-to-chunks` is invoked
// as a different user (e.g. root) than the live server runs as (`orlop`),
// `os.CreateTemp`'s default 0600 left the resulting files unreadable to the
// server, and handleChunkGet returned EIO with no audit row. Pin the mode
// so future regressions land here instead of staging.
func TestChunkStorePutFilesAreModeReadable(t *testing.T) {
	cs, err := NewChunkStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("readable everywhere inside the store")
	h := blake3.Sum256(data)
	if _, err := cs.Put(h[:], data); err != nil {
		t.Fatalf("Put: %v", err)
	}
	p, err := cs.Path(h[:])
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	const want = 0o644
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("chunk file mode = %#o, want %#o (issue #125: cross-user reads must succeed)", got, want)
	}
}

func TestChunkStoreDeleteRemovesFile(t *testing.T) {
	root := t.TempDir()
	cs, err := NewChunkStore(root)
	if err != nil {
		t.Fatal(err)
	}
	b := []byte("hello chunk")
	h := blake3.Sum256(b)
	if _, err := cs.Put(h[:], b); err != nil {
		t.Fatal(err)
	}

	if err := cs.Delete(h[:]); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	// Verify the file was actually removed.
	p, err := cs.Path(h[:])
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("chunk file still present after Delete: stat err = %v", err)
	}
	// Second delete is a no-op (idempotent).
	if err := cs.Delete(h[:]); err != nil {
		t.Errorf("Delete on missing should be nil, got %v", err)
	}
}
