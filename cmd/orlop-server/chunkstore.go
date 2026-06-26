package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"lukechampine.com/blake3"
)

// HashLen is the wire length of a chunk hash. BLAKE3-32.
const HashLen = 32

// ChunkStore writes content-addressed blobs into <root>/<first-2-hex>/<hash-hex>.
// Same instance is safe for concurrent use — every write goes through a temp
// file that's rename()'d into place, so partial writes never become visible
// and racing writers of the same hash see deterministic content (BLAKE3 of
// the bytes is the filename).
type ChunkStore struct {
	root string
}

// NewChunkStore returns a store rooted at <storeRoot>/objects.
func NewChunkStore(storeRoot string) (*ChunkStore, error) {
	root := filepath.Join(storeRoot, "objects")
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", root, err)
	}
	return &ChunkStore{root: root}, nil
}

// Path is the canonical filesystem location for a hash.
func (cs *ChunkStore) Path(hash []byte) (string, error) {
	if len(hash) != HashLen {
		return "", fmt.Errorf("hash must be %d bytes, got %d", HashLen, len(hash))
	}
	hexs := hex.EncodeToString(hash)
	return filepath.Join(cs.root, hexs[:2], hexs), nil
}

// Has returns whether the chunk is present on disk. Stat-based, cheap.
func (cs *ChunkStore) Has(hash []byte) (bool, error) {
	p, err := cs.Path(hash)
	if err != nil {
		return false, err
	}
	if _, err := os.Stat(p); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// Get returns the chunk bytes. Hash verification is left to the caller —
// stored content is content-addressed by definition; verification is wasted
// work on every hot-path read. Migration tools and tests verify explicitly.
func (cs *ChunkStore) Get(hash []byte) ([]byte, error) {
	p, err := cs.Path(hash)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// Put stores `data` under `hash`. Verifies BLAKE3(data) == hash before
// touching disk. Idempotent: if the chunk already exists, returns false
// (not stored, already there); otherwise true.
func (cs *ChunkStore) Put(hash, data []byte) (bool, error) {
	if len(hash) != HashLen {
		return false, fmt.Errorf("hash must be %d bytes, got %d", HashLen, len(hash))
	}
	computed := blake3.Sum256(data)
	if !bytes.Equal(computed[:], hash) {
		return false, fmt.Errorf(
			"hash mismatch: provided %s, computed %s",
			hex.EncodeToString(hash),
			hex.EncodeToString(computed[:]),
		)
	}
	p, err := cs.Path(hash)
	if err != nil {
		return false, err
	}
	if _, err := os.Stat(p); err == nil {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return false, fmt.Errorf("mkdir %s: %w", filepath.Dir(p), err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".chunk-*")
	if err != nil {
		return false, fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	cleanupTmp := func() { _ = os.Remove(tmpName) }
	// os.CreateTemp defaults to 0o600 — locked to the writing uid. When
	// `orlop-server -migrate-to-chunks` is invoked as a different user
	// (e.g. root) than the live server runs as (`orlop`), the resulting
	// chunks are unreadable to the server and handleChunkGet returns
	// silent EIO on every read (issue #125). Force 0o644 so any process
	// that already has dir-traversal access to <storeRoot>/objects can
	// open the file. Tenant isolation is enforced by the parent dirs
	// (<tenant>/store is mode 0o750 orlop:orlop).
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		cleanupTmp()
		return false, fmt.Errorf("chmod chunk: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanupTmp()
		return false, fmt.Errorf("write chunk: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanupTmp()
		return false, fmt.Errorf("sync chunk: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanupTmp()
		return false, fmt.Errorf("close chunk: %w", err)
	}
	if err := os.Rename(tmpName, p); err != nil {
		cleanupTmp()
		return false, fmt.Errorf("rename %s -> %s: %w", tmpName, p, err)
	}
	return true, nil
}

// Delete removes the on-disk file for hash. Idempotent: missing files
// return nil. Does not touch any DB row — refcount management is the
// caller's responsibility.
func (cs *ChunkStore) Delete(hash []byte) error {
	p, err := cs.Path(hash)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("chunk delete %x: %w", hash[:4], err)
	}
	return nil
}

// HasMany returns a parallel boolean slice for the requested hashes.
// Each `hashes[i]` should be HashLen bytes; the i-th boolean reflects
// whether that chunk is present.
func (cs *ChunkStore) HasMany(hashes [][]byte) ([]bool, error) {
	out := make([]bool, len(hashes))
	for i, h := range hashes {
		ok, err := cs.Has(h)
		if err != nil {
			return nil, fmt.Errorf("has[%d]: %w", i, err)
		}
		out[i] = ok
	}
	return out, nil
}
