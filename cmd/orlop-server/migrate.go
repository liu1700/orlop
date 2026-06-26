package main

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// runMigrateToChunks walks every configured tenant's store root, chunks each
// flat file via FastCDC, writes chunks under <storeRoot>/objects, and upserts
// manifests in routes.db. Idempotent: a re-run that finds an existing
// manifest with the same chunk list is a no-op.
//
// Returns nil if every tenant's store finishes cleanly. Per-file errors fail
// the run loudly so an operator notices — partial state on disk (chunks
// written, manifest not) is fine because chunks are content-addressed.
func runMigrateToChunks(ctx context.Context, logger *slog.Logger, cfg Config) error {
	state, err := newServerState(cfg, certIdentifier{trustDomain: cfg.TrustDomain}, logger)
	if err != nil {
		return err
	}
	defer func() { _ = state.Close() }()

	for _, tid := range state.sortedTenantIDs() {
		tenant, _ := state.tenant(tid)
		if err := migrateTenant(ctx, logger, tenant); err != nil {
			return fmt.Errorf("migrate tenant %s: %w", tenant.id, err)
		}
	}
	return nil
}

// migrateTenant walks tenant.storeRoot recursively, chunks each regular file
// it finds, and registers a manifest at the file's path relative to the
// store root. Server-managed files (the SQLite DBs and the chunk objects/
// dir) are skipped by name.
func migrateTenant(ctx context.Context, logger *slog.Logger, tenant *tenantState) error {
	logger.Info("migrate-to-chunks scanning",
		"tenant", tenant.id,
		"store_root", tenant.storeRoot,
	)

	if _, err := os.Stat(tenant.storeRoot); os.IsNotExist(err) {
		logger.Info("migrate-to-chunks: store_root does not exist, nothing to migrate",
			"tenant", tenant.id,
		)
		return nil
	}

	var (
		processed int
		skipped   int
		written   int
		newChunks int
	)

	walkErr := filepath.WalkDir(tenant.storeRoot, func(path string, d fs.DirEntry, walkErr error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if walkErr != nil {
			return walkErr
		}
		// Skip the chunk objects directory at storeRoot/objects — those bytes
		// are server-managed, not user content.
		rel, err := filepath.Rel(tenant.storeRoot, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		// Skip server-internal files at the store root.
		topSegment := strings.SplitN(filepath.ToSlash(rel), "/", 2)[0]
		if topSegment == "objects" {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.IsDir() && (topSegment == "routes.db" || topSegment == "leases.db" ||
			strings.HasSuffix(topSegment, ".db-wal") || strings.HasSuffix(topSegment, ".db-shm")) {
			return nil
		}

		virtualPath := "/" + filepath.ToSlash(rel)

		if d.IsDir() {
			// Seed dir_entries so that Put calls on children pass the
			// parent-existence check.
			parent, name := splitParentName(virtualPath)
			if name != "" {
				if err := tenant.manifests.RegisterDir(parent, name); err != nil {
					return fmt.Errorf("register_dir %s: %w", virtualPath, err)
				}
			}
			return nil
		}

		processed++
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		mode := uint32(info.Mode().Perm())
		mtime := info.ModTime().Unix()
		size := uint64(info.Size())

		chunks, err := ChunkFile(path)
		if err != nil {
			return fmt.Errorf("chunk %s: %w", path, err)
		}

		existing, err := tenant.manifests.Get(virtualPath)
		isNew := err == ErrManifestNotFound
		if err != nil && !isNew {
			return fmt.Errorf("get manifest %s: %w", virtualPath, err)
		}
		if !isNew && manifestMatches(existing, chunks, size) {
			skipped++
			return nil
		}

		for _, c := range chunks {
			stored, err := tenant.chunks.Put(c.Hash[:], c.Bytes)
			if err != nil {
				return fmt.Errorf("chunk_put %s offset %d: %w", virtualPath, c.Offset, err)
			}
			if stored {
				newChunks++
			}
		}

		mf := Manifest{
			Path:   virtualPath,
			Size:   size,
			Mode:   mode,
			Mtime:  mtime,
			Chunks: toManifestRefs(chunks),
		}
		var expected uint64
		if !isNew {
			expected = existing.Version
		}
		if _, err := tenant.manifests.Put(virtualPath, expected, mf, "", "", ""); err != nil {
			return fmt.Errorf("manifest_put %s: %w", virtualPath, err)
		}
		written++
		return nil
	})
	if walkErr != nil {
		return walkErr
	}

	logger.Info("migrate-to-chunks done",
		"tenant", tenant.id,
		"files_processed", processed,
		"manifests_written", written,
		"manifests_skipped_unchanged", skipped,
		"new_chunks", newChunks,
	)
	return nil
}

func manifestMatches(existing Manifest, chunks []Chunk, size uint64) bool {
	if existing.Size != size {
		return false
	}
	if len(existing.Chunks) != len(chunks) {
		return false
	}
	for i, c := range chunks {
		ec := existing.Chunks[i]
		if ec.Hash != c.Hash || ec.Offset != c.Offset || ec.Len != c.Len {
			return false
		}
	}
	return true
}

func toManifestRefs(chunks []Chunk) []ChunkRef {
	out := make([]ChunkRef, len(chunks))
	for i, c := range chunks {
		out[i] = ChunkRef{Hash: c.Hash, Offset: c.Offset, Len: c.Len}
	}
	return out
}
