package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"path"
	"strings"
	"time"
)

type seedOpts struct {
	tenantID    string
	virtualPath string
	data        io.Reader
}

// runSeed reads bytes from opts.data, chunks them via FastCDC, and writes the
// chunks + manifest into the named tenant's storage. Idempotent on the chunk
// store (content-addressed) and CAS-guarded on the manifest. Modeled on
// migrate.migrateTenant — same primitives, single-file scope.
func runSeed(_ context.Context, logger *slog.Logger, cfg Config, opts seedOpts) error {
	if opts.tenantID == "" {
		return fmt.Errorf("--seed-tenant is required")
	}
	if opts.virtualPath == "" {
		return fmt.Errorf("--seed-virtual-path is required")
	}
	if !strings.HasPrefix(opts.virtualPath, "/") {
		return fmt.Errorf("--seed-virtual-path must be absolute (start with /), got %q", opts.virtualPath)
	}

	state, err := newServerState(cfg, certIdentifier{trustDomain: cfg.TrustDomain}, logger)
	if err != nil {
		return err
	}
	defer func() { _ = state.Close() }()

	tenant, ok := state.tenant(opts.tenantID)
	if !ok {
		return fmt.Errorf("tenant %q is not configured on this server (must be statically configured or dynamically registered first)", opts.tenantID)
	}

	data, err := io.ReadAll(opts.data)
	if err != nil {
		return fmt.Errorf("read seed data: %w", err)
	}

	chunks := chunkBytes(data)

	for _, c := range chunks {
		stored, err := tenant.chunks.Put(c.Hash[:], c.Bytes)
		if err != nil {
			return fmt.Errorf("chunk_put offset %d: %w", c.Offset, err)
		}
		if stored {
			logger.Debug("seed chunk stored", "offset", c.Offset, "len", c.Len)
		}
	}

	if err := registerParents(tenant, opts.virtualPath); err != nil {
		return err
	}

	existing, err := tenant.manifests.Get(opts.virtualPath)
	var expected uint64
	switch {
	case err == nil:
		expected = existing.Version
	case err == ErrManifestNotFound:
		expected = 0
	default:
		return fmt.Errorf("manifest get %s: %w", opts.virtualPath, err)
	}

	mf := Manifest{
		Path:   opts.virtualPath,
		Size:   uint64(len(data)),
		Mode:   0o644,
		Mtime:  time.Now().Unix(),
		Chunks: toManifestRefs(chunks),
	}
	if _, err := tenant.manifests.Put(opts.virtualPath, expected, mf, "", "", ""); err != nil {
		return fmt.Errorf("manifest_put %s: %w", opts.virtualPath, err)
	}

	logger.Info("seed wrote manifest",
		"tenant", opts.tenantID,
		"virtual_path", opts.virtualPath,
		"size", len(data),
		"chunks", len(chunks),
	)
	return nil
}

// registerParents seeds dir_entries for every ancestor of virtualPath so the
// manifest_put parent-existence check passes. Mirrors the per-dir RegisterDir
// loop in migrate.migrateTenant's WalkDir.
func registerParents(tenant *tenantState, virtualPath string) error {
	parts := strings.Split(strings.Trim(path.Dir(virtualPath), "/"), "/")
	cur := ""
	for _, p := range parts {
		if p == "" {
			continue
		}
		parent := "/"
		if cur != "" {
			parent = cur
		}
		if err := tenant.manifests.RegisterDir(parent, p); err != nil {
			return fmt.Errorf("register_dir %s/%s: %w", parent, p, err)
		}
		if cur == "" {
			cur = "/" + p
		} else {
			cur = cur + "/" + p
		}
	}
	return nil
}
