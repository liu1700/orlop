// Package usage computes on-disk byte totals for a tenant's storage tree.
//
// MVP implementation walks the directory and sums regular-file sizes. This
// is correct everywhere (including dev VMs without ext4 prjquota) but scales
// O(files). For production volumes a quotactl Q_GETPQUOTA fast path is the
// natural follow-up — the project ID is already tracked in
// internal/quota.Manager.
package usage

import (
	"errors"
	"io/fs"
	"path/filepath"
)

// DirSize returns the total on-disk size, in bytes, of all regular files
// under root (recursively). Symlinks are not followed; their own size is
// counted (matches `du -sb` behavior).
//
// Returns 0, nil when root does not exist — a tenant whose storeRoot has
// not been written to yet has zero usage.
func DirSize(root string) (int64, error) {
	var total int64
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) && path == root {
				return filepath.SkipDir
			}
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		total += info.Size()
		return nil
	})
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	return total, err
}
