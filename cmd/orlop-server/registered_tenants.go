package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
)

// registeredTenant is one entry in registered_tenants.json.
type registeredTenant struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	SizeBytes int64  `json:"size_bytes"`
	ProjectID uint32 `json:"project_id"`
	StoreRoot string `json:"store_root"`
	RoutesDB  string `json:"routes_db"`
}

type registeredTenantsFile struct {
	Tenants []registeredTenant `json:"tenants"`
}

// loadRegisteredTenants reads the JSON file at path and returns all tenant
// entries. Returns nil (not an error) when the file does not exist.
func loadRegisteredTenants(path string) ([]registeredTenant, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var f registeredTenantsFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return f.Tenants, nil
}

// mutateRegisteredTenants is the shared load → mutate → atomic-rename core.
// If mutate leaves the entries unchanged (full-struct equality), the file is
// not rewritten.
func mutateRegisteredTenants(path string, mutate func([]registeredTenant) []registeredTenant) error {
	existing, err := loadRegisteredTenants(path)
	if err != nil {
		return err
	}
	// Snapshot before mutating: mutators edit the slice in place, so comparing
	// against the live slice would always report "unchanged".
	before := slices.Clone(existing)
	next := mutate(existing)
	if slices.Equal(before, next) {
		return nil
	}

	data, err := json.MarshalIndent(registeredTenantsFile{Tenants: next}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o640); err != nil {
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// persistRegisteredTenant appends rt to registered_tenants.json under regFileMu.
// The mutex serializes the shared load→mutate→atomic-rename file: with tenant
// registration no longer under mu, two DIFFERENT tenants can persist
// concurrently, and without this guard one write would clobber the other (they
// share a fixed .tmp name and each rewrites the whole file). See serverState.regFileMu.
func (s *serverState) persistRegisteredTenant(rt registeredTenant) error {
	s.regFileMu.Lock()
	defer s.regFileMu.Unlock()
	return appendRegisteredTenant(s.adminCfg.RegisteredTenantsPath, rt)
}

// dropRegisteredTenant removes tenantID from registered_tenants.json under
// regFileMu (see persistRegisteredTenant).
func (s *serverState) dropRegisteredTenant(tenantID string) error {
	s.regFileMu.Lock()
	defer s.regFileMu.Unlock()
	return removeRegisteredTenant(s.adminCfg.RegisteredTenantsPath, tenantID)
}

// appendRegisteredTenant inserts rt or, if an entry with the same ID exists,
// replaces it. Idempotent.
func appendRegisteredTenant(path string, rt registeredTenant) error {
	return mutateRegisteredTenants(path, func(existing []registeredTenant) []registeredTenant {
		for i, e := range existing {
			if e.ID == rt.ID {
				existing[i] = rt
				return existing
			}
		}
		return append(existing, rt)
	})
}

// removeRegisteredTenant drops the entry for tenantID. No-op when path is
// empty or no matching entry exists.
func removeRegisteredTenant(path, tenantID string) error {
	if path == "" {
		return nil
	}
	return mutateRegisteredTenants(path, func(existing []registeredTenant) []registeredTenant {
		out := existing[:0]
		for _, e := range existing {
			if e.ID == tenantID {
				continue
			}
			out = append(out, e)
		}
		return out
	})
}
