package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
// Returns mutator's `next` slice; if it returns the same slice (by length AND
// content equality at the ID level) the file is not rewritten.
func mutateRegisteredTenants(path string, mutate func([]registeredTenant) []registeredTenant) error {
	existing, err := loadRegisteredTenants(path)
	if err != nil {
		return err
	}
	next := mutate(existing)
	if registeredTenantsEqual(existing, next) {
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

func registeredTenantsEqual(a, b []registeredTenant) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].ID != b[i].ID {
			return false
		}
	}
	return true
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
