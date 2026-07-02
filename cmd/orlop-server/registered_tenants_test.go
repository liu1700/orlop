package main

import (
	"path/filepath"
	"testing"
)

// A re-registration that changes a field other than ID (a moved store root, a
// refreshed ProjectID, ...) must rewrite the JSON file. Regression: the old
// ID-only comparison ran against the in-place mutated slice, so the write was
// skipped and restarts resurrected the stale entry.
func TestAppendRegisteredTenantPersistsChangedFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registered_tenants.json")

	first := registeredTenant{
		ID: "t1", Name: "one", SizeBytes: 100, ProjectID: 7,
		StoreRoot: "/old/store", RoutesDB: "/old/routes.db",
	}
	if err := appendRegisteredTenant(path, first); err != nil {
		t.Fatalf("append: %v", err)
	}

	changed := first
	changed.StoreRoot = "/new/store"
	changed.RoutesDB = "/new/routes.db"
	changed.ProjectID = 8
	if err := appendRegisteredTenant(path, changed); err != nil {
		t.Fatalf("re-append: %v", err)
	}

	got, err := loadRegisteredTenants(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if got[0] != changed {
		t.Errorf("persisted entry = %+v, want %+v", got[0], changed)
	}
}
