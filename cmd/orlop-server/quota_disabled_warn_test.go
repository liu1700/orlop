package main

import (
	"bytes"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
)

func newStateWithQuotaEnforce(t *testing.T, enforce bool) string {
	t.Helper()
	root := t.TempDir()
	tenantsRoot := filepath.Join(root, "tenants")
	mustMkdirAll(t, tenantsRoot)
	storeRoot := filepath.Join(root, "store")
	mustMkdirAll(t, storeRoot)
	dbPath := filepath.Join(root, "routes.db")
	createSchema(t, dbPath)

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	cfg := Config{
		AuditLog:              filepath.Join(root, "audit.log"),
		StoreRoot:             storeRoot,
		RoutesDB:              dbPath,
		TenantID:              testTenant,
		TrustDomain:           "orlop.example",
		Tenants:               []TenantConfig{{ID: testTenant, Name: testTenant, StoreRoot: storeRoot, RoutesDB: dbPath}},
		TenantsRoot:           tenantsRoot,
		RegisteredTenantsPath: filepath.Join(root, "registered_tenants.json"),
		QuotaEnforce:          enforce,
	}
	state, err := newServerState(cfg, contextIdentifier{}, logger)
	if err != nil {
		t.Fatalf("newServerState: %v", err)
	}
	t.Cleanup(func() { _ = state.Close() })
	return buf.String()
}

func TestQuotaDisabledEmitsWarning(t *testing.T) {
	logs := newStateWithQuotaEnforce(t, false)
	if !strings.Contains(logs, "quota enforcement is OFF") {
		t.Fatalf("expected a quota-disabled warning, got: %q", logs)
	}
}

func TestQuotaEnabledNoWarning(t *testing.T) {
	logs := newStateWithQuotaEnforce(t, true)
	if strings.Contains(logs, "quota enforcement is OFF") {
		t.Fatalf("did not expect a quota-disabled warning, got: %q", logs)
	}
}
