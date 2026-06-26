package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "server.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// Singular `tenant:` block with nested store/routes must be honored.
// Regression: prior to the fix the parser dropped tenant.Store / tenant.Routes
// and synthesized rawTenants with raw.Store / raw.Routes (top-level), so a
// config that only set the nested forms failed with "store.root is required".
func TestSingularTenantHonorsNestedStoreAndRoutes(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, `
tenant:
  id: tenant-a
  name: Tenant A
  store:
    type: local
    root: `+dir+`/entities
  routes:
    type: sqlite
    path: `+dir+`/routes.db
policy:
  readonly: true
server:
  ops_bind: 127.0.0.1:0
tls:
  cert_file: `+dir+`/cert.pem
  key_file:  `+dir+`/key.pem
  client_ca_file: `+dir+`/client-ca.pem
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if got, want := cfg.TenantID, "tenant-a"; got != want {
		t.Errorf("TenantID = %q, want %q", got, want)
	}
	if got := cfg.StoreRoot; got != dir+"/entities" {
		t.Errorf("StoreRoot = %q, want %q", got, dir+"/entities")
	}
	if got := cfg.RoutesDB; got != dir+"/routes.db" {
		t.Errorf("RoutesDB = %q, want %q", got, dir+"/routes.db")
	}
}

// Top-level store/routes must still work (the form the deploy templates use).
func TestSingularTenantUsesTopLevelStoreAndRoutes(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, `
tenant:
  id: tenant-a
  name: Tenant A
store:
  type: local
  root: `+dir+`/entities
routes:
  type: sqlite
  path: `+dir+`/routes.db
policy:
  readonly: true
server:
  ops_bind: 127.0.0.1:0
tls:
  cert_file: `+dir+`/cert.pem
  key_file:  `+dir+`/key.pem
  client_ca_file: `+dir+`/client-ca.pem
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if got := cfg.StoreRoot; got != dir+"/entities" {
		t.Errorf("StoreRoot = %q", got)
	}
	if got := cfg.RoutesDB; got != dir+"/routes.db" {
		t.Errorf("RoutesDB = %q", got)
	}
}

func TestGCConfigDefaults(t *testing.T) {
	var c GCConfig
	eff := c.Effective()
	if eff.Interval != 24*time.Hour {
		t.Errorf("default interval = %v, want 24h", eff.Interval)
	}
	if eff.RetentionWindow != 7*24*time.Hour {
		t.Errorf("default retention = %v, want 168h", eff.RetentionWindow)
	}
	if eff.BatchSize != 500 {
		t.Errorf("default batch = %d, want 500", eff.BatchSize)
	}
	if eff.TenantBudget != 2*time.Minute {
		t.Errorf("default budget = %v, want 2m", eff.TenantBudget)
	}
	if eff.DryRun {
		t.Error("default dry_run should be false")
	}
}

func TestGCConfigYAMLOverride(t *testing.T) {
	yamlBytes := []byte(`
tenant: { id: t1, name: t1, store: { type: local, root: /tmp/t1 }, routes: { type: sqlite, path: /tmp/t1/routes.db } }
gc:
  interval: 1h
  retention_window: 6h
  batch_size: 100
  tenant_budget: 30s
  dry_run: true
`)
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, yamlBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	eff := cfg.GC.Effective()
	if eff.Interval != time.Hour {
		t.Errorf("interval = %v, want 1h", eff.Interval)
	}
	if eff.RetentionWindow != 6*time.Hour {
		t.Errorf("retention = %v, want 6h", eff.RetentionWindow)
	}
	if eff.BatchSize != 100 {
		t.Errorf("batch = %d, want 100", eff.BatchSize)
	}
	if eff.TenantBudget != 30*time.Second {
		t.Errorf("budget = %v, want 30s", eff.TenantBudget)
	}
	if !eff.DryRun {
		t.Error("dry_run not picked up")
	}
}

func TestGCConfigDisabled(t *testing.T) {
	var c GCConfig
	c.Interval = "0"
	if c.Effective().Interval != 0 {
		t.Error("interval=0 should disable GC")
	}
}

// When both nested and top-level are set, nested wins.
func TestQuotaBurstMarginConfig(t *testing.T) {
	base := "tenant: { id: t1, name: t1, store: { type: local, root: /tmp/t1 }, routes: { type: sqlite, path: /tmp/t1/routes.db } }\n"
	load := func(body string) Config {
		t.Helper()
		p := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := LoadConfig(p)
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}

	if got := load(base).QuotaBurstMarginBytes; got != defaultQuotaBurstMarginBytes {
		t.Errorf("default margin = %d, want %d", got, int64(defaultQuotaBurstMarginBytes))
	}
	if got := load(base + "quota:\n  burst_margin_bytes: 1048576\n").QuotaBurstMarginBytes; got != 1<<20 {
		t.Errorf("override margin = %d, want %d", got, int64(1<<20))
	}
	if got := load(base + "quota:\n  burst_margin_bytes: 0\n").QuotaBurstMarginBytes; got != 0 {
		t.Errorf("zero margin = %d, want 0 (disabled)", got)
	}
}

func TestSingularTenantNestedOverridesTopLevel(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, `
tenant:
  id: tenant-a
  store:
    type: local
    root: `+dir+`/preferred
  routes:
    type: sqlite
    path: `+dir+`/preferred.db
store:
  type: local
  root: `+dir+`/fallback
routes:
  type: sqlite
  path: `+dir+`/fallback.db
policy:
  readonly: true
server:
  ops_bind: 127.0.0.1:0
tls:
  cert_file: `+dir+`/cert.pem
  key_file:  `+dir+`/key.pem
  client_ca_file: `+dir+`/client-ca.pem
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if got := cfg.StoreRoot; got != dir+"/preferred" {
		t.Errorf("StoreRoot = %q (nested should win)", got)
	}
	if got := cfg.RoutesDB; got != dir+"/preferred.db" {
		t.Errorf("RoutesDB = %q (nested should win)", got)
	}
}
