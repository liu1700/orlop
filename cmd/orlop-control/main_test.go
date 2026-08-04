package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/allocations"
)

func TestHealthz(t *testing.T) {
	server := httptest.NewServer(newRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), runtimeDeps{}, config{}))
	defer server.Close()

	resp, err := http.Get(server.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Fatalf("content type = %q, want application/json", got)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.TrimSpace(string(body)), `{"status":"ok"}`; got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
}

func TestLoadConfigReadsEnv(t *testing.T) {
	t.Setenv("PORT", "9090")
	t.Setenv("DATABASE_URL", "postgres://example")

	cfg := mustLoadConfig(t)

	if cfg.Addr != ":9090" {
		t.Fatalf("addr = %q, want :9090", cfg.Addr)
	}
	if cfg.DatabaseURL != "postgres://example" {
		t.Fatalf("database url = %q, want postgres://example", cfg.DatabaseURL)
	}
}

func TestLoadConfigInitialGrant(t *testing.T) {
	// Default when unset.
	if cfg := mustLoadConfig(t); cfg.InitialGrantBytes != agentDiskInitialGrantBytes {
		t.Errorf("default initial grant = %d, want %d", cfg.InitialGrantBytes, int64(agentDiskInitialGrantBytes))
	}
	// Override parses.
	t.Setenv("ORLOP_INITIAL_GRANT_BYTES", "2147483648") // 2 GiB
	if cfg := mustLoadConfig(t); cfg.InitialGrantBytes != 2<<30 {
		t.Errorf("initial grant = %d, want %d", cfg.InitialGrantBytes, int64(2<<30))
	}
}

func TestLoadConfigMountLeaseTTL(t *testing.T) {
	if cfg := mustLoadConfig(t); cfg.MountLeaseTTL != allocations.DefaultMountLeaseTTL {
		t.Fatalf("default mount lease TTL = %s, want %s", cfg.MountLeaseTTL, allocations.DefaultMountLeaseTTL)
	}

	t.Setenv("ORLOP_MOUNT_LEASE_TTL", "20s")
	cfg := mustLoadConfig(t)
	if cfg.MountLeaseTTL != 20*time.Second {
		t.Fatalf("env mount lease TTL = %s, want 20s", cfg.MountLeaseTTL)
	}

	cfg, err := loadConfig("--mount-lease-ttl=45s")
	if err != nil {
		t.Fatalf("flag override: %v", err)
	}
	if cfg.MountLeaseTTL != 45*time.Second {
		t.Fatalf("flag mount lease TTL = %s, want 45s", cfg.MountLeaseTTL)
	}
}

func TestLoadConfigPurgeSweepInterval(t *testing.T) {
	if cfg := mustLoadConfig(t); cfg.PurgeSweepInterval != defaultPurgeSweepInterval {
		t.Fatalf("default purge sweep interval = %s, want %s", cfg.PurgeSweepInterval, defaultPurgeSweepInterval)
	}

	t.Setenv("ORLOP_PURGE_SWEEP_INTERVAL", "2m")
	if cfg := mustLoadConfig(t); cfg.PurgeSweepInterval != 2*time.Minute {
		t.Fatalf("purge sweep interval = %s, want 2m", cfg.PurgeSweepInterval)
	}

	for _, disabled := range []string{"0", "0s"} {
		t.Run("disabled_"+disabled, func(t *testing.T) {
			t.Setenv("ORLOP_PURGE_SWEEP_INTERVAL", disabled)
			if cfg := mustLoadConfig(t); cfg.PurgeSweepInterval != 0 {
				t.Fatalf("disabled interval = %s, want 0", cfg.PurgeSweepInterval)
			}
		})
	}
}

func TestLoadConfigRejectsInvalidPurgeSweepInterval(t *testing.T) {
	for _, value := range []string{"-1s", "not-a-duration"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("ORLOP_PURGE_SWEEP_INTERVAL", value)
			if _, err := loadConfig(); err == nil {
				t.Fatalf("ORLOP_PURGE_SWEEP_INTERVAL=%q should fail configuration", value)
			}
		})
	}
}

func TestLoadConfigRejectsUnsafeMountLeaseTTL(t *testing.T) {
	for _, value := range []string{"0s", "3s", "not-a-duration"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("ORLOP_MOUNT_LEASE_TTL", value)
			if _, err := loadConfig(); err == nil {
				t.Fatalf("ORLOP_MOUNT_LEASE_TTL=%q should fail configuration", value)
			}
		})
	}
}

func TestLoadConfigMountPrefix(t *testing.T) {
	t.Setenv("ORLOP_MOUNT_PREFIX", "")
	if cfg := mustLoadConfig(t); cfg.MountPrefix != defaultMountPrefix {
		t.Errorf("default mount prefix = %q; want %q", cfg.MountPrefix, defaultMountPrefix)
	}

	t.Setenv("ORLOP_MOUNT_PREFIX", "/mnt/plori/")
	if cfg := mustLoadConfig(t); cfg.MountPrefix != "/mnt/plori" {
		t.Errorf("mount prefix = %q; want /mnt/plori", cfg.MountPrefix)
	}

	t.Setenv("ORLOP_MOUNT_PREFIX", "relative/path")
	if _, err := loadConfig(); err == nil {
		t.Fatal("relative ORLOP_MOUNT_PREFIX should fail configuration")
	}
}

// TestParseBoolEnvRejectsTypos covers the security-review fix: a set-but-
// unrecognized boolean is an error (fail boot), not a silent fallback that
// would leave a security toggle in its permissive default.
func TestParseBoolEnvRejectsTypos(t *testing.T) {
	const key = "ORLOP_TEST_BOOL"

	t.Setenv(key, "")
	if v, err := parseBoolEnv(key, true); err != nil || v != true {
		t.Fatalf("unset: got (%v, %v), want (true, nil)", v, err)
	}
	for _, s := range []string{"false", "0", "no", "OFF"} {
		t.Setenv(key, s)
		if v, err := parseBoolEnv(key, true); err != nil || v != false {
			t.Fatalf("%q: got (%v, %v), want (false, nil)", s, v, err)
		}
	}
	for _, s := range []string{"fals", "tru", "nope", "2"} {
		t.Setenv(key, s)
		if _, err := parseBoolEnv(key, true); err == nil {
			t.Fatalf("%q: expected an error, got nil", s)
		}
	}
}

// mustLoadConfig loads config and fails the test on a config error.
func mustLoadConfig(t *testing.T) config {
	t.Helper()
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	return cfg
}

func TestRunShutsDownWhenContextIsCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := run(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), config{Addr: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDefaultPort(t *testing.T) {
	t.Setenv("PORT", "")

	cfg := mustLoadConfig(t)

	if cfg.Addr != ":8080" {
		t.Fatalf("addr = %q, want :8080", cfg.Addr)
	}
}

func TestShutdownTimeoutIsBounded(t *testing.T) {
	if shutdownTimeout > 30*time.Second {
		t.Fatalf("shutdown timeout = %s, want <= 30s", shutdownTimeout)
	}
}
