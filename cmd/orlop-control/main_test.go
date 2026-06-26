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

	cfg := loadConfig()

	if cfg.Addr != ":9090" {
		t.Fatalf("addr = %q, want :9090", cfg.Addr)
	}
	if cfg.DatabaseURL != "postgres://example" {
		t.Fatalf("database url = %q, want postgres://example", cfg.DatabaseURL)
	}
}

func TestLoadConfigInitialGrant(t *testing.T) {
	// Default when unset.
	if cfg := loadConfig(); cfg.InitialGrantBytes != agentDiskInitialGrantBytes {
		t.Errorf("default initial grant = %d, want %d", cfg.InitialGrantBytes, int64(agentDiskInitialGrantBytes))
	}
	// Override parses.
	t.Setenv("ORLOP_INITIAL_GRANT_BYTES", "2147483648") // 2 GiB
	if cfg := loadConfig(); cfg.InitialGrantBytes != 2<<30 {
		t.Errorf("initial grant = %d, want %d", cfg.InitialGrantBytes, int64(2<<30))
	}
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

	cfg := loadConfig()

	if cfg.Addr != ":8080" {
		t.Fatalf("addr = %q, want :8080", cfg.Addr)
	}
}

func TestShutdownTimeoutIsBounded(t *testing.T) {
	if shutdownTimeout > 30*time.Second {
		t.Fatalf("shutdown timeout = %s, want <= 30s", shutdownTimeout)
	}
}

func TestDeviceFlowRoutesNotMountedWithoutDB(t *testing.T) {
	server := httptest.NewServer(newRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), runtimeDeps{}, config{}))
	defer server.Close()

	resp, err := http.Post(server.URL+"/auth/device/code", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 404/405 without DB, got %d", resp.StatusCode)
	}
}
