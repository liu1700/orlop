package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestRunServerNoArgsReturnsUsage(t *testing.T) {
	err := runServer(context.Background(), &bytes.Buffer{}, nil)
	if err == nil || !strings.Contains(err.Error(), "server register") {
		t.Fatalf("expected usage error, got %v", err)
	}
}

func TestRunServerHelp(t *testing.T) {
	var out bytes.Buffer
	if err := runServer(context.Background(), &out, []string{"help"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "server register") {
		t.Fatalf("usage not printed: %q", out.String())
	}
}

func TestRunServerUnknownSubcommand(t *testing.T) {
	err := runServer(context.Background(), &bytes.Buffer{}, []string{"bogus"})
	if err == nil || !strings.Contains(err.Error(), "unknown server subcommand") {
		t.Fatalf("expected unknown-subcommand error, got %v", err)
	}
}

func TestServerRegisterRequiresDatabaseURL(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	err := runServerRegister(context.Background(), &bytes.Buffer{}, nil)
	if err == nil || !strings.Contains(err.Error(), "DATABASE_URL") {
		t.Fatalf("expected DATABASE_URL required, got %v", err)
	}
}

func TestServerRegisterRejectsEmptyAddr(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://example")
	err := runServerRegister(context.Background(), &bytes.Buffer{}, []string{"--data-addr", ""})
	if err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("expected addr-required error, got %v", err)
	}
}
