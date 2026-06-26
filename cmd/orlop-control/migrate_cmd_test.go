package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestRunMigrateRequiresSubcommand(t *testing.T) {
	var buf bytes.Buffer
	err := runMigrate(context.Background(), &buf, nil)
	if err == nil {
		t.Fatal("expected error when no subcommand given")
	}
	if !strings.Contains(err.Error(), "usage") {
		t.Fatalf("error should include usage; got %q", err.Error())
	}
}

func TestRunMigrateUnknownSubcommand(t *testing.T) {
	err := runMigrate(context.Background(), &bytes.Buffer{}, []string{"sideways"})
	if err == nil || !strings.Contains(err.Error(), "unknown migrate subcommand") {
		t.Fatalf("expected unknown-subcommand error; got %v", err)
	}
}

func TestRunMigrateHelp(t *testing.T) {
	var buf bytes.Buffer
	if err := runMigrate(context.Background(), &buf, []string{"--help"}); err != nil {
		t.Fatalf("help should succeed: %v", err)
	}
	if !strings.Contains(buf.String(), "migrate up") {
		t.Fatalf("help text missing migrate up; got %q", buf.String())
	}
}

func TestRunMigrateUpRequiresDatabaseURL(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	err := runMigrateUp(context.Background(), &bytes.Buffer{}, nil)
	if err == nil || !strings.Contains(err.Error(), "DATABASE_URL") {
		t.Fatalf("expected DATABASE_URL error; got %v", err)
	}
}
