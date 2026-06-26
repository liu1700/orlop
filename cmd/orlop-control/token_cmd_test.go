package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestRunTokenNoArgsReturnsUsage(t *testing.T) {
	err := runToken(context.Background(), &bytes.Buffer{}, nil)
	if err == nil || !strings.Contains(err.Error(), "token issue") {
		t.Fatalf("expected usage error, got %v", err)
	}
}

func TestRunTokenHelp(t *testing.T) {
	var out bytes.Buffer
	if err := runToken(context.Background(), &out, []string{"help"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "token issue") {
		t.Fatalf("usage not printed: %q", out.String())
	}
}

func TestRunTokenUnknownSubcommand(t *testing.T) {
	err := runToken(context.Background(), &bytes.Buffer{}, []string{"bogus"})
	if err == nil || !strings.Contains(err.Error(), "unknown token subcommand") {
		t.Fatalf("expected unknown-subcommand error, got %v", err)
	}
}

func TestTokenIssueRequiresAgent(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://example")
	if err := runTokenIssue(context.Background(), &bytes.Buffer{}, nil); err == nil ||
		!strings.Contains(err.Error(), "--agent is required") {
		t.Fatalf("expected --agent required, got %v", err)
	}
}

func TestTokenIssueRequiresDatabaseURL(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	err := runTokenIssue(context.Background(), &bytes.Buffer{}, []string{"--agent", "demo"})
	if err == nil || !strings.Contains(err.Error(), "DATABASE_URL") {
		t.Fatalf("expected DATABASE_URL required, got %v", err)
	}
}

func TestTokenIssueRejectsNonUUIDOwner(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://example")
	err := runTokenIssue(context.Background(), &bytes.Buffer{},
		[]string{"--agent", "demo", "--owner", "not-a-uuid"})
	if err == nil || !strings.Contains(err.Error(), "uuid") {
		t.Fatalf("expected uuid validation error, got %v", err)
	}
}
