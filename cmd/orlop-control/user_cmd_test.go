package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestRunUserNoArgsReturnsUsage(t *testing.T) {
	err := runUser(context.Background(), &bytes.Buffer{}, nil)
	if err == nil || !strings.Contains(err.Error(), "user seed") {
		t.Fatalf("expected usage error, got %v", err)
	}
}

func TestRunUserHelp(t *testing.T) {
	var out bytes.Buffer
	if err := runUser(context.Background(), &out, []string{"help"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "user seed") {
		t.Fatalf("usage not printed: %q", out.String())
	}
}

func TestUserSeedRequiresFlags(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	cases := [][]string{
		{},
		{"--email", "a@b.test"},
		{"--tenant", "acme"},
	}
	for _, args := range cases {
		err := runUserSeed(context.Background(), &bytes.Buffer{}, args)
		if err == nil {
			t.Fatalf("expected error for args %v", args)
		}
	}
}

func TestUserSuspendRequiresEmail(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	if err := runUserSuspend(context.Background(), &bytes.Buffer{}, nil); err == nil {
		t.Fatal("expected --email required")
	}
}
