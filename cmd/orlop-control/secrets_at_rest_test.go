package main

import (
	"io"
	"log/slog"
	"strings"
	"testing"
)

func TestCheckCASecretsAtRest(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	cases := []struct {
		name      string
		cfg       config
		wantError bool
	}{
		{
			name:      "postgres without enc key fails closed",
			cfg:       config{SecretsBackend: "postgres"},
			wantError: true,
		},
		{
			name:      "postgres with enc key is fine",
			cfg:       config{SecretsBackend: "postgres", SecretsEncKey: "deadbeef"},
			wantError: false,
		},
		{
			name:      "postgres plaintext with explicit opt-in is allowed",
			cfg:       config{SecretsBackend: "postgres", AllowPlaintextSecrets: true},
			wantError: false,
		},
		{
			name:      "filesystem backend is not gated",
			cfg:       config{SecretsBackend: "", SecretsDir: "/tmp/secrets"},
			wantError: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkCASecretsAtRest(tc.cfg, logger)
			if tc.wantError && err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !tc.wantError && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if tc.wantError && !strings.Contains(err.Error(), "ORLOP_SECRETS_ENC_KEY") {
				t.Fatalf("error should name the fix env var, got %q", err)
			}
		})
	}
}
