package tokens_test

import (
	"strings"
	"testing"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/tokens"
)

func TestGenerate_FormatAndUniqueness(t *testing.T) {
	tok1, err := tokens.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	tok2, err := tokens.Generate()
	if err != nil {
		t.Fatalf("Generate 2: %v", err)
	}

	for _, tok := range []tokens.RawToken{tok1, tok2} {
		if !strings.HasPrefix(tok.Raw, "orlop_") {
			t.Errorf("token %q does not start with orlop_", tok.Raw)
		}
		// 24 random bytes base32-no-padding = 39 chars; plus "orlop_" = 45 total.
		if got, want := len(tok.Raw), 45; got != want {
			t.Errorf("token len = %d; want %d (got %q)", got, want, tok.Raw)
		}
		if len(tok.Hash) != 64 {
			t.Errorf("hash len = %d; want 64 hex chars", len(tok.Hash))
		}
		if got, want := len(tok.Prefix), 12; got != want {
			t.Errorf("prefix len = %d; want %d", got, want)
		}
		if !strings.HasPrefix(tok.Raw, tok.Prefix) {
			t.Errorf("prefix %q is not a prefix of raw %q", tok.Prefix, tok.Raw)
		}
	}
	if tok1.Raw == tok2.Raw {
		t.Errorf("two generated tokens collided: %q", tok1.Raw)
	}
}

func TestHashIsDeterministic(t *testing.T) {
	a := tokens.Hash("orlop_abcdef12345")
	b := tokens.Hash("orlop_abcdef12345")
	if a != b {
		t.Errorf("hash is not deterministic: %s vs %s", a, b)
	}
	if len(a) != 64 {
		t.Errorf("hash len = %d; want 64", len(a))
	}
	if a == tokens.Hash("orlop_DIFFERENT___") {
		t.Errorf("different inputs produced equal hashes")
	}
}
