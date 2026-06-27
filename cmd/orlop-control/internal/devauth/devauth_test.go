package devauth

import (
	"crypto/rand"
	"testing"
)

func TestHashCodeStable(t *testing.T) {
	a := hashCode("ORL-K7Q9")
	b := hashCode("ORL-K7Q9")
	if a != b {
		t.Fatal("hashCode not deterministic")
	}
	if len(a) != 64 {
		t.Fatalf("hash len = %d, want 64", len(a))
	}
	if hashCode("ORL-K7Q9") == hashCode("ORL-K7Q8") {
		t.Fatal("distinct inputs hashed to same value")
	}
}

func TestRandomTokenShape(t *testing.T) {
	s := &Service{rand: rand.Read}
	tok, err := s.randomToken()
	if err != nil {
		t.Fatal(err)
	}
	// 16 bytes → 22 chars in raw url base64.
	if len(tok) != 22 {
		t.Fatalf("token length = %d, want 22", len(tok))
	}
	// Two calls must differ — 128 bits of entropy means collision is
	// astronomically unlikely.
	tok2, err := s.randomToken()
	if err != nil {
		t.Fatal(err)
	}
	if tok == tok2 {
		t.Fatal("two random tokens collided")
	}
}

func TestBearerToken(t *testing.T) {
	cases := map[string]string{
		"Bearer abc123":   "abc123",
		"bearer abc123":   "abc123",
		"BEARER  abc123 ": "abc123",
		"abc123":          "",
		"":                "",
		"Bearer":          "",
	}
	for in, want := range cases {
		if got := bearerToken(in); got != want {
			t.Errorf("bearerToken(%q) = %q, want %q", in, got, want)
		}
	}
}
