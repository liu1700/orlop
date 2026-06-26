package devauth

import (
	"crypto/rand"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNormalizeUserCode(t *testing.T) {
	cases := map[string]string{
		"orl-k7q9":    "ORL-K7Q9",
		"ORLK7Q9":     "ORL-K7Q9",
		" ORL K7 Q9 ": "ORL-K7Q9",
		"orl - k7 q9": "ORL-K7Q9",
		"":            "",
		"ABC":         "ABC", // not ORL-prefixed → leave alone, lookup will miss
		"ORL-":        "ORL-",
	}
	for in, want := range cases {
		if got := NormalizeUserCode(in); got != want {
			t.Errorf("NormalizeUserCode(%q) = %q, want %q", in, got, want)
		}
	}
}

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

func TestRandomUserCodeShape(t *testing.T) {
	s := &Service{rand: rand.Read}
	for i := 0; i < 100; i++ {
		uc, err := s.randomUserCode()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(uc, "ORL-") {
			t.Fatalf("missing ORL- prefix: %q", uc)
		}
		if len(uc) != 8 {
			t.Fatalf("len = %d, want 8: %q", len(uc), uc)
		}
		body := uc[4:]
		for _, r := range body {
			if !strings.ContainsRune(userCodeAlphabet, r) {
				t.Fatalf("char %q not in alphabet (uc=%q)", r, uc)
			}
		}
	}
}

func TestRandomEmailOTPShape(t *testing.T) {
	s := &Service{rand: rand.Read}
	for i := 0; i < 100; i++ {
		code, err := s.randomEmailOTP()
		if err != nil {
			t.Fatal(err)
		}
		if len(code) != 6 {
			t.Fatalf("len = %d, want 6: %q", len(code), code)
		}
		for _, r := range code {
			if r < '0' || r > '9' {
				t.Fatalf("non-numeric code %q", code)
			}
		}
	}
}

func TestNormalizeEmail(t *testing.T) {
	cases := map[string]string{
		"ALICE@example.test":   "alice@example.test",
		" alice@example.test ": "alice@example.test",
	}
	for in, want := range cases {
		got, err := NormalizeEmail(in)
		if err != nil {
			t.Fatalf("NormalizeEmail(%q) unexpected err: %v", in, err)
		}
		if got != want {
			t.Fatalf("NormalizeEmail(%q) = %q, want %q", in, got, want)
		}
	}
	for _, in := range []string{"", "not-email", "Alice <alice@example.test>"} {
		if got, err := NormalizeEmail(in); err == nil {
			t.Fatalf("NormalizeEmail(%q) = %q, want err", in, got)
		}
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

func TestRateLimiterAllowsThenDenies(t *testing.T) {
	rl := NewRateLimiter(3, 10*time.Second)
	for i := 0; i < 3; i++ {
		if !rl.Allow("ip-a") {
			t.Fatalf("call %d denied prematurely", i)
		}
	}
	if rl.Allow("ip-a") {
		t.Fatal("4th call should be rate-limited")
	}
	// distinct key has its own bucket
	if !rl.Allow("ip-b") {
		t.Fatal("distinct key denied")
	}
}

func TestRateLimiterRefillsOverTime(t *testing.T) {
	rl := NewRateLimiter(2, 1*time.Second)
	// freeze time at t0; consume both tokens.
	t0 := time.Unix(1_700_000_000, 0)
	rl.now = func() time.Time { return t0 }
	if !rl.Allow("k") || !rl.Allow("k") {
		t.Fatal("bucket should grant 2 tokens")
	}
	if rl.Allow("k") {
		t.Fatal("3rd should be denied")
	}
	// advance well past one full window; bucket refills to cap.
	rl.now = func() time.Time { return t0.Add(2 * time.Second) }
	if !rl.Allow("k") {
		t.Fatal("after window, bucket should refill")
	}
}

func TestRateLimiterConcurrent(t *testing.T) {
	rl := NewRateLimiter(1000, time.Minute)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				rl.Allow("shared")
			}
		}()
	}
	wg.Wait()
	// just verify no panic / data race; correctness of count is covered above.
}

func TestUserCodeAlphabetExcludesConfusables(t *testing.T) {
	for _, ch := range "01ILOU" {
		if strings.ContainsRune(userCodeAlphabet, ch) {
			t.Errorf("alphabet contains confusable %q", ch)
		}
	}
}
