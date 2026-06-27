package main

import (
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCertRevocationRegistry(t *testing.T) {
	now := time.Date(2026, 6, 26, 12, 0, 0, 0, time.UTC)
	r := newCertRevocationRegistry()
	r.now = func() time.Time { return now }

	future := now.Add(time.Hour)
	r.Add("aabb", future)

	// Case-insensitive / trimmed match against the canonical uppercase form.
	if !r.IsRevoked("AABB") {
		t.Fatal("AABB should be revoked")
	}
	if !r.IsRevoked("  aabb ") {
		t.Fatal("whitespace/case variants should still match")
	}
	if r.IsRevoked("ccdd") {
		t.Fatal("unknown serial must not be revoked")
	}
	if r.IsRevoked("") {
		t.Fatal("empty serial must not be revoked")
	}

	// An entry past the cert's own expiry reports not-revoked.
	r.Add("eeff", now.Add(-time.Minute))
	if r.IsRevoked("EEFF") {
		t.Fatal("expired entry must report not-revoked")
	}
}

func TestCertRevocationRegistryPrune(t *testing.T) {
	now := time.Date(2026, 6, 26, 12, 0, 0, 0, time.UTC)
	r := newCertRevocationRegistry()
	r.now = func() time.Time { return now }

	r.Add("live", now.Add(time.Hour))
	if got := r.Count(); got != 1 {
		t.Fatalf("Count after first Add = %d, want 1", got)
	}
	// An entry that expires while in the map is reclaimed by Prune (and reads as
	// not-revoked even before that).
	r.Add("dead", now.Add(-time.Hour))
	if r.IsRevoked("DEAD") {
		t.Fatal("expired entry must read as not-revoked")
	}
	r.Prune()
	if got := r.Count(); got != 1 {
		t.Fatalf("Count after Prune = %d, want 1", got)
	}
	if !r.IsRevoked("LIVE") {
		t.Fatal("live entry must survive prune")
	}
}

func TestPushCertRevocationsHandler(t *testing.T) {
	s := &serverState{certRevocations: newCertRevocationRegistry()}

	body := `{"revocations":[
		{"serial":"AABB","expires_at":"2030-01-01T00:00:00Z"},
		{"serial":"ccdd","expires_at":"2030-01-01T00:00:00Z"}
	]}`
	req := httptest.NewRequest(http.MethodPut, "/control/cert-revocations", strings.NewReader(body))
	w := httptest.NewRecorder()
	s.pushCertRevocations(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	if !s.certRevocations.IsRevoked("AABB") || !s.certRevocations.IsRevoked("CCDD") {
		t.Fatal("pushed serials must be registered (case-normalized)")
	}

	// Malformed body → 400.
	bad := httptest.NewRequest(http.MethodPut, "/control/cert-revocations", strings.NewReader("{"))
	bw := httptest.NewRecorder()
	s.pushCertRevocations(bw, bad)
	if bw.Code != http.StatusBadRequest {
		t.Fatalf("malformed body status = %d, want 400", bw.Code)
	}

	// Registry unconfigured → 501.
	none := &serverState{}
	nw := httptest.NewRecorder()
	none.pushCertRevocations(nw, httptest.NewRequest(http.MethodPut, "/control/cert-revocations", strings.NewReader(`{"revocations":[]}`)))
	if nw.Code != http.StatusNotImplemented {
		t.Fatalf("nil registry status = %d, want 501", nw.Code)
	}
}

func TestFormatSerialHex(t *testing.T) {
	if got := formatSerialHex(big.NewInt(0xABCD)); got != "ABCD" {
		t.Fatalf("formatSerialHex = %q, want ABCD", got)
	}
	if got := formatSerialHex(nil); got != "" {
		t.Fatalf("formatSerialHex(nil) = %q, want empty", got)
	}
}
