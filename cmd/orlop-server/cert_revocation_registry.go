package main

import (
	"encoding/hex"
	"math/big"
	"strings"
	"sync"
	"time"
)

// certRevocationRegistry is the in-memory serial deny-list checked at the start
// of every data-plane session (issue #5). orlop-control pushes revoked agent
// leaf serials here — on lease release and on a periodic reconcile — so a
// leaked or compromised cert can be killed mid-TTL instead of staying valid for
// its full hour. The check is the data-plane "kill switch" the zero-trust claim
// otherwise lacked.
//
// Serials are uppercase hex (matching the control plane's formatSerial and the
// agent_enrollments.cert_serial column, i.e. big.Int.Bytes() hex-encoded).
//
// State lives only in memory. The control plane re-pushes the active set
// (idempotent merge) every reconcile interval and on each revocation, so a
// server restart self-heals within one interval — the same restart-tolerant
// design as mountLeaseRegistry. Merge-only is correct because a revoked cert is
// never un-revoked; an entry simply ages out once the cert's own expiry passes.
type certRevocationRegistry struct {
	mu      sync.RWMutex
	serials map[string]time.Time // serial(uppercase hex) -> cert NotAfter (prune horizon)
	now     func() time.Time
}

func newCertRevocationRegistry() *certRevocationRegistry {
	return &certRevocationRegistry{serials: map[string]time.Time{}, now: time.Now}
}

// Add records a revoked serial with the cert's expiry (its prune horizon).
// Idempotent. Aged-out entries are reclaimed once per push batch via Prune
// (called by the push handler), not per Add, so merging a full reconcile
// snapshot stays O(n) rather than O(n²).
func (r *certRevocationRegistry) Add(serial string, expiresAt time.Time) {
	serial = normalizeSerial(serial)
	if serial == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.serials[serial] = expiresAt
}

// IsRevoked reports whether serial is on the deny-list and not yet past the
// cert's own expiry. An expired entry reports false (the cert would fail
// verification anyway) and is reclaimed by the next Add/Prune.
func (r *certRevocationRegistry) IsRevoked(serial string) bool {
	serial = normalizeSerial(serial)
	if serial == "" {
		return false
	}
	r.mu.RLock()
	exp, ok := r.serials[serial]
	r.mu.RUnlock()
	if !ok {
		return false
	}
	return exp.IsZero() || r.now().Before(exp)
}

// Prune drops entries whose cert expiry has passed.
func (r *certRevocationRegistry) Prune() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneLocked()
}

func (r *certRevocationRegistry) pruneLocked() {
	now := r.now()
	for s, exp := range r.serials {
		if !exp.IsZero() && now.After(exp) {
			delete(r.serials, s)
		}
	}
}

// Count returns the current entry count (for the push response / observability).
func (r *certRevocationRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.serials)
}

// formatSerialHex renders a certificate serial as uppercase hex, the canonical
// deny-list form (matches the control plane's ca.formatSerial).
func formatSerialHex(s *big.Int) string {
	if s == nil {
		return ""
	}
	return strings.ToUpper(hex.EncodeToString(s.Bytes()))
}

func normalizeSerial(s string) string {
	return strings.ToUpper(strings.TrimSpace(s))
}
