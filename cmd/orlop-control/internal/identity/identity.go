// Package identity is the pluggable host-identity seam for orlop-control
// (issue #4, docs/design-identity.md). An embeddable orlop does not own the
// human account lifecycle: the host platform asserts identity and orlop
// verifies it, mapping a verified claim onto the load-bearing tenant subject.
//
// The seam is a single Verifier interface (Temporal ClaimMapper / Envoy
// ext_authz shaped). AuthInfo carries both a bearer token and the mTLS
// connection state so a JWT verifier (Mode B) and a future cert verifier share
// one mapping point. The built-in default is JWTVerifier.
package identity

import (
	"context"
	"crypto/tls"
	"errors"
)

// Identity is the result of verifying a host assertion: the orlop tenant
// subject the caller is authorized to act as, plus the raw verified claims for
// auditing. It deliberately does not carry a user-account concept — orlop does
// not own that.
type Identity struct {
	// TenantID is the load-bearing authorization subject, derived from a
	// verified-and-allowlisted claim. Never taken from a request body.
	TenantID string
	// Subject is the token's `sub` (the host's principal id), for audit.
	Subject string
	// Claims is the verified claim set, for audit/debug. Read-only.
	Claims map[string]any
}

// AuthInfo is the raw material a Verifier inspects. A JWT verifier reads
// Bearer; an mTLS verifier reads TLS. Both may be present.
type AuthInfo struct {
	// Bearer is the raw bearer token (no "Bearer " prefix).
	Bearer string
	// TLS is the verified-peer connection state, if the caller presented a
	// client certificate. May be nil.
	TLS *tls.ConnectionState
}

// Verifier resolves a host assertion into an orlop Identity. Implementations
// MUST fail closed: an unverifiable assertion, or one whose claim is not on the
// operator allowlist, returns an error and never a zero-value success.
type Verifier interface {
	Verify(ctx context.Context, info AuthInfo) (Identity, error)
}

// Sentinel errors. Callers map these to HTTP status; raw error text never
// leaks to clients.
var (
	ErrNoCredential       = errors.New("identity: no credential presented")
	ErrMalformedToken     = errors.New("identity: malformed token")
	ErrUnsupportedAlg     = errors.New("identity: unsupported or mismatched signing algorithm")
	ErrBadSignature       = errors.New("identity: signature verification failed")
	ErrClaimsInvalid      = errors.New("identity: token claims failed validation")
	ErrTenantClaimMissing = errors.New("identity: tenant claim missing or not a string")
	ErrTenantNotAllowed   = errors.New("identity: tenant not on operator allowlist")
)
