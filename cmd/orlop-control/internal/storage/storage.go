// Package storage is the control plane's backend-agnostic data layer.
//
// It defines domain types and small *role* interfaces that HTTP/business code
// depends on, so the concrete database lives entirely behind an adapter
// (storage/postgres today; storage/sqlite, storage/redis later). The rules that
// make a second backend possible:
//
//   - No driver types cross this boundary. Methods take and return plain Go /
//     domain types (string, time.Time, *time.Time, domain structs) — never
//     pgx/pgtype. Adapters do the conversion.
//   - Interfaces express *intent*, not SQL. A method is named for what the
//     caller wants ("ConsumeEnrollToken"), not the query that happens to back
//     it. JOINs/RETURNING/conditional-updates are an adapter concern.
//   - Role interfaces stay small and are consumed à-la-carte (a reconciler asks
//     for a RevocationStore, not a 84-method god object). One adapter value
//     implements all of them.
//   - Errors are domain sentinels (ErrNotFound, …); adapters map their driver's
//     equivalents onto these so callers never import a driver to read a result.
//
// Transactions (for multi-statement flows like token issuance and lease
// acquisition) will be exposed here as `WithTx(ctx, func(s Store) error) error`
// once the first transactional slice is migrated; the Postgres adapter backs it
// with pgx.BeginFunc + Queries.WithTx.
package storage

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound is returned when a lookup matches nothing. Adapters map their
// driver's "no rows" sentinel onto this so callers stay driver-agnostic
// (`errors.Is(err, storage.ErrNotFound)`).
var ErrNotFound = errors.New("storage: not found")

// CertRevocation is a revoked agent-leaf serial on the data-plane deny-list
// (issue #5). Serial is uppercase hex; ExpiresAt is the cert's NotAfter.
type CertRevocation struct {
	Serial    string
	TenantID  string
	ExpiresAt time.Time
	Reason    string
}

// RevocationStore is the cert-revocation slice of the data layer.
type RevocationStore interface {
	// AddCertRevocation records a revoked serial. Idempotent on the serial (a
	// serial already present is left untouched).
	AddCertRevocation(ctx context.Context, rev CertRevocation) error
	// ListActiveCertRevocations returns revocations whose certs have not yet
	// expired, with Serial and ExpiresAt populated.
	ListActiveCertRevocations(ctx context.Context) ([]CertRevocation, error)
	// ListActiveServerOpsAddrs returns the distinct ops addresses of servers
	// that currently host at least one placed tenant — the push targets for the
	// deny-list reconcile.
	ListActiveServerOpsAddrs(ctx context.Context) ([]string, error)
}
