package storage

import "context"

// Tx is a transaction-scoped handle exposing every subdomain's operations plus
// Commit/Rollback. A single value backs all of them, so a transaction can span
// subdomains; consumers that only need one subdomain depend on the narrow role
// interface (SessionStore, AllocationStore, ...) and receive a Tx inside Begin.
type Tx interface {
	SessionOps
	AllocationOps
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}

// beginner starts a transaction. Commit persists; Rollback (safe to call after
// Commit) discards.
type beginner interface {
	Begin(ctx context.Context) (Tx, error)
}
