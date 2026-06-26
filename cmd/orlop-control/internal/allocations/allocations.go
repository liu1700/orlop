// Package allocations is the source of truth for per-user disk quotas and
// the per-allocation mount lock. The data plane is orlop-control's Postgres
// (Supabase). HTTP endpoints that consume this package land in #59/#60/#62.
//
// Lifecycle:
//
//	Allocate (Free) -> Bind (Bound) -> AcquireMountLease (Mounted)
//	                               <- ReleaseMountLease (back to Free)
//	any state -> Revoke (terminal).
//
// See an internal design spec.
package allocations

import (
	"errors"
	"io"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/db/sqlcdb"
)

// LeaseTTL is the server-side mount-lease window. The agent (#62) refreshes
// at half this interval. Hardcoded to keep moving parts to a minimum.
const LeaseTTL = 60 * time.Second

// Sentinel errors. Callers map these to HTTP status codes; raw text never
// leaks to clients.
var (
	ErrQuotaExceeded  = errors.New("allocations: quota exceeded")
	ErrAlreadyBound   = errors.New("allocations: already bound to an agent")
	ErrWrongUser      = errors.New("allocations: belongs to a different user")
	ErrWrongAgent     = errors.New("allocations: bound to a different agent")
	ErrAlreadyMounted = errors.New("allocations: lease already live for this agent")
	ErrLeaseLost      = errors.New("allocations: lease expired; re-acquire required")
	ErrRevoked        = errors.New("allocations: revoked")
	ErrNotFound       = errors.New("allocations: not found")
)

// Allocation is the public projection of a disk_allocations row.
type Allocation struct {
	ID             pgtype.UUID
	UserID         pgtype.UUID
	SizeBytes      int64
	CreatedAt      time.Time
	RevokedAt      *time.Time
	BoundAgentID   *pgtype.UUID
	BoundAt        *time.Time
	LeaseExpiresAt *time.Time
}

// Service provides the allocations workflow. Holds a pgxpool because every
// public method either runs in a single statement or opens a short-lived tx.
type Service struct {
	pool   *pgxpool.Pool
	q      *sqlcdb.Queries
	logger *slog.Logger
}

// NewService wires the service to a pgxpool. The pool must already have run
// migrations through 0004. If logger is nil, logs are discarded.
func NewService(pool *pgxpool.Pool, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Service{pool: pool, q: sqlcdb.New(pool), logger: logger}
}

// fromRow projects an sqlcdb row into the public Allocation type.
func fromRow(r sqlcdb.DiskAllocation) Allocation {
	a := Allocation{
		ID:        r.ID,
		UserID:    r.UserID,
		SizeBytes: r.SizeBytes,
		CreatedAt: r.CreatedAt.Time,
	}
	if r.RevokedAt.Valid {
		t := r.RevokedAt.Time
		a.RevokedAt = &t
	}
	if r.BoundAgentID.Valid {
		id := r.BoundAgentID
		a.BoundAgentID = &id
	}
	if r.BoundAt.Valid {
		t := r.BoundAt.Time
		a.BoundAt = &t
	}
	if r.LeaseExpiresAt.Valid {
		t := r.LeaseExpiresAt.Time
		a.LeaseExpiresAt = &t
	}
	return a
}
