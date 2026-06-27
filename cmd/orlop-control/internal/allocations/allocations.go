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

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
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

// Service provides the allocations workflow over a storage backend.
type Service struct {
	store  storage.AllocationStore
	logger *slog.Logger
}

// NewService wires the service to a storage backend. If logger is nil, logs are
// discarded.
func NewService(store storage.AllocationStore, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Service{store: store, logger: logger}
}

// fromStorage projects a storage.Allocation into the public Allocation type,
// which still speaks pgtype.UUID for its handler consumers.
func fromStorage(a storage.Allocation) Allocation {
	out := Allocation{
		ID:             fromUUID(a.ID),
		UserID:         fromUUID(a.UserID),
		SizeBytes:      a.SizeBytes,
		CreatedAt:      a.CreatedAt,
		RevokedAt:      a.RevokedAt,
		BoundAt:        a.BoundAt,
		LeaseExpiresAt: a.LeaseExpiresAt,
	}
	if a.BoundAgentID != nil {
		p := fromUUID(*a.BoundAgentID)
		out.BoundAgentID = &p
	}
	return out
}

// Boundary conversions: the public API still speaks pgtype.UUID (handlers
// consume it); storage speaks uuid.UUID.

func toUUID(u pgtype.UUID) uuid.UUID {
	if !u.Valid {
		return uuid.UUID{}
	}
	return uuid.UUID(u.Bytes)
}

func fromUUID(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: true} }
