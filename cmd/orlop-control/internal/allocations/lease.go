package allocations

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/db/sqlcdb"
)

func ttlInterval(ttl time.Duration) pgtype.Interval {
	return pgtype.Interval{
		Microseconds: ttl.Microseconds(),
		Valid:        true,
	}
}

// AcquireMountLease atomically claims the allocation for agentID and sets a fresh mount
// lease, UNCONDITIONALLY taking over any existing lease (only a revoked/missing allocation
// fails, mapped to ErrRevoked/ErrNotFound). An allocation belongs to a single orlop agent,
// so callers the handler authorized (owning user + agent-scoped cert) are always that
// agent; a one-shot pod re-mounts with a fresh enrollment every turn and must take over
// the prior pod's lease — including one a crashed pod leaked, without waiting out the TTL.
// Mount exclusivity is enforced by the handler's ownership check + the data-plane cert.
func (s *Service) AcquireMountLease(ctx context.Context, allocationID, agentID pgtype.UUID, ttl time.Duration) (Allocation, error) {
	row, err := s.q.AcquireMountLease(ctx, sqlcdb.AcquireMountLeaseParams{
		ID:           allocationID,
		BoundAgentID: pgtype.UUID{Bytes: agentID.Bytes, Valid: true},
		Ttl:          ttlInterval(ttl),
	})
	if err == nil {
		return fromRow(row), nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Allocation{}, fmt.Errorf("acquire: %w", err)
	}
	return Allocation{}, s.classifyLeaseMiss(ctx, allocationID, agentID, true)
}

// classifyLeaseMiss reads the current row to map a zero-rows update to the
// right sentinel error. acquired=true means the failing call was an Acquire
// (so a live lease for the same agent should map to ErrAlreadyMounted);
// acquired=false means the call was a Refresh (live lease is the success
// case, so this branch should not happen).
func (s *Service) classifyLeaseMiss(ctx context.Context, allocationID, agentID pgtype.UUID, acquired bool) error {
	cur, err := s.q.GetAllocation(ctx, allocationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("get after lease miss: %w", err)
	}
	if cur.RevokedAt.Valid {
		return ErrRevoked
	}
	if cur.LeaseExpiresAt.Valid && cur.LeaseExpiresAt.Time.After(time.Now()) {
		if !cur.BoundAgentID.Valid || cur.BoundAgentID.Bytes != agentID.Bytes {
			return ErrWrongAgent
		}
		if acquired {
			return ErrAlreadyMounted
		}
		// Refresh would succeed in this state, so this branch is unreachable.
		return fmt.Errorf("classify: refresh miss with live lease (state=%+v)", cur)
	}
	if !cur.BoundAgentID.Valid || cur.BoundAgentID.Bytes != agentID.Bytes {
		if acquired {
			return fmt.Errorf("classify: acquire miss without live lease (state=%+v)", cur)
		}
		return ErrWrongAgent
	}
	// Lease expired or absent.
	if !acquired {
		return ErrLeaseLost
	}
	// Acquired with no live lease: the conditional update should have hit.
	// Treat as a transient race — caller may retry.
	return fmt.Errorf("classify: acquire miss with no live lease (state=%+v)", cur)
}

// RefreshMountLease extends the lease for the agent that already holds it.
// Returns ErrLeaseLost if the lease has already expired (caller must call
// AcquireMountLease again), ErrWrongAgent if a different agent holds the
// binding, ErrRevoked if the allocation was revoked, or ErrNotFound if the
// allocation id is unknown.
func (s *Service) RefreshMountLease(ctx context.Context, allocationID, agentID pgtype.UUID, ttl time.Duration) (Allocation, error) {
	row, err := s.q.RefreshMountLease(ctx, sqlcdb.RefreshMountLeaseParams{
		ID:           allocationID,
		BoundAgentID: pgtype.UUID{Bytes: agentID.Bytes, Valid: true},
		Ttl:          ttlInterval(ttl),
	})
	if err == nil {
		return fromRow(row), nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Allocation{}, fmt.Errorf("refresh: %w", err)
	}
	return Allocation{}, s.classifyLeaseMiss(ctx, allocationID, agentID, false)
}

// ReleaseMountLease clears the binding (bound_agent_id, bound_at) and the
// lease, returning the allocation to Free state. Idempotent: calling on an
// already-Free allocation is a no-op.
// Errors with ErrWrongAgent if the binding belongs to a different agent.
func (s *Service) ReleaseMountLease(ctx context.Context, allocationID, agentID pgtype.UUID) error {
	row, err := s.q.ReleaseMountLease(ctx, sqlcdb.ReleaseMountLeaseParams{
		ID:           allocationID,
		BoundAgentID: pgtype.UUID{Bytes: agentID.Bytes, Valid: true},
	})
	if err == nil {
		_ = row
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("release: %w", err)
	}
	cur, gerr := s.q.GetAllocation(ctx, allocationID)
	if errors.Is(gerr, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if gerr != nil {
		return fmt.Errorf("get after release miss: %w", gerr)
	}
	if cur.BoundAgentID.Valid && cur.BoundAgentID.Bytes != agentID.Bytes {
		return ErrWrongAgent
	}
	return fmt.Errorf("release: zero rows but no guard matched (state=%+v)", cur)
}
