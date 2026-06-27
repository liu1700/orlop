package allocations

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/db/sqlcdb"
)

// ForceReleaseMountLease clears bound_agent_id, bound_at, and lease_expires_at
// for an allocation owned by userID. The caller must be the owner — this is the
// admin-session counterpart of ReleaseMountLease (which is keyed by agent
// identity). Idempotent on already-released rows.
//
// Errors:
//   - ErrNotFound: no row with that ID.
//   - ErrWrongUser: row belongs to a different user.
//   - ErrRevoked: row is soft-deleted.
func (s *Service) ForceReleaseMountLease(ctx context.Context, allocationID, userID pgtype.UUID) error {
	// Capture the bound agent (if any) before the release clears bound_agent_id,
	// so its leaf can be revoked on success (issue #5).
	prior, priorErr := s.q.GetAllocation(ctx, allocationID)

	_, err := s.q.ForceReleaseMountLease(ctx, sqlcdb.ForceReleaseMountLeaseParams{
		ID:     allocationID,
		UserID: userID,
	})
	if err == nil {
		if priorErr == nil && prior.BoundAgentID.Valid {
			s.revokeReleasedAgentCert(ctx, prior.BoundAgentID, prior.TenantID)
		}
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("force release: %w", err)
	}

	cur, gerr := s.q.GetAllocation(ctx, allocationID)
	if errors.Is(gerr, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if gerr != nil {
		return fmt.Errorf("get after force release miss: %w", gerr)
	}
	if cur.UserID != userID {
		return ErrWrongUser
	}
	if cur.RevokedAt.Valid {
		return ErrRevoked
	}
	return fmt.Errorf("force release: zero rows but no guard matched (state=%+v)", cur)
}
