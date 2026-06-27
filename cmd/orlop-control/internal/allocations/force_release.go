package allocations

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
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
	prior, priorErr := s.store.GetAllocation(ctx, toUUID(allocationID))

	err := s.store.ForceReleaseMountLease(ctx, toUUID(allocationID), toUUID(userID))
	if err == nil {
		if priorErr == nil && prior.BoundAgentID != nil {
			s.revokeReleasedAgentCert(ctx, *prior.BoundAgentID, prior.TenantID)
		}
		return nil
	}
	if !errors.Is(err, storage.ErrNotFound) {
		return fmt.Errorf("force release: %w", err)
	}

	cur, gerr := s.store.GetAllocation(ctx, toUUID(allocationID))
	if errors.Is(gerr, storage.ErrNotFound) {
		return ErrNotFound
	}
	if gerr != nil {
		return fmt.Errorf("get after force release miss: %w", gerr)
	}
	if cur.UserID != toUUID(userID) {
		return ErrWrongUser
	}
	if cur.RevokedAt != nil {
		return ErrRevoked
	}
	return fmt.Errorf("force release: zero rows but no guard matched (state=%+v)", cur)
}
