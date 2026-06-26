package allocations

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/db/sqlcdb"
)

// Revoke soft-deletes the allocation. Idempotent: calling on an already-
// revoked row is a no-op and returns nil.
// Returns ErrWrongUser if the row exists under a different owner.
func (s *Service) Revoke(ctx context.Context, allocationID, userID pgtype.UUID) error {
	_, err := s.q.RevokeAllocation(ctx, sqlcdb.RevokeAllocationParams{
		ID:     allocationID,
		UserID: userID,
	})
	if err == nil {
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("revoke: %w", err)
	}
	cur, gerr := s.q.GetAllocation(ctx, allocationID)
	if errors.Is(gerr, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if gerr != nil {
		return fmt.Errorf("get after revoke miss: %w", gerr)
	}
	if cur.UserID != userID {
		return ErrWrongUser
	}
	return fmt.Errorf("revoke: zero rows but no guard matched (state=%+v)", cur)
}
