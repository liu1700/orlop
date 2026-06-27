package allocations

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
)

// Revoke soft-deletes the allocation. Idempotent: calling on an already-
// revoked row is a no-op and returns nil.
// Returns ErrWrongUser if the row exists under a different owner.
func (s *Service) Revoke(ctx context.Context, allocationID, userID pgtype.UUID) error {
	err := s.store.RevokeAllocation(ctx, toUUID(allocationID), toUUID(userID))
	if err == nil {
		return nil
	}
	if !errors.Is(err, storage.ErrNotFound) {
		return fmt.Errorf("revoke: %w", err)
	}
	cur, gerr := s.store.GetAllocation(ctx, toUUID(allocationID))
	if errors.Is(gerr, storage.ErrNotFound) {
		return ErrNotFound
	}
	if gerr != nil {
		return fmt.Errorf("get after revoke miss: %w", gerr)
	}
	if cur.UserID != toUUID(userID) {
		return ErrWrongUser
	}
	return fmt.Errorf("revoke: zero rows but no guard matched (state=%+v)", cur)
}
