package allocations

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
)

// GetForUser is the user-scoped read path: it enforces ownership and
// revocation as sentinel errors so callers don't repeat the checks.
func (s *Service) GetForUser(ctx context.Context, allocationID, userID pgtype.UUID) (Allocation, error) {
	row, err := s.store.GetAllocation(ctx, toUUID(allocationID))
	if errors.Is(err, storage.ErrNotFound) {
		return Allocation{}, ErrNotFound
	}
	if err != nil {
		return Allocation{}, fmt.Errorf("get for user: %w", err)
	}
	if row.UserID != toUUID(userID) {
		return Allocation{}, ErrWrongUser
	}
	if row.RevokedAt != nil {
		return Allocation{}, ErrRevoked
	}
	return fromStorage(row), nil
}
