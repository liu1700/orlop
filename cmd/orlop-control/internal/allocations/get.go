package allocations

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// GetForUser is the user-scoped read path: it enforces ownership and
// revocation as sentinel errors so callers don't repeat the checks.
func (s *Service) GetForUser(ctx context.Context, allocationID, userID pgtype.UUID) (Allocation, error) {
	row, err := s.q.GetAllocation(ctx, allocationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Allocation{}, ErrNotFound
	}
	if err != nil {
		return Allocation{}, fmt.Errorf("get for user: %w", err)
	}
	if row.UserID != userID {
		return Allocation{}, ErrWrongUser
	}
	if row.RevokedAt.Valid {
		return Allocation{}, ErrRevoked
	}
	return fromRow(row), nil
}
