package allocations

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"
)

// Allocate creates a Free disk for the user and returns it. Errors with
// ErrQuotaExceeded if the user's non-revoked total would exceed
// users.quota_bytes. Concurrent callers serialize on the user row via
// SELECT ... FOR UPDATE.
func (s *Service) Allocate(ctx context.Context, userID pgtype.UUID, sizeBytes int64) (Allocation, error) {
	if sizeBytes <= 0 {
		return Allocation{}, fmt.Errorf("allocations: size_bytes must be positive, got %d", sizeBytes)
	}
	uid := toUUID(userID)

	tx, err := s.store.Begin(ctx)
	if err != nil {
		return Allocation{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	user, err := tx.GetUserForUpdate(ctx, uid)
	if err != nil {
		return Allocation{}, fmt.Errorf("get user: %w", err)
	}
	used, err := tx.SumActiveAllocationBytes(ctx, uid)
	if err != nil {
		return Allocation{}, fmt.Errorf("sum allocations: %w", err)
	}
	if used+sizeBytes > user.QuotaBytes {
		return Allocation{}, ErrQuotaExceeded
	}
	row, err := tx.InsertAllocation(ctx, uid, sizeBytes)
	if err != nil {
		return Allocation{}, fmt.Errorf("insert allocation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Allocation{}, err
	}
	return fromStorage(row), nil
}
