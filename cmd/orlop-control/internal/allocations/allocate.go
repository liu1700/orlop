package allocations

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/db/sqlcdb"
)

// Allocate creates a Free disk for the user and returns it. Errors with
// ErrQuotaExceeded if the user's non-revoked total would exceed
// users.quota_bytes. Concurrent callers serialize on the user row via
// SELECT ... FOR UPDATE.
func (s *Service) Allocate(ctx context.Context, userID pgtype.UUID, sizeBytes int64) (Allocation, error) {
	if sizeBytes <= 0 {
		return Allocation{}, fmt.Errorf("allocations: size_bytes must be positive, got %d", sizeBytes)
	}

	var out Allocation
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		qtx := s.q.WithTx(tx)
		user, err := qtx.GetUserForUpdate(ctx, userID)
		if err != nil {
			return fmt.Errorf("get user: %w", err)
		}
		used, err := qtx.SumActiveAllocationBytes(ctx, userID)
		if err != nil {
			return fmt.Errorf("sum allocations: %w", err)
		}
		if used+sizeBytes > user.QuotaBytes {
			return ErrQuotaExceeded
		}
		row, err := qtx.InsertAllocation(ctx, sqlcdb.InsertAllocationParams{
			UserID:    userID,
			SizeBytes: sizeBytes,
		})
		if err != nil {
			return fmt.Errorf("insert allocation: %w", err)
		}
		out = fromRow(row)
		return nil
	})
	if err != nil {
		return Allocation{}, err
	}
	return out, nil
}
