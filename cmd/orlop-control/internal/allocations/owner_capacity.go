package allocations

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
)

// ResizeOwnerCapacity changes each account-level server reservation exactly
// once. Allocation rows may be repeated per agent, but the pool debit mirrors
// the shared owner-directory quota and therefore must not carry that multiplier.
func (s *Service) ResizeOwnerCapacity(ctx context.Context, userID uuid.UUID, newSizeBytes int64) error {
	if newSizeBytes <= 0 {
		return fmt.Errorf("allocations: size_bytes must be positive, got %d", newSizeBytes)
	}
	tx, err := s.store.Begin(ctx)
	if err != nil {
		return fmt.Errorf("allocations: begin owner resize: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.GetUserForUpdate(ctx, userID); err != nil {
		return fmt.Errorf("allocations: lock owner: %w", err)
	}
	reservations, err := tx.ListOwnerCapacityReservations(ctx, userID)
	if err != nil {
		return fmt.Errorf("allocations: list owner reservations: %w", err)
	}
	for _, reservation := range reservations {
		delta := newSizeBytes - reservation.SizeBytes
		if delta > 0 {
			if err := tx.ReserveCapacityForGrowth(ctx, reservation.ServerID, delta); errors.Is(err, storage.ErrNotFound) {
				return ErrNoCapacity
			} else if err != nil {
				return fmt.Errorf("allocations: grow owner reservation: %w", err)
			}
		} else if delta < 0 {
			if err := tx.ReleaseCapacity(ctx, reservation.ServerID, -delta); err != nil {
				return fmt.Errorf("allocations: shrink owner reservation: %w", err)
			}
		}
		if delta != 0 {
			if err := tx.UpdateOwnerCapacityReservationSize(ctx, userID, reservation.ServerID, newSizeBytes); err != nil {
				return fmt.Errorf("allocations: update owner reservation: %w", err)
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("allocations: commit owner resize: %w", err)
	}
	return nil
}
