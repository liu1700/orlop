package allocations

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
)

// ListForUser returns the user's non-revoked allocations, newest first.
func (s *Service) ListForUser(ctx context.Context, userID pgtype.UUID) ([]Allocation, error) {
	rows, err := s.store.ListAllocationsForUser(ctx, toUUID(userID))
	if err != nil {
		return nil, err
	}
	out := make([]Allocation, 0, len(rows))
	for _, r := range rows {
		out = append(out, fromStorage(r))
	}
	return out, nil
}
