package allocations

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
)

// Bind attaches an existing Free allocation to an agent enrollment.
// Returns ErrNotFound, ErrWrongUser, ErrRevoked, or ErrAlreadyBound if the
// guard predicates do not match.
func (s *Service) Bind(ctx context.Context, allocationID, userID, agentID pgtype.UUID) (Allocation, error) {
	row, err := s.store.BindAllocation(ctx, toUUID(allocationID), toUUID(userID), toUUID(agentID))
	if err == nil {
		return fromStorage(row), nil
	}
	if !errors.Is(err, storage.ErrNotFound) {
		return Allocation{}, fmt.Errorf("bind: %w", err)
	}
	// Zero rows updated — figure out why.
	cur, gerr := s.store.GetAllocation(ctx, toUUID(allocationID))
	if errors.Is(gerr, storage.ErrNotFound) {
		return Allocation{}, ErrNotFound
	}
	if gerr != nil {
		return Allocation{}, fmt.Errorf("get after bind miss: %w", gerr)
	}
	switch {
	case cur.UserID != toUUID(userID):
		return Allocation{}, ErrWrongUser
	case cur.RevokedAt != nil:
		return Allocation{}, ErrRevoked
	case cur.BoundAgentID != nil:
		return Allocation{}, ErrAlreadyBound
	default:
		return Allocation{}, fmt.Errorf("bind: zero rows but no guard matched (state=%+v)", cur)
	}
}
