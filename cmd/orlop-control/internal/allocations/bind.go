package allocations

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/db/sqlcdb"
)

// Bind attaches an existing Free allocation to an agent enrollment.
// Returns ErrNotFound, ErrWrongUser, ErrRevoked, or ErrAlreadyBound if the
// guard predicates do not match.
func (s *Service) Bind(ctx context.Context, allocationID, userID, agentID pgtype.UUID) (Allocation, error) {
	row, err := s.q.BindAllocation(ctx, sqlcdb.BindAllocationParams{
		ID:           allocationID,
		UserID:       userID,
		BoundAgentID: pgtype.UUID{Bytes: agentID.Bytes, Valid: true},
	})
	if err == nil {
		return fromRow(row), nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Allocation{}, fmt.Errorf("bind: %w", err)
	}
	// Zero rows updated — figure out why.
	cur, gerr := s.q.GetAllocation(ctx, allocationID)
	if errors.Is(gerr, pgx.ErrNoRows) {
		return Allocation{}, ErrNotFound
	}
	if gerr != nil {
		return Allocation{}, fmt.Errorf("get after bind miss: %w", gerr)
	}
	switch {
	case cur.UserID != userID:
		return Allocation{}, ErrWrongUser
	case cur.RevokedAt.Valid:
		return Allocation{}, ErrRevoked
	case cur.BoundAgentID.Valid:
		return Allocation{}, ErrAlreadyBound
	default:
		return Allocation{}, fmt.Errorf("bind: zero rows but no guard matched (state=%+v)", cur)
	}
}
