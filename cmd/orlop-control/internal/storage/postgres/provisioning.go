package postgres

import (
	"context"

	"github.com/google/uuid"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/db/sqlcdb"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
)

var _ storage.ProvisioningStore = (*Store)(nil)

func (s *Store) EnsureTenant(ctx context.Context, id, name string) error {
	return mapErr(s.q.EnsureTenant(ctx, sqlcdb.EnsureTenantParams{ID: id, Name: name}))
}

func (s *Store) EnsureUserWithID(ctx context.Context, in storage.NewUser) error {
	return mapErr(s.q.EnsureUserWithID(ctx, sqlcdb.EnsureUserWithIDParams{
		ID:       pgUUID(in.ID),
		TenantID: in.TenantID,
		Email:    in.Email,
	}))
}

func (s *Store) UpsertAgentAllocation(ctx context.Context, in storage.NewAgentAllocation) (storage.Allocation, error) {
	row, err := s.q.UpsertAgentAllocation(ctx, sqlcdb.UpsertAgentAllocationParams{
		UserID:    pgUUID(in.UserID),
		AgentID:   pgText(in.AgentID),
		TenantID:  pgText(in.TenantID),
		SizeBytes: in.SizeBytes,
	})
	if err != nil {
		return storage.Allocation{}, mapErr(err)
	}
	return allocation(row), nil
}

func (s *Store) GetAllocationByAgent(ctx context.Context, agentID string) (storage.Allocation, error) {
	row, err := s.q.GetAllocationByAgent(ctx, pgText(agentID))
	if err != nil {
		return storage.Allocation{}, mapErr(err)
	}
	return allocation(row), nil
}

func (s *Store) ReassignAgentAllocation(ctx context.Context, agentID string, newUserID uuid.UUID) error {
	return mapErr(s.q.ReassignAgentAllocation(ctx, sqlcdb.ReassignAgentAllocationParams{
		AgentID: pgText(agentID),
		UserID:  pgUUID(newUserID),
	}))
}
