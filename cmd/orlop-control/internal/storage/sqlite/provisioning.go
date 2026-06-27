package sqlite

import (
	"context"

	"github.com/google/uuid"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
)

var _ storage.ProvisioningStore = (*Store)(nil)

func (s *Store) EnsureTenant(ctx context.Context, id, name string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO tenants (id, name, created_at) VALUES (?, ?, ?)
		 ON CONFLICT(id) DO NOTHING`,
		id, name, nowMicros())
	return mapErr(err)
}

func (s *Store) EnsureUserWithID(ctx context.Context, in storage.NewUser) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO users (id, tenant_id, email, created_at) VALUES (?, ?, ?, ?)
		 ON CONFLICT(id) DO NOTHING`,
		in.ID, in.TenantID, in.Email, nowMicros())
	return mapErr(err)
}

func (s *Store) UpsertAgentAllocation(ctx context.Context, in storage.NewAgentAllocation) (storage.Allocation, error) {
	// Idempotent per-agent provisioning. The conflict target reuses the partial
	// unique index (agent_id WHERE revoked_at IS NULL); on conflict we touch
	// user_id so RETURNING yields the existing row.
	return scanAllocation(s.db.QueryRowContext(ctx,
		`INSERT INTO disk_allocations (id, user_id, agent_id, tenant_id, size_bytes, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(agent_id) WHERE revoked_at IS NULL
		 DO UPDATE SET user_id = excluded.user_id
		 RETURNING `+allocationColumns,
		uuid.New(), in.UserID, in.AgentID, in.TenantID, in.SizeBytes, nowMicros()))
}

func (s *Store) GetAllocationByAgent(ctx context.Context, agentID string) (storage.Allocation, error) {
	return scanAllocation(s.db.QueryRowContext(ctx,
		`SELECT `+allocationColumns+` FROM disk_allocations
		 WHERE agent_id = ? AND revoked_at IS NULL`, agentID))
}

func (s *Store) ReassignAgentAllocation(ctx context.Context, agentID string, newUserID uuid.UUID) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE disk_allocations SET user_id = ? WHERE agent_id = ? AND revoked_at IS NULL`,
		newUserID, agentID)
	return mapErr(err)
}
