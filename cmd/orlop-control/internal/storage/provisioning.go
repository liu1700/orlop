package storage

import (
	"context"

	"github.com/google/uuid"
)

// NewUser idempotently ensures a user row with an explicit id (the orlop user
// UUID is reused as the storage user id).
type NewUser struct {
	ID       uuid.UUID
	TenantID string
	Email    string
}

// NewAgentAllocation upserts an agent's disk allocation, keyed on AgentID and
// living in its own per-agent TenantID.
type NewAgentAllocation struct {
	UserID    uuid.UUID
	AgentID   string
	TenantID  string
	SizeBytes int64
}

// ProvisioningStore is the write surface the /v1/entities provisioning API uses
// to bootstrap an agent's storage entities (tenant + user + per-agent disk) and
// re-home a disk to a new owner. Every ensure/upsert is idempotent.
type ProvisioningStore interface {
	// EnsureTenant creates the tenant if absent.
	EnsureTenant(ctx context.Context, id, name string) error
	// EnsureUserWithID creates the user with an explicit id if absent.
	EnsureUserWithID(ctx context.Context, in NewUser) error
	// UpsertAgentAllocation creates (or returns) the agent's disk, keyed on agent
	// id; re-provisioning returns the existing row unchanged.
	UpsertAgentAllocation(ctx context.Context, in NewAgentAllocation) (Allocation, error)
	// GetAllocationByAgent resolves an agent's disk allocation, or ErrNotFound.
	GetAllocationByAgent(ctx context.Context, agentID string) (Allocation, error)
	// ReassignAgentAllocation re-homes an agent's disk to newUserID (a user_id flip
	// only — the disk stays in its per-agent tenant, so no data moves).
	ReassignAgentAllocation(ctx context.Context, agentID string, newUserID uuid.UUID) error
}
