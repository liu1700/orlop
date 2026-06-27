package storage

import (
	"context"

	"github.com/google/uuid"
)

// ServerPool is the operator view of a server_pools row used by the
// `server register` CLI: the registration fields plus capacity. (Distinct from
// [Server], the leaner placement-time projection the allocations path reads.)
type ServerPool struct {
	DataAddr   string
	OpsAddr    string
	TotalBytes int64
	FreeBytes  int64
	Status     string
}

// AdminStore is the operator-CLI data surface: the `user seed` / `user suspend`
// and `server register` subcommands run against Postgres directly. These are
// privileged, out-of-band operations (DATABASE_URL is the credential), distinct
// from the request-path role interfaces.
type AdminStore interface {
	// CreateTenant inserts a tenant, erroring (not ErrAlreadyExists) on a
	// duplicate id — callers gate on GetTenant first. For the idempotent
	// provisioning path use ProvisioningStore.EnsureTenant instead.
	CreateTenant(ctx context.Context, id, name string) error
	// GetUserByEmail resolves a user by email, or ErrNotFound.
	GetUserByEmail(ctx context.Context, email string) (User, error)
	// CreateUser inserts a user (DB-assigned id, default 'admin' role).
	CreateUser(ctx context.Context, email, tenantID string) (User, error)
	// SuspendUser marks a user suspended; its access tokens stop validating.
	SuspendUser(ctx context.Context, id uuid.UUID) error
	// RegisterServerPool upserts a placement-pool server keyed on data addr,
	// returning the stored row.
	RegisterServerPool(ctx context.Context, in ServerPool) (ServerPool, error)
}
