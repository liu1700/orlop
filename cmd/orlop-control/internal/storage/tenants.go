package storage

import "context"

// Tenant is a tenants row projection. Suspended folds the nullable suspended_at
// timestamp into a bool — callers gate on the fact of suspension, not its time.
// (No ID field: the only caller looks a tenant up by id it already holds.)
type Tenant struct {
	Name      string
	Suspended bool
}

// TenantStore reads tenant records (the agent-enroll suspension gate).
type TenantStore interface {
	// GetTenant returns the tenant by id, or ErrNotFound.
	GetTenant(ctx context.Context, id string) (Tenant, error)
}
