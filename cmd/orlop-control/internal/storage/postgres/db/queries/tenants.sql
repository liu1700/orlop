-- name: CreateTenant :one
INSERT INTO tenants (id, name)
VALUES ($1, $2)
RETURNING *;

-- name: EnsureTenant :exec
-- Idempotent: create the tenant if it does not already exist. The caller
-- follows up with GetTenant when it needs the row. Used by /v1/entities
-- provisioning to lazily ensure the customer's per-user tenant.
INSERT INTO tenants (id, name)
VALUES ($1, $2)
ON CONFLICT (id) DO NOTHING;

-- name: GetTenant :one
SELECT * FROM tenants WHERE id = $1;

-- name: ListTenants :many
SELECT * FROM tenants ORDER BY created_at;

-- name: SuspendTenant :exec
UPDATE tenants SET suspended_at = now() WHERE id = $1;
