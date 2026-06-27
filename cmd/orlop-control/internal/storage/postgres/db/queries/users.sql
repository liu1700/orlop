-- name: CreateUser :one
INSERT INTO users (email, tenant_id)
VALUES ($1, $2)
RETURNING *;

-- name: EnsureUserWithID :exec
-- Idempotent: create the user with an explicit id (the orlop user UUID is
-- reused as the dg user id) if it does not already exist. Used by /v1/entities
-- provisioning so the disk allocation can reference the agent's owner.
INSERT INTO users (id, tenant_id, email)
VALUES ($1, $2, $3)
ON CONFLICT (id) DO NOTHING;

-- name: GetUser :one
SELECT * FROM users WHERE id = $1;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1;

-- name: SuspendUser :exec
UPDATE users SET suspended_at = now() WHERE id = $1;

-- name: UnsuspendUser :exec
UPDATE users SET suspended_at = NULL WHERE id = $1;

-- name: GetUserForUpdate :one
SELECT * FROM users WHERE id = $1 FOR UPDATE;

-- name: SetUserQuota :exec
-- Sets a user's aggregate quota. Used to provision the shared control-plane system
-- user with a high ceiling so per-agent caps are governed by each allocation's size.
UPDATE users SET quota_bytes = $2 WHERE id = $1;

-- name: SumActiveAllocationBytes :one
SELECT COALESCE(SUM(size_bytes), 0)::BIGINT AS total_bytes
FROM disk_allocations
WHERE user_id = $1 AND revoked_at IS NULL;
