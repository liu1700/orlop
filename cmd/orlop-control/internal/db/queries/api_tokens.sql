-- name: CreateAPIToken :one
INSERT INTO api_tokens (user_id, name, token_hash, prefix, expires_at)
VALUES ($1, $2, $3, $4, $5)
RETURNING id, user_id, name, prefix, created_at, expires_at;

-- name: GetAPITokenByHash :one
SELECT
    t.id, t.user_id, t.name, t.prefix, t.created_at, t.last_used_at, t.revoked_at, t.expires_at,
    u.tenant_id      AS user_tenant_id,
    u.suspended_at   AS user_suspended_at,
    ten.suspended_at AS tenant_suspended_at
FROM api_tokens t
JOIN users u ON u.id = t.user_id
JOIN tenants ten ON ten.id = u.tenant_id
WHERE t.token_hash = $1;

-- name: ListAPITokensByUser :many
SELECT id, name, prefix, created_at, last_used_at
FROM api_tokens
WHERE user_id = $1 AND revoked_at IS NULL
ORDER BY created_at DESC;

-- name: GetAPITokenByID :one
SELECT id, user_id, name, prefix, created_at, last_used_at, revoked_at
FROM api_tokens
WHERE id = $1;

-- name: RevokeAPIToken :exec
UPDATE api_tokens SET revoked_at = now()
WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL;

-- name: TouchAPITokenLastUsed :exec
UPDATE api_tokens SET last_used_at = now() WHERE id = $1;
