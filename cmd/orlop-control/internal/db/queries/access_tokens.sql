-- name: CreateAccessToken :one
INSERT INTO access_tokens (token_hash, purpose, user_id, tenant_id, expires_at, allocation_id)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetAccessTokenByHash :one
SELECT
    t.id,
    t.token_hash,
    t.purpose,
    t.user_id,
    t.tenant_id,
    t.expires_at,
    t.revoked_at,
    t.created_at,
    t.allocation_id,
    u.suspended_at AS user_suspended_at,
    ten.suspended_at AS tenant_suspended_at
FROM access_tokens t
JOIN users   u   ON u.id = t.user_id
JOIN tenants ten ON ten.id = t.tenant_id
WHERE t.token_hash = $1;

-- name: RevokeAccessToken :exec
UPDATE access_tokens SET revoked_at = now() WHERE token_hash = $1;
