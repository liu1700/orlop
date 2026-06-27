-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens (token_hash, family_id, user_id, tenant_id, expires_at, allocation_id)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetRefreshTokenByHash :one
SELECT
    t.id,
    t.token_hash,
    t.family_id,
    t.user_id,
    t.tenant_id,
    t.expires_at,
    t.revoked_at,
    t.rotated_at,
    t.created_at,
    t.allocation_id,
    u.suspended_at AS user_suspended_at,
    ten.suspended_at AS tenant_suspended_at
FROM refresh_tokens t
JOIN users   u   ON u.id = t.user_id
JOIN tenants ten ON ten.id = t.tenant_id
WHERE t.token_hash = $1
FOR UPDATE;

-- name: MarkRefreshTokenRotated :exec
UPDATE refresh_tokens SET rotated_at = now() WHERE id = $1 AND rotated_at IS NULL AND revoked_at IS NULL;

-- name: RevokeRefreshTokenFamily :exec
UPDATE refresh_tokens SET revoked_at = now() WHERE family_id = $1 AND revoked_at IS NULL;

-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens SET revoked_at = now() WHERE token_hash = $1;
