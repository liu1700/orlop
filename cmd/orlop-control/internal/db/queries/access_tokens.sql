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
    t.consumed_at,
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

-- name: ConsumeAgentEnrollToken :one
-- Atomically spend a single-use agent-enroll token (issue #6). Matches only an
-- un-consumed 'agent_enroll' row; a replay or a lost concurrent race matches
-- zero rows and returns pgx.ErrNoRows, which the caller treats as "already
-- spent" and rejects. The purpose filter keeps device/admin/api multi-use
-- sessions out — they are never consumed here even when presented on the
-- enroll route. The literal mirrors devauth.PurposeAgentEnroll.
UPDATE access_tokens
SET consumed_at = now()
WHERE token_hash = $1
  AND purpose = 'agent_enroll'
  AND consumed_at IS NULL
RETURNING id;
