-- name: InsertAnonymousAllocation :one
INSERT INTO disk_allocations (user_id, size_bytes, expires_at)
VALUES (NULL, $1, $2)
RETURNING *;

-- name: InsertAnonymousSession :one
INSERT INTO sessions_anonymous (
    session_id, allocation_id, device_id, cert_serial,
    spawner_url, ip_address, user_agent
) VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: GetAnonymousSession :one
SELECT * FROM sessions_anonymous WHERE session_id = $1;

-- name: GetAnonymousSessionAllocation :one
SELECT sa.*, da.expires_at AS allocation_expires_at
FROM sessions_anonymous sa
JOIN disk_allocations da ON da.id = sa.allocation_id
WHERE sa.session_id = $1;

-- name: CountUnclaimedAnonymousSessionsForDevice :one
SELECT count(*)::int AS n FROM sessions_anonymous
WHERE device_id = $1
  AND claimed_at IS NULL
  AND created_at > now() - INTERVAL '5 hours';

-- name: CountAnonymousSessionsForIP :one
SELECT count(*)::int AS n FROM sessions_anonymous
WHERE ip_address = $1 AND created_at > now() - INTERVAL '5 minutes';

-- name: ClaimAnonymousAllocations :many
-- Two-step: promote allocations, then mark sessions claimed.
WITH promoted AS (
    UPDATE disk_allocations
       SET user_id    = sqlc.arg(user_id)::uuid,
           expires_at = NULL
     WHERE id IN (
         SELECT allocation_id FROM sessions_anonymous
          WHERE device_id = sqlc.arg(device_id)::text
            AND claimed_at IS NULL
            AND created_at > now() - INTERVAL '5 hours'
     )
     AND user_id IS NULL
    RETURNING id
)
UPDATE sessions_anonymous
   SET claimed_at = now(),
       claimed_by = sqlc.arg(user_id)::uuid
 WHERE device_id = sqlc.arg(device_id)::text
   AND claimed_at IS NULL
   AND allocation_id IN (SELECT id FROM promoted)
RETURNING allocation_id;

-- name: ListExpiredAnonymousSessions :many
SELECT sa.*
FROM sessions_anonymous sa
JOIN disk_allocations da ON da.id = sa.allocation_id
WHERE sa.claimed_at IS NULL
  AND da.expires_at IS NOT NULL
  AND da.expires_at < now();

-- name: DeleteUnclaimedExpiredAnonymousAllocations :many
DELETE FROM disk_allocations
 WHERE user_id IS NULL
   AND expires_at IS NOT NULL
   AND created_at < now() - INTERVAL '5 hours'
   AND id IN (
       SELECT allocation_id FROM sessions_anonymous
        WHERE claimed_at IS NULL
   )
RETURNING id;

-- name: MarkAnonymousAllocationDeleted :one
UPDATE disk_allocations
   SET expires_at = now()
 WHERE id = $1
   AND user_id IS NULL
RETURNING *;
