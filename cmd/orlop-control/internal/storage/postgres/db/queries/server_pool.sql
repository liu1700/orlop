-- name: PickBestAvailableServer :one
SELECT * FROM server_pool
WHERE status = 'available' AND free_bytes >= $1
ORDER BY free_bytes DESC, data_addr
LIMIT 1;

-- name: ReserveCapacity :one
UPDATE server_pool
SET free_bytes = free_bytes - $1,
    updated_at = now()
WHERE id = $2
  AND status = 'available'
  AND free_bytes >= $1
RETURNING *;

-- name: ReleaseCapacity :one
UPDATE server_pool
SET free_bytes = LEAST(free_bytes + $1, total_bytes),
    updated_at = now()
WHERE id = $2
RETURNING *;

-- name: GetServerPoolByDataAddr :one
SELECT * FROM server_pool WHERE data_addr = $1;

-- name: UpsertServerPool :one
INSERT INTO server_pool (data_addr, ops_addr, total_bytes, free_bytes, status)
VALUES ($1, $2, $3, $4, COALESCE(NULLIF(sqlc.arg(status)::text, ''), 'available'))
ON CONFLICT (data_addr) DO UPDATE SET
    ops_addr = EXCLUDED.ops_addr,
    total_bytes = EXCLUDED.total_bytes,
    free_bytes = EXCLUDED.free_bytes,
    status = EXCLUDED.status,
    updated_at = now()
RETURNING *;

-- name: ReserveCapacityForGrowth :one
-- Like ReserveCapacity, but also permits a 'draining' server. A draining server
-- takes no NEW tenants (PickBestAvailableServer filters status='available'), yet
-- an existing resident must still be able to grow in place — otherwise elastic
-- growth would stall the moment a server crossed its high-water mark.
UPDATE server_pool
SET free_bytes = free_bytes - $1,
    updated_at = now()
WHERE id = $2
  AND status IN ('available', 'draining')
  AND free_bytes >= $1
RETURNING *;

-- name: ReconcileServerStatus :exec
-- Flip servers between 'available' and 'draining' based on a growth-headroom
-- buffer: a server with less than buffer_fraction of its capacity free is
-- 'draining' (no new placements, residents may still grow); one at/above the
-- buffer returns to 'available'. Operator-set 'unavailable' servers are left
-- untouched.
UPDATE server_pool
SET status = CASE
        WHEN free_bytes::float8 < total_bytes::float8 * sqlc.arg(buffer_fraction)::float8
        THEN 'draining' ELSE 'available' END,
    updated_at = now()
WHERE status IN ('available', 'draining');
