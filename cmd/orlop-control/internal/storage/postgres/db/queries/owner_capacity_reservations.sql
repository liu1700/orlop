-- name: ListOwnerCapacityReservations :many
SELECT r.user_id, r.server_id, r.size_bytes, sp.data_addr, sp.ops_addr
FROM owner_capacity_reservations r
JOIN server_pool sp ON sp.id = r.server_id
WHERE r.user_id = $1
ORDER BY r.created_at, r.server_id;

-- name: CreateOwnerCapacityReservation :exec
INSERT INTO owner_capacity_reservations (user_id, server_id, size_bytes)
VALUES ($1, $2, $3);

-- name: DeleteOwnerCapacityReservation :execrows
DELETE FROM owner_capacity_reservations
WHERE user_id = $1 AND server_id = $2;

-- name: UpdateOwnerCapacityReservationSize :exec
UPDATE owner_capacity_reservations
SET size_bytes = $3
WHERE user_id = $1 AND server_id = $2;

-- name: CountPlacedAllocationsForUserOnServer :one
SELECT count(DISTINCT sv.tenant_id)
FROM disk_allocations da
JOIN users u ON u.id = da.user_id
JOIN server_vms sv ON sv.tenant_id = COALESCE(da.tenant_id, u.tenant_id)
WHERE da.user_id = $1
  AND da.purged_at IS NULL
  AND sv.data_addr = $2;
