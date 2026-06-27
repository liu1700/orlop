-- name: CreateServerVM :one
INSERT INTO server_vms (tenant_id, data_addr, status)
VALUES ($1, $2, $3)
RETURNING *;

-- name: GetServerVMByTenant :one
SELECT * FROM server_vms WHERE tenant_id = $1;

-- name: MarkServerVMProvisioned :one
UPDATE server_vms
SET provisioned_at = now(), status = $2
WHERE tenant_id = $1
RETURNING *;

-- name: DeleteServerVM :execrows
-- Remove a tenant's placement after its data-plane tenant was unregistered
-- (last-allocation purge). The next enroll for this tenant re-Reserves a
-- placement from the pool.
DELETE FROM server_vms WHERE tenant_id = $1;
