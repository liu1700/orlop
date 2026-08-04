-- Track pool capacity once per account and hosting server, instead of once per
-- agent allocation. The data plane applies the disk budget to the shared owner
-- directory, so this is the durable record of the capacity that quota can use.

-- +goose Up
CREATE TABLE IF NOT EXISTS owner_capacity_reservations (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    server_id uuid NOT NULL REFERENCES server_pool(id) ON DELETE CASCADE,
    size_bytes bigint NOT NULL CHECK (size_bytes > 0),
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    PRIMARY KEY (user_id, server_id)
);

-- Backfill one reservation per existing owner/server pair. Include revoked but
-- not-yet-purged allocations: their placement still owns capacity until the
-- purge reconciliation removes it.
INSERT INTO owner_capacity_reservations (user_id, server_id, size_bytes)
SELECT da.user_id, sp.id, MAX(da.size_bytes)
FROM disk_allocations da
JOIN users u ON u.id = da.user_id
JOIN server_vms sv ON sv.tenant_id = COALESCE(da.tenant_id, u.tenant_id)
JOIN server_pool sp ON sp.data_addr = sv.data_addr
WHERE da.user_id IS NOT NULL
  AND da.purged_at IS NULL
GROUP BY da.user_id, sp.id
ON CONFLICT (user_id, server_id) DO NOTHING;

-- Legacy releases debited the whole account budget once per agent. Rebuild the
-- pool's derived free capacity from the new reservation ledger so an upgrade
-- repairs existing over-reservation immediately and idempotently.
WITH reserved AS (
    SELECT server_id, SUM(size_bytes) AS bytes
    FROM owner_capacity_reservations
    GROUP BY server_id
)
UPDATE server_pool sp
SET free_bytes = GREATEST(0, sp.total_bytes - COALESCE(r.bytes, 0)),
    updated_at = now()
FROM reserved r
WHERE r.server_id = sp.id;

UPDATE server_pool sp
SET free_bytes = sp.total_bytes,
    updated_at = now()
WHERE NOT EXISTS (
    SELECT 1 FROM owner_capacity_reservations r WHERE r.server_id = sp.id
);

-- +goose Down
DROP TABLE IF EXISTS owner_capacity_reservations;
