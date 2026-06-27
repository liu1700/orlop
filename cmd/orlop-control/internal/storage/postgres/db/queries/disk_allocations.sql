-- name: InsertAllocation :one
INSERT INTO disk_allocations (user_id, size_bytes)
VALUES ($1, $2)
RETURNING *;

-- name: UpsertAgentAllocation :one
-- Idempotent per-agent provisioning. The partial unique index
-- disk_allocations_agent_active_idx (agent_id) WHERE revoked_at IS NULL
-- guarantees at most one live allocation per agent (orlop agent ids are
-- globally unique), so the conflict target reuses that predicate — and it
-- matches GetAllocationByAgent's lookup-by-agent_id. On conflict we touch
-- user_id (a no-op update) purely so RETURNING yields the existing row. Returns
-- the allocation whose id is the caller's handle.
INSERT INTO disk_allocations (user_id, agent_id, tenant_id, size_bytes)
VALUES ($1, $2, $3, $4)
ON CONFLICT (agent_id) WHERE revoked_at IS NULL
DO UPDATE SET user_id = EXCLUDED.user_id
RETURNING *;

-- name: ReassignAgentAllocation :exec
-- Re-home an agent's live allocation to a new billing owner (the orlop side of
-- merging an anon trial's agent into an existing account). Only user_id changes;
-- tenant_id — the per-agent storage tenant — is untouched, so the data stays exactly
-- where it is. No quota gate: a merge is allowed even if it pushes the new owner over
-- their ceiling.
UPDATE disk_allocations SET user_id = $2
WHERE agent_id = $1 AND revoked_at IS NULL;

-- name: GetAllocationByAgent :one
-- Resolve an agent's live (non-revoked) allocation. agent_id is the orlop
-- agent id, a globally-unique UUID, so a lookup by agent_id alone resolves to
-- at most one live row.
SELECT * FROM disk_allocations
WHERE agent_id = $1 AND revoked_at IS NULL;

-- name: GetAllocation :one
SELECT * FROM disk_allocations WHERE id = $1;

-- name: ListAllocationsForUser :many
SELECT * FROM disk_allocations
WHERE user_id = $1 AND user_id IS NOT NULL AND revoked_at IS NULL
ORDER BY created_at DESC;

-- name: BindAllocation :one
UPDATE disk_allocations
   SET bound_agent_id = $3,
       bound_at       = now()
 WHERE id = $1
   AND user_id = $2
   AND revoked_at IS NULL
   AND bound_agent_id IS NULL
RETURNING *;

-- name: RevokeAllocation :one
UPDATE disk_allocations
   SET revoked_at = COALESCE(revoked_at, now())
 WHERE id = $1
   AND user_id = $2
RETURNING *;

-- name: UpdateAllocationSize :one
-- Raise (or lower) an allocation's hard size cap in place, preserving its id so the
-- control-plane's stored disk handle stays valid. Used by the entity disk PATCH path
-- to flip an anonymous agent's 128 MiB disk to the expandable registered size.
UPDATE disk_allocations
   SET size_bytes = $3
 WHERE id = $1
   AND user_id = $2
   AND revoked_at IS NULL
RETURNING *;

-- name: AcquireMountLease :one
-- An authorized mount unconditionally takes over the lease (only a revoked/missing
-- allocation fails). An allocation belongs to a single orlop agent, so any caller the
-- handler authorized (owning user + agent-scoped cert) IS that agent; a one-shot pod
-- re-mounts with a FRESH enrollment ($2 is an FK into agent_enrollments, so it changes
-- every turn) and must be able to take over the prior pod's lease — including one a
-- crashed/forcibly-killed pod leaked, without waiting out the TTL. Mount exclusivity is
-- enforced by the handler's ownership check + the data-plane agent cert, and the acquire
-- handler fences any stale server-side session so the new mount's hex is accepted.
UPDATE disk_allocations
   SET bound_agent_id   = $2,
       bound_at         = CASE WHEN bound_agent_id = $2 THEN bound_at ELSE now() END,
       lease_expires_at = now() + sqlc.arg(ttl)::interval
 WHERE id = $1
   AND revoked_at IS NULL
RETURNING *;

-- name: RefreshMountLease :one
UPDATE disk_allocations
   SET lease_expires_at = now() + sqlc.arg(ttl)::interval
 WHERE id = $1
   AND bound_agent_id = $2
   AND revoked_at IS NULL
   AND lease_expires_at IS NOT NULL
   AND lease_expires_at > now()
RETURNING *;

-- name: ReleaseMountLease :one
UPDATE disk_allocations
   SET bound_agent_id   = NULL,
       bound_at         = NULL,
       lease_expires_at = NULL
 WHERE id = $1
   AND (bound_agent_id = $2 OR bound_agent_id IS NULL)
RETURNING *;

-- name: ForceReleaseMountLease :one
UPDATE disk_allocations
   SET bound_agent_id   = NULL,
       bound_at         = NULL,
       lease_expires_at = NULL
 WHERE id = $1
   AND user_id = $2
   AND revoked_at IS NULL
RETURNING *;

-- name: ListGrowableAllocations :many
-- Active, placed, registered allocations that still have room to grow toward
-- their promised ceiling (users.quota_bytes). The storage autoscaler polls this
-- to decide which tenants to expand. Anonymous allocations (user_id IS NULL) are
-- excluded — they bypass server_pool and are ephemeral.
SELECT
    da.id          AS allocation_id,
    da.user_id     AS user_id,
    da.size_bytes  AS size_bytes,
    u.quota_bytes  AS ceiling_bytes,
    COALESCE(da.tenant_id, u.tenant_id) AS tenant_id,
    sp.ops_addr    AS ops_addr
FROM disk_allocations da
JOIN users u        ON u.id = da.user_id
JOIN server_vms sv  ON sv.tenant_id = COALESCE(da.tenant_id, u.tenant_id)
JOIN server_pool sp ON sp.data_addr = sv.data_addr
WHERE da.revoked_at IS NULL
  AND da.user_id IS NOT NULL
  AND da.size_bytes < u.quota_bytes;

-- name: MarkAllocationPurged :one
-- CAS-claim the purge of a revoked allocation: only one caller transitions
-- purged_at from NULL, so exactly one releases the pool reservation. Fails
-- (zero rows) when the allocation is not revoked yet or already purged.
UPDATE disk_allocations
   SET purged_at = now()
 WHERE id = $1
   AND revoked_at IS NOT NULL
   AND purged_at IS NULL
RETURNING *;

-- name: ListPurgePendingAllocations :many
-- The purge sweeper's work queue: revoked agent allocations whose backend
-- data has not been erased yet. LEFT JOINs the placement chain — an unplaced
-- tenant (never enrolled, ops_addr NULL) has no server-side data and is
-- marked purged without a data-plane call.
SELECT
    da.id          AS allocation_id,
    da.user_id     AS user_id,
    da.agent_id    AS agent_id,
    da.size_bytes  AS size_bytes,
    COALESCE(da.tenant_id, u.tenant_id) AS tenant_id,
    sp.ops_addr    AS ops_addr
FROM disk_allocations da
JOIN users u         ON u.id = da.user_id
LEFT JOIN server_vms sv  ON sv.tenant_id = COALESCE(da.tenant_id, u.tenant_id)
LEFT JOIN server_pool sp ON sp.data_addr = sv.data_addr
WHERE da.revoked_at IS NOT NULL
  AND da.purged_at IS NULL
  AND da.agent_id IS NOT NULL
  AND da.user_id IS NOT NULL
ORDER BY da.revoked_at ASC
LIMIT $1;

-- name: CountActiveAllocationsForUser :one
-- Live (non-revoked) allocations a user still has. The purge path uses this
-- to decide between a per-agent subtree purge (other agents share the tenant
-- dir) and a whole-tenant unregister (this was the last one).
SELECT count(*) FROM disk_allocations
WHERE user_id = $1 AND revoked_at IS NULL;
