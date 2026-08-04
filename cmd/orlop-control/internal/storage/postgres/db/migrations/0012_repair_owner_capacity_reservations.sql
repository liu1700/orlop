-- Repair the v0.5.2 owner-capacity backfill. Migration 0011 could not see an
-- allocation when its per-agent tenant had no server_vms row, so it omitted
-- the owner reservation and then overstated server_pool.free_bytes (#108).
--
-- Keep the placement join as the authoritative path. For an owner with no
-- surviving placement, the server can only be inferred safely when the
-- deployment has exactly one pool server. Refuse to report migration success
-- when a multi-server deployment still has ambiguous owners: guessing would
-- make the capacity ledger look valid while potentially debiting the wrong
-- server.

-- +goose Up
-- +goose StatementBegin
DO $$
DECLARE
    placed_rows bigint := 0;
    single_server_rows bigint := 0;
    unresolved_owners bigint := 0;
BEGIN
    -- Re-run the original placement-based backfill so this migration also
    -- repairs rows whose server_vms placement was restored after 0011 ran.
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
    GET DIAGNOSTICS placed_rows = ROW_COUNT;

    -- With one pool server there is no placement ambiguity. Backfill every
    -- still-unreserved owner that has evidence of a successful enrollment
    -- after one of its surviving allocations was provisioned. This avoids
    -- charging capacity for allocations that were provisioned but never
    -- enrolled; a successful enroll always records agent_enrollments only
    -- after Reserve has committed the owner debit.
    --
    -- Include allocations revoked but not yet purged because those bytes
    -- remain owned until purge reconciliation.
    INSERT INTO owner_capacity_reservations (user_id, server_id, size_bytes)
    SELECT da.user_id, only_server.id, MAX(da.size_bytes)
    FROM disk_allocations da
    CROSS JOIN (
        SELECT id
        FROM server_pool
        WHERE (SELECT COUNT(*) FROM server_pool) = 1
    ) only_server
    WHERE da.user_id IS NOT NULL
      AND da.purged_at IS NULL
      AND NOT EXISTS (
          SELECT 1
          FROM owner_capacity_reservations r
          WHERE r.user_id = da.user_id
      )
      AND EXISTS (
          SELECT 1
          FROM disk_allocations enrolled_da
          JOIN agent_enrollments ae
            ON ae.user_id = enrolled_da.user_id
           AND ae.enrolled_at >= enrolled_da.created_at
          WHERE enrolled_da.user_id = da.user_id
            AND enrolled_da.purged_at IS NULL
      )
    GROUP BY da.user_id, only_server.id
    ON CONFLICT (user_id, server_id) DO NOTHING;
    GET DIAGNOSTICS single_server_rows = ROW_COUNT;

    SELECT COUNT(*)
    INTO unresolved_owners
    FROM (
        SELECT DISTINCT da.user_id
        FROM disk_allocations da
        WHERE da.user_id IS NOT NULL
          AND da.purged_at IS NULL
          AND EXISTS (
              SELECT 1
              FROM disk_allocations enrolled_da
              JOIN agent_enrollments ae
                ON ae.user_id = enrolled_da.user_id
               AND ae.enrolled_at >= enrolled_da.created_at
              WHERE enrolled_da.user_id = da.user_id
                AND enrolled_da.purged_at IS NULL
          )
          AND NOT EXISTS (
              SELECT 1
              FROM owner_capacity_reservations r
              WHERE r.user_id = da.user_id
          )
    ) unresolved;

    RAISE NOTICE
        'owner-capacity repair: % placement rows, % single-server fallback rows, % unresolved owners',
        placed_rows, single_server_rows, unresolved_owners;

    IF unresolved_owners > 0 THEN
        RAISE EXCEPTION USING MESSAGE = format(
            'owner-capacity repair cannot infer server placement for %s owner(s); restore their server_vms rows or create matching owner_capacity_reservations, then rerun migrate up',
            unresolved_owners
        );
    END IF;
END $$;
-- +goose StatementEnd

-- free_bytes is derived state. Rebuild every pool row after the repair so an
-- already-migrated v0.5.2 deployment immediately gets a truthful gauge.
UPDATE server_pool sp
SET free_bytes = GREATEST(0, sp.total_bytes - COALESCE((
        SELECT SUM(r.size_bytes)
        FROM owner_capacity_reservations r
        WHERE r.server_id = sp.id
    ), 0)),
    updated_at = now();

-- +goose Down
-- Data repair is intentionally irreversible; removing valid reservations
-- would recreate the accounting bug.
SELECT 1;
