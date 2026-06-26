-- +goose Up
-- +goose StatementBegin
-- 0005_allocation_purge.sql
-- Revoke (revoked_at) is a metadata-only soft delete: the agent's bytes stay
-- on the orlop-server until someone erases them. purged_at records that
-- the backend data was actually erased (per-agent subtree purge, or whole-
-- tenant unregister when it was the user's last allocation) and the pool
-- reservation released. revoked_at IS NOT NULL AND purged_at IS NULL is the
-- purge sweeper's work queue.
ALTER TABLE disk_allocations ADD COLUMN purged_at TIMESTAMPTZ;

CREATE INDEX disk_allocations_purge_pending_idx
  ON disk_allocations (revoked_at)
  WHERE revoked_at IS NOT NULL AND purged_at IS NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS disk_allocations_purge_pending_idx;
ALTER TABLE disk_allocations DROP COLUMN IF EXISTS purged_at;
-- +goose StatementEnd
