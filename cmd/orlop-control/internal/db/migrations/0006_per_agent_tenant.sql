-- +goose Up
-- +goose StatementBegin
-- Per-agent storage tenants (docs/design/per-agent-tenant.md). Each agent's disk
-- now lives in its OWN tenant (a_<agentID>) instead of its owner's shared per-user
-- tenant, so re-homing an agent to a different billing owner is a user_id flip with
-- no data move. tenant_id records that per-agent tenant on the allocation; every
-- placement/usage/purge path keys on COALESCE(da.tenant_id, u.tenant_id) so a legacy
-- allocation without a per-agent tenant (the non-agent OAuth disk path) still resolves
-- to the user's tenant. Re-parenting changes user_id only; tenant_id is left alone.
ALTER TABLE disk_allocations ADD COLUMN tenant_id TEXT REFERENCES tenants(id);
CREATE INDEX disk_allocations_tenant_id_idx ON disk_allocations(tenant_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS disk_allocations_tenant_id_idx;
ALTER TABLE disk_allocations DROP COLUMN IF EXISTS tenant_id;
-- +goose StatementEnd
