-- +goose Up
-- +goose StatementBegin
-- 0004_agent_disks.sql
-- Phase 1 of the orlop-agent ↔ orlop bridge (Path B): metadata-only
-- disk provisioning via /v1/entities. Spec: docs/design/agent-storage-bridge.md.
--
-- A orlop agent maps onto a disk allocation under its owner's per-user tenant.
-- agent_id is the one new dimension: it holds the orlop agent id (an opaque
-- TEXT to the dg) and keys the per-agent allocation. orlop agent ids are
-- globally unique, so the partial unique index is on agent_id alone — it
-- enforces at most one live (non-revoked) allocation per agent (the invariant
-- GetAllocationByAgent's single lookup relies on) and keeps provisioning
-- idempotent.
ALTER TABLE disk_allocations ADD COLUMN agent_id TEXT;

CREATE UNIQUE INDEX disk_allocations_agent_active_idx
  ON disk_allocations (agent_id)
  WHERE revoked_at IS NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS disk_allocations_agent_active_idx;
ALTER TABLE disk_allocations DROP COLUMN IF EXISTS agent_id;
-- +goose StatementEnd
