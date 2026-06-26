-- +goose Up
-- +goose StatementBegin
-- 0003_anonymous_sandbox.sql
-- Phase 2: anonymous Try-it sandbox.
-- Spec: an internal design spec

-- 1. Make disk_allocations.user_id nullable so anonymous allocations
--    have owner_id = NULL until claimed.
ALTER TABLE disk_allocations
  ALTER COLUMN user_id DROP NOT NULL;

-- 2. Add expires_at column. Owned allocations leave it NULL.
--    Anonymous allocations set it to now()+5min; the sweeper deletes the
--    row once both expires_at is past AND nothing has claimed it within 5h.
--
--    Note: this is distinct from the pre-existing lease_expires_at column.
--    lease_expires_at tracks mount-lease renewals for the local-mount surface
--    (set by the CLI when it connects; cleared on disconnect). expires_at
--    tracks the anonymous-sandbox TTL and is only set for anonymous allocations
--    (user_id IS NULL). The two columns model orthogonal lifetimes: a named
--    user's allocation never has expires_at set; an anonymous allocation never
--    uses lease_expires_at.
ALTER TABLE disk_allocations
  ADD COLUMN expires_at TIMESTAMPTZ;

CREATE INDEX disk_allocations_expires_at_idx
  ON disk_allocations (expires_at)
  WHERE expires_at IS NOT NULL;

-- 3. Anonymous tenant. Real tenant on orlop-server; mTLS isolated.
INSERT INTO tenants (id, name) VALUES ('tenant_anonymous', 'Anonymous sandboxes')
ON CONFLICT (id) DO NOTHING;

-- 4. sessions_anonymous: source of truth for "which device created which
--    allocation, when, and has it been claimed". One row per anonymous
--    POST /api/v1/anonymous-session call. claimed_at = NULL while open.
CREATE TABLE sessions_anonymous (
    session_id     TEXT PRIMARY KEY,            -- base32, 16-byte payload
    allocation_id  UUID NOT NULL REFERENCES disk_allocations(id) ON DELETE CASCADE,
    device_id      TEXT NOT NULL,               -- UUIDv4 from localStorage
    cert_serial    TEXT NOT NULL,               -- so sweeper can revoke
    spawner_url    TEXT NOT NULL,               -- so claim/delete can call back
    ip_address     INET NOT NULL,               -- for rate limiting + audit
    user_agent     TEXT NOT NULL DEFAULT '',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    claimed_at     TIMESTAMPTZ,
    claimed_by     UUID REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX sessions_anonymous_device_unclaimed_idx
  ON sessions_anonymous (device_id, created_at DESC)
  WHERE claimed_at IS NULL;
CREATE INDEX sessions_anonymous_created_at_idx
  ON sessions_anonymous (created_at)
  WHERE claimed_at IS NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS sessions_anonymous_created_at_idx;
DROP INDEX IF EXISTS sessions_anonymous_device_unclaimed_idx;
DROP TABLE IF EXISTS sessions_anonymous;
DELETE FROM tenants WHERE id = 'tenant_anonymous';
DROP INDEX IF EXISTS disk_allocations_expires_at_idx;
ALTER TABLE disk_allocations DROP COLUMN IF EXISTS expires_at;
ALTER TABLE disk_allocations ALTER COLUMN user_id SET NOT NULL;
-- +goose StatementEnd
