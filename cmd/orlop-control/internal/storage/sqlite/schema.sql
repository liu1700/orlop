-- SQLite schema for the orlop control plane — the embedded single-node backend.
--
-- Mirrors the Postgres baseline (internal/storage/postgres/db/migrations) at the
-- domain level, adapted to SQLite's type affinities:
--   * uuid        -> TEXT  (lowercase canonical, set in Go)
--   * timestamptz -> INTEGER (Unix microseconds, UTC, set in Go — never a SQL
--                    default, so ordering and "now" comparisons stay exact)
--   * bigint      -> INTEGER
--   * bytea       -> BLOB
--   * inet        -> TEXT
-- IDs are generated in Go (no gen_random_uuid()); created_at is set in Go.
-- Applied idempotently on Open via CREATE ... IF NOT EXISTS.

CREATE TABLE IF NOT EXISTS tenants (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    suspended_at INTEGER,
    created_at   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id           TEXT PRIMARY KEY,
    email        TEXT NOT NULL UNIQUE,
    tenant_id    TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    role         TEXT NOT NULL DEFAULT 'admin',
    suspended_at INTEGER,
    quota_bytes  INTEGER NOT NULL DEFAULT 10737418240,
    created_at   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS users_tenant_id_idx ON users (tenant_id);

CREATE TABLE IF NOT EXISTS disk_allocations (
    id               TEXT PRIMARY KEY,
    user_id          TEXT REFERENCES users(id) ON DELETE CASCADE,
    size_bytes       INTEGER NOT NULL CHECK (size_bytes > 0),
    created_at       INTEGER NOT NULL,
    revoked_at       INTEGER,
    bound_agent_id   TEXT,
    bound_at         INTEGER,
    lease_expires_at INTEGER,
    expires_at       INTEGER,
    agent_id         TEXT,
    purged_at        INTEGER,
    tenant_id        TEXT REFERENCES tenants(id),
    CHECK (((bound_agent_id IS NULL) AND (bound_at IS NULL) AND (lease_expires_at IS NULL))
        OR ((bound_agent_id IS NOT NULL) AND (bound_at IS NOT NULL)))
);
CREATE UNIQUE INDEX IF NOT EXISTS disk_allocations_agent_active_idx ON disk_allocations (agent_id) WHERE (revoked_at IS NULL);
CREATE INDEX IF NOT EXISTS disk_allocations_bound_agent_idx ON disk_allocations (bound_agent_id) WHERE (bound_agent_id IS NOT NULL);
CREATE INDEX IF NOT EXISTS disk_allocations_expires_at_idx ON disk_allocations (expires_at) WHERE (expires_at IS NOT NULL);
CREATE INDEX IF NOT EXISTS disk_allocations_purge_pending_idx ON disk_allocations (revoked_at) WHERE ((revoked_at IS NOT NULL) AND (purged_at IS NULL));
CREATE INDEX IF NOT EXISTS disk_allocations_tenant_id_idx ON disk_allocations (tenant_id);
CREATE INDEX IF NOT EXISTS disk_allocations_user_active_idx ON disk_allocations (user_id) WHERE (revoked_at IS NULL);

CREATE TABLE IF NOT EXISTS agent_enrollments (
    id             TEXT PRIMARY KEY,
    user_id        TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    cert_serial    TEXT NOT NULL,
    cert_not_after INTEGER NOT NULL,
    enrolled_at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS agent_enrollments_not_after_idx ON agent_enrollments (cert_not_after);
CREATE INDEX IF NOT EXISTS agent_enrollments_user_id_idx ON agent_enrollments (user_id);

-- bound_agent_id references agent_enrollments(id); added after both tables exist.
CREATE INDEX IF NOT EXISTS disk_allocations_bound_agent_fk_idx ON disk_allocations (bound_agent_id);

CREATE TABLE IF NOT EXISTS access_tokens (
    id            TEXT PRIMARY KEY,
    token_hash    TEXT NOT NULL UNIQUE,
    purpose       TEXT NOT NULL,
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    tenant_id     TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    allocation_id TEXT REFERENCES disk_allocations(id) ON DELETE RESTRICT,
    expires_at    INTEGER NOT NULL,
    revoked_at    INTEGER,
    created_at    INTEGER NOT NULL,
    consumed_at   INTEGER
);
CREATE INDEX IF NOT EXISTS access_tokens_purpose_user_id_idx ON access_tokens (purpose, user_id);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id            TEXT PRIMARY KEY,
    token_hash    TEXT NOT NULL UNIQUE,
    family_id     TEXT NOT NULL,
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    tenant_id     TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    allocation_id TEXT REFERENCES disk_allocations(id) ON DELETE RESTRICT,
    expires_at    INTEGER NOT NULL,
    revoked_at    INTEGER,
    rotated_at    INTEGER,
    created_at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS refresh_tokens_family_id_idx ON refresh_tokens (family_id);
CREATE INDEX IF NOT EXISTS refresh_tokens_user_id_idx ON refresh_tokens (user_id);

CREATE TABLE IF NOT EXISTS api_tokens (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    token_hash   TEXT NOT NULL,
    prefix       TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER,
    revoked_at   INTEGER,
    expires_at   INTEGER
);
CREATE UNIQUE INDEX IF NOT EXISTS api_tokens_token_hash_idx ON api_tokens (token_hash);
CREATE INDEX IF NOT EXISTS api_tokens_user_id_active_idx ON api_tokens (user_id) WHERE (revoked_at IS NULL);

CREATE TABLE IF NOT EXISTS device_authorizations (
    id               TEXT PRIMARY KEY,
    device_code_hash TEXT NOT NULL UNIQUE,
    user_code_hash   TEXT NOT NULL UNIQUE,
    tenant_id        TEXT REFERENCES tenants(id) ON DELETE RESTRICT,
    user_id          TEXT REFERENCES users(id) ON DELETE RESTRICT,
    allocation_id    TEXT REFERENCES disk_allocations(id) ON DELETE RESTRICT,
    status           TEXT NOT NULL,
    expires_at       INTEGER NOT NULL,
    approved_at      INTEGER,
    last_polled_at   INTEGER,
    created_at       INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS device_authorizations_status_idx ON device_authorizations (status);

CREATE TABLE IF NOT EXISTS cert_revocations (
    cert_serial TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL DEFAULT '',
    expires_at  INTEGER NOT NULL,
    reason      TEXT NOT NULL DEFAULT '',
    revoked_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS cert_revocations_expires_at_idx ON cert_revocations (expires_at);

CREATE TABLE IF NOT EXISTS server_pool (
    id          TEXT PRIMARY KEY,
    data_addr   TEXT NOT NULL UNIQUE,
    ops_addr    TEXT NOT NULL UNIQUE,
    total_bytes INTEGER NOT NULL CHECK (total_bytes > 0),
    free_bytes  INTEGER NOT NULL,
    status      TEXT NOT NULL DEFAULT 'available',
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL,
    CHECK ((free_bytes >= 0) AND (free_bytes <= total_bytes)),
    CHECK (status IN ('available', 'draining', 'unavailable'))
);
CREATE INDEX IF NOT EXISTS server_pool_available_idx ON server_pool (free_bytes DESC) WHERE (status = 'available');

CREATE TABLE IF NOT EXISTS server_vms (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL UNIQUE REFERENCES tenants(id) ON DELETE RESTRICT,
    data_addr       TEXT NOT NULL,
    provisioned_at  INTEGER,
    status          TEXT NOT NULL,
    created_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS dg_ca_secrets (
    key        TEXT PRIMARY KEY,
    value      BLOB NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions_anonymous (
    session_id    TEXT PRIMARY KEY,
    allocation_id TEXT NOT NULL REFERENCES disk_allocations(id) ON DELETE CASCADE,
    device_id     TEXT NOT NULL,
    cert_serial   TEXT NOT NULL,
    spawner_url   TEXT NOT NULL,
    ip_address    TEXT NOT NULL,
    user_agent    TEXT NOT NULL DEFAULT '',
    created_at    INTEGER NOT NULL,
    claimed_at    INTEGER,
    claimed_by    TEXT REFERENCES users(id) ON DELETE SET NULL
);
