-- +goose Up
-- +goose StatementBegin
CREATE TABLE tenants (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    suspended_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email        TEXT NOT NULL UNIQUE,
    tenant_id    TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    role         TEXT NOT NULL DEFAULT 'admin',
    suspended_at TIMESTAMPTZ,
    quota_bytes  BIGINT NOT NULL DEFAULT 10737418240,  -- 10 GiB
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX users_tenant_id_idx ON users(tenant_id);

CREATE TABLE agent_enrollments (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    cert_serial    TEXT NOT NULL,
    cert_not_after TIMESTAMPTZ NOT NULL,
    enrolled_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX agent_enrollments_user_id_idx   ON agent_enrollments(user_id);
CREATE INDEX agent_enrollments_not_after_idx ON agent_enrollments(cert_not_after);

CREATE TABLE disk_allocations (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    size_bytes          BIGINT NOT NULL CHECK (size_bytes > 0),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at          TIMESTAMPTZ,
    bound_agent_id      UUID REFERENCES agent_enrollments(id) ON DELETE SET NULL,
    bound_at            TIMESTAMPTZ,
    lease_expires_at    TIMESTAMPTZ,
    CONSTRAINT disk_allocations_lease_requires_binding CHECK (
        (bound_agent_id IS NULL AND bound_at IS NULL AND lease_expires_at IS NULL)
        OR
        (bound_agent_id IS NOT NULL AND bound_at IS NOT NULL)
    )
);
CREATE INDEX disk_allocations_user_active_idx
  ON disk_allocations (user_id) WHERE revoked_at IS NULL;
CREATE INDEX disk_allocations_bound_agent_idx
  ON disk_allocations (bound_agent_id) WHERE bound_agent_id IS NOT NULL;

CREATE TABLE device_authorizations (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_code_hash  TEXT NOT NULL UNIQUE,
    user_code_hash    TEXT NOT NULL UNIQUE,
    tenant_id         TEXT REFERENCES tenants(id) ON DELETE RESTRICT,
    user_id           UUID REFERENCES users(id) ON DELETE RESTRICT,
    allocation_id     UUID REFERENCES disk_allocations(id) ON DELETE RESTRICT,
    status            TEXT NOT NULL,
    expires_at        TIMESTAMPTZ NOT NULL,
    approved_at       TIMESTAMPTZ,
    last_polled_at    TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX device_authorizations_status_idx ON device_authorizations(status);

CREATE TABLE access_tokens (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash     TEXT NOT NULL UNIQUE,
    purpose        TEXT NOT NULL,
    user_id        UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    tenant_id      TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    allocation_id  UUID REFERENCES disk_allocations(id) ON DELETE RESTRICT,
    expires_at     TIMESTAMPTZ NOT NULL,
    revoked_at     TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX access_tokens_purpose_user_id_idx ON access_tokens(purpose, user_id);

CREATE TABLE refresh_tokens (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash     TEXT NOT NULL UNIQUE,
    family_id      UUID NOT NULL,
    user_id        UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    tenant_id      TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    allocation_id  UUID REFERENCES disk_allocations(id) ON DELETE RESTRICT,
    expires_at     TIMESTAMPTZ NOT NULL,
    revoked_at     TIMESTAMPTZ,
    rotated_at     TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX refresh_tokens_family_id_idx ON refresh_tokens(family_id);
CREATE INDEX refresh_tokens_user_id_idx   ON refresh_tokens(user_id);

CREATE TABLE email_otps (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email       TEXT NOT NULL,
    code_hash   TEXT NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX email_otps_email_created_at_idx ON email_otps (email, created_at DESC);

-- A pool entry represents one orlop-server. data_addr is where FUSE clients
-- connect (mTLS data plane). ops_addr is where the control plane sends
-- control RPCs (e.g. /control/tenants) and operators read /audit, /healthz.
CREATE TABLE server_pool (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    data_addr   TEXT NOT NULL UNIQUE,
    ops_addr    TEXT NOT NULL UNIQUE,
    total_bytes BIGINT NOT NULL CHECK (total_bytes > 0),
    free_bytes  BIGINT NOT NULL CHECK (free_bytes >= 0 AND free_bytes <= total_bytes),
    status      TEXT NOT NULL DEFAULT 'available'
                CHECK (status IN ('available', 'draining', 'unavailable')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX server_pool_available_idx
  ON server_pool (free_bytes DESC) WHERE status = 'available';

-- Snapshot of tenant→server placement. data_addr is what the client uses;
-- it's a snapshot of server_pool.data_addr at allocation time.
CREATE TABLE server_vms (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      TEXT NOT NULL UNIQUE REFERENCES tenants(id) ON DELETE RESTRICT,
    data_addr      TEXT NOT NULL,
    provisioned_at TIMESTAMPTZ,
    status         TEXT NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS server_vms;
DROP TABLE IF EXISTS server_pool;
DROP TABLE IF EXISTS email_otps;
DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS access_tokens;
DROP TABLE IF EXISTS device_authorizations;
DROP TABLE IF EXISTS disk_allocations;
DROP TABLE IF EXISTS agent_enrollments;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS tenants;
-- +goose StatementEnd
