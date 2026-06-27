-- Squashed baseline schema for the orlop control plane.
-- Consolidates the incremental 0001-0012 migrations (including the
-- email-OTP self-service login removed in #9) into one clean schema.
-- goose applies this to a fresh database; sqlc reads it for codegen.

-- +goose Up
CREATE TABLE access_tokens (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    token_hash text NOT NULL,
    purpose text NOT NULL,
    user_id uuid NOT NULL,
    tenant_id text NOT NULL,
    allocation_id uuid,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    consumed_at timestamp with time zone
);
CREATE TABLE agent_enrollments (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    cert_serial text NOT NULL,
    cert_not_after timestamp with time zone NOT NULL,
    enrolled_at timestamp with time zone DEFAULT now() NOT NULL
);
CREATE TABLE api_tokens (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    name text NOT NULL,
    token_hash text NOT NULL,
    prefix text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_used_at timestamp with time zone,
    revoked_at timestamp with time zone,
    expires_at timestamp with time zone
);
CREATE TABLE cert_revocations (
    cert_serial text NOT NULL,
    tenant_id text DEFAULT ''::text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    reason text DEFAULT ''::text NOT NULL,
    revoked_at timestamp with time zone DEFAULT now() NOT NULL
);
CREATE TABLE device_authorizations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    device_code_hash text NOT NULL,
    user_code_hash text NOT NULL,
    tenant_id text,
    user_id uuid,
    allocation_id uuid,
    status text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    approved_at timestamp with time zone,
    last_polled_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);
CREATE TABLE dg_ca_secrets (
    key text NOT NULL,
    value bytea NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);
CREATE TABLE disk_allocations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid,
    size_bytes bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at timestamp with time zone,
    bound_agent_id uuid,
    bound_at timestamp with time zone,
    lease_expires_at timestamp with time zone,
    expires_at timestamp with time zone,
    agent_id text,
    purged_at timestamp with time zone,
    tenant_id text,
    CONSTRAINT disk_allocations_lease_requires_binding CHECK ((((bound_agent_id IS NULL) AND (bound_at IS NULL) AND (lease_expires_at IS NULL)) OR ((bound_agent_id IS NOT NULL) AND (bound_at IS NOT NULL)))),
    CONSTRAINT disk_allocations_size_bytes_check CHECK ((size_bytes > 0))
);
CREATE TABLE refresh_tokens (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    token_hash text NOT NULL,
    family_id uuid NOT NULL,
    user_id uuid NOT NULL,
    tenant_id text NOT NULL,
    allocation_id uuid,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    rotated_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);
CREATE TABLE server_pool (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    data_addr text NOT NULL,
    ops_addr text NOT NULL,
    total_bytes bigint NOT NULL,
    free_bytes bigint NOT NULL,
    status text DEFAULT 'available'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT server_pool_check CHECK (((free_bytes >= 0) AND (free_bytes <= total_bytes))),
    CONSTRAINT server_pool_status_check CHECK ((status = ANY (ARRAY['available'::text, 'draining'::text, 'unavailable'::text]))),
    CONSTRAINT server_pool_total_bytes_check CHECK ((total_bytes > 0))
);
CREATE TABLE server_vms (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id text NOT NULL,
    data_addr text NOT NULL,
    provisioned_at timestamp with time zone,
    status text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);
CREATE TABLE sessions_anonymous (
    session_id text NOT NULL,
    allocation_id uuid NOT NULL,
    device_id text NOT NULL,
    cert_serial text NOT NULL,
    spawner_url text NOT NULL,
    ip_address inet NOT NULL,
    user_agent text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    claimed_at timestamp with time zone,
    claimed_by uuid
);
CREATE TABLE tenants (
    id text NOT NULL,
    name text NOT NULL,
    suspended_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);
CREATE TABLE users (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    email text NOT NULL,
    tenant_id text NOT NULL,
    role text DEFAULT 'admin'::text NOT NULL,
    suspended_at timestamp with time zone,
    quota_bytes bigint DEFAULT '10737418240'::bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);
ALTER TABLE ONLY access_tokens
    ADD CONSTRAINT access_tokens_pkey PRIMARY KEY (id);
ALTER TABLE ONLY access_tokens
    ADD CONSTRAINT access_tokens_token_hash_key UNIQUE (token_hash);
ALTER TABLE ONLY agent_enrollments
    ADD CONSTRAINT agent_enrollments_pkey PRIMARY KEY (id);
ALTER TABLE ONLY api_tokens
    ADD CONSTRAINT api_tokens_pkey PRIMARY KEY (id);
ALTER TABLE ONLY cert_revocations
    ADD CONSTRAINT cert_revocations_pkey PRIMARY KEY (cert_serial);
ALTER TABLE ONLY device_authorizations
    ADD CONSTRAINT device_authorizations_device_code_hash_key UNIQUE (device_code_hash);
ALTER TABLE ONLY device_authorizations
    ADD CONSTRAINT device_authorizations_pkey PRIMARY KEY (id);
ALTER TABLE ONLY device_authorizations
    ADD CONSTRAINT device_authorizations_user_code_hash_key UNIQUE (user_code_hash);
ALTER TABLE ONLY dg_ca_secrets
    ADD CONSTRAINT dg_ca_secrets_pkey PRIMARY KEY (key);
ALTER TABLE ONLY disk_allocations
    ADD CONSTRAINT disk_allocations_pkey PRIMARY KEY (id);
ALTER TABLE ONLY refresh_tokens
    ADD CONSTRAINT refresh_tokens_pkey PRIMARY KEY (id);
ALTER TABLE ONLY refresh_tokens
    ADD CONSTRAINT refresh_tokens_token_hash_key UNIQUE (token_hash);
ALTER TABLE ONLY server_pool
    ADD CONSTRAINT server_pool_data_addr_key UNIQUE (data_addr);
ALTER TABLE ONLY server_pool
    ADD CONSTRAINT server_pool_ops_addr_key UNIQUE (ops_addr);
ALTER TABLE ONLY server_pool
    ADD CONSTRAINT server_pool_pkey PRIMARY KEY (id);
ALTER TABLE ONLY server_vms
    ADD CONSTRAINT server_vms_pkey PRIMARY KEY (id);
ALTER TABLE ONLY server_vms
    ADD CONSTRAINT server_vms_tenant_id_key UNIQUE (tenant_id);
ALTER TABLE ONLY sessions_anonymous
    ADD CONSTRAINT sessions_anonymous_pkey PRIMARY KEY (session_id);
ALTER TABLE ONLY tenants
    ADD CONSTRAINT tenants_pkey PRIMARY KEY (id);
ALTER TABLE ONLY users
    ADD CONSTRAINT users_email_key UNIQUE (email);
ALTER TABLE ONLY users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);
CREATE INDEX access_tokens_purpose_user_id_idx ON access_tokens USING btree (purpose, user_id);
CREATE INDEX agent_enrollments_not_after_idx ON agent_enrollments USING btree (cert_not_after);
CREATE INDEX agent_enrollments_user_id_idx ON agent_enrollments USING btree (user_id);
CREATE UNIQUE INDEX api_tokens_token_hash_idx ON api_tokens USING btree (token_hash);
CREATE INDEX api_tokens_user_id_active_idx ON api_tokens USING btree (user_id) WHERE (revoked_at IS NULL);
CREATE INDEX cert_revocations_expires_at_idx ON cert_revocations USING btree (expires_at);
CREATE INDEX device_authorizations_status_idx ON device_authorizations USING btree (status);
CREATE UNIQUE INDEX disk_allocations_agent_active_idx ON disk_allocations USING btree (agent_id) WHERE (revoked_at IS NULL);
CREATE INDEX disk_allocations_bound_agent_idx ON disk_allocations USING btree (bound_agent_id) WHERE (bound_agent_id IS NOT NULL);
CREATE INDEX disk_allocations_expires_at_idx ON disk_allocations USING btree (expires_at) WHERE (expires_at IS NOT NULL);
CREATE INDEX disk_allocations_purge_pending_idx ON disk_allocations USING btree (revoked_at) WHERE ((revoked_at IS NOT NULL) AND (purged_at IS NULL));
CREATE INDEX disk_allocations_tenant_id_idx ON disk_allocations USING btree (tenant_id);
CREATE INDEX disk_allocations_user_active_idx ON disk_allocations USING btree (user_id) WHERE (revoked_at IS NULL);
CREATE INDEX refresh_tokens_family_id_idx ON refresh_tokens USING btree (family_id);
CREATE INDEX refresh_tokens_user_id_idx ON refresh_tokens USING btree (user_id);
CREATE INDEX server_pool_available_idx ON server_pool USING btree (free_bytes DESC) WHERE (status = 'available'::text);
CREATE INDEX sessions_anonymous_created_at_idx ON sessions_anonymous USING btree (created_at) WHERE (claimed_at IS NULL);
CREATE INDEX sessions_anonymous_device_unclaimed_idx ON sessions_anonymous USING btree (device_id, created_at DESC) WHERE (claimed_at IS NULL);
CREATE INDEX users_tenant_id_idx ON users USING btree (tenant_id);
ALTER TABLE ONLY access_tokens
    ADD CONSTRAINT access_tokens_allocation_id_fkey FOREIGN KEY (allocation_id) REFERENCES disk_allocations(id) ON DELETE RESTRICT;
ALTER TABLE ONLY access_tokens
    ADD CONSTRAINT access_tokens_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT;
ALTER TABLE ONLY access_tokens
    ADD CONSTRAINT access_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT;
ALTER TABLE ONLY agent_enrollments
    ADD CONSTRAINT agent_enrollments_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT;
ALTER TABLE ONLY api_tokens
    ADD CONSTRAINT api_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE ONLY device_authorizations
    ADD CONSTRAINT device_authorizations_allocation_id_fkey FOREIGN KEY (allocation_id) REFERENCES disk_allocations(id) ON DELETE RESTRICT;
ALTER TABLE ONLY device_authorizations
    ADD CONSTRAINT device_authorizations_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT;
ALTER TABLE ONLY device_authorizations
    ADD CONSTRAINT device_authorizations_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT;
ALTER TABLE ONLY disk_allocations
    ADD CONSTRAINT disk_allocations_bound_agent_id_fkey FOREIGN KEY (bound_agent_id) REFERENCES agent_enrollments(id) ON DELETE SET NULL;
ALTER TABLE ONLY disk_allocations
    ADD CONSTRAINT disk_allocations_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE ONLY disk_allocations
    ADD CONSTRAINT disk_allocations_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE ONLY refresh_tokens
    ADD CONSTRAINT refresh_tokens_allocation_id_fkey FOREIGN KEY (allocation_id) REFERENCES disk_allocations(id) ON DELETE RESTRICT;
ALTER TABLE ONLY refresh_tokens
    ADD CONSTRAINT refresh_tokens_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT;
ALTER TABLE ONLY refresh_tokens
    ADD CONSTRAINT refresh_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT;
ALTER TABLE ONLY server_vms
    ADD CONSTRAINT server_vms_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT;
ALTER TABLE ONLY sessions_anonymous
    ADD CONSTRAINT sessions_anonymous_allocation_id_fkey FOREIGN KEY (allocation_id) REFERENCES disk_allocations(id) ON DELETE CASCADE;
ALTER TABLE ONLY sessions_anonymous
    ADD CONSTRAINT sessions_anonymous_claimed_by_fkey FOREIGN KEY (claimed_by) REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE ONLY users
    ADD CONSTRAINT users_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT;

-- +goose Down
DROP TABLE IF EXISTS access_tokens CASCADE;
DROP TABLE IF EXISTS agent_enrollments CASCADE;
DROP TABLE IF EXISTS api_tokens CASCADE;
DROP TABLE IF EXISTS cert_revocations CASCADE;
DROP TABLE IF EXISTS device_authorizations CASCADE;
DROP TABLE IF EXISTS dg_ca_secrets CASCADE;
DROP TABLE IF EXISTS disk_allocations CASCADE;
DROP TABLE IF EXISTS refresh_tokens CASCADE;
DROP TABLE IF EXISTS server_pool CASCADE;
DROP TABLE IF EXISTS server_vms CASCADE;
DROP TABLE IF EXISTS sessions_anonymous CASCADE;
DROP TABLE IF EXISTS tenants CASCADE;
DROP TABLE IF EXISTS users CASCADE;
