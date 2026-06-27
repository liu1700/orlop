-- Bridge migration for databases provisioned by the pre-squash v0.1.x line.
--
-- The squashed baseline (0001_init, #23) reset goose numbering to version 1, but
-- a database migrated by v0.1.0 is already at goose version 9 (from its original
-- 0001-0009 files). goose only applies versions greater than the current max, so
-- on those databases it skips the squashed baseline entirely -- leaving them
-- without the schema 0001_init folded in from the post-v0.1.0 migrations:
-- access_tokens.consumed_at and the cert_revocations table. Without this,
-- v0.2.0+ enroll-token minting fails (column "consumed_at" does not exist) and
-- the cert-revocation reconcile errors (relation "cert_revocations" does not
-- exist).
--
-- This migration is numbered 0010 (above the highest released pre-squash
-- version) so goose applies it on a v0.1.x database, and every statement is
-- guarded with IF NOT EXISTS so it is a complete no-op on a fresh database that
-- already has the full schema from 0001_init. The definitions below match
-- 0001_init exactly so both paths converge on an identical schema.

-- +goose Up
ALTER TABLE access_tokens ADD COLUMN IF NOT EXISTS consumed_at timestamp with time zone;

CREATE TABLE IF NOT EXISTS cert_revocations (
    cert_serial text NOT NULL,
    tenant_id text DEFAULT ''::text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    reason text DEFAULT ''::text NOT NULL,
    revoked_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT cert_revocations_pkey PRIMARY KEY (cert_serial)
);
CREATE INDEX IF NOT EXISTS cert_revocations_expires_at_idx ON cert_revocations USING btree (expires_at);

-- +goose Down
-- Forward-only reconcile: consumed_at and cert_revocations are part of the
-- current baseline schema (0001_init), so a downgrade must not drop them.
SELECT 1;
