-- +goose Up
-- +goose StatementBegin
-- CA secret store (secrets.Postgres backend). Lets dg-control keep the agent CA
-- root key + per-tenant intermediates in this durable Postgres instead of a
-- block-storage PVC mounted at ORLOP_SECRETS_DIR — one fewer disk on cloud
-- deploys. Keys are the same slash-paths the filesystem backend used
-- ("ca/root/cert.pem", "ca/tenant/<id>/key.pem"); value is opaque PEM bytes. No
-- size cap (unlike a k8s Secret), so it holds one intermediate per agent. Only
-- dg-control reads/writes this table. Selected via ORLOP_SECRETS_BACKEND=postgres.
CREATE TABLE dg_ca_secrets (
    key        TEXT PRIMARY KEY,
    value      BYTEA NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS dg_ca_secrets;
-- +goose StatementEnd
