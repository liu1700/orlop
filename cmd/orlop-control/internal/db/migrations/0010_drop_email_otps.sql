-- +goose Up
-- +goose StatementBegin
-- Email-OTP self-service login was removed: an embeddable infra component does
-- not own the human signup/login lifecycle (see docs/design-identity.md). The
-- table and its per-code attempt counter go with it.
DROP TABLE IF EXISTS email_otps;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE TABLE email_otps (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email       TEXT NOT NULL,
    code_hash   TEXT NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    attempts    INT NOT NULL DEFAULT 0
);
CREATE INDEX email_otps_email_created_at_idx ON email_otps (email, created_at DESC);
-- +goose StatementEnd
