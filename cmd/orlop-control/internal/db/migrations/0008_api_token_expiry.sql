-- +goose Up
-- +goose StatementBegin
-- API tokens were valid until explicit revocation (no expiry), so a leaked
-- token stayed live indefinitely. Add an optional expiry to bound the blast
-- radius. Existing rows stay NULL = never expire (backward compatible); new
-- tokens get an expiry only when ORLOP_API_TOKEN_TTL is configured.
ALTER TABLE api_tokens ADD COLUMN expires_at TIMESTAMPTZ;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE api_tokens DROP COLUMN IF EXISTS expires_at;
-- +goose StatementEnd
