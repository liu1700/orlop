-- +goose Up
-- +goose StatementBegin
CREATE TABLE api_tokens (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    token_hash   TEXT NOT NULL,
    prefix       TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ
);

CREATE UNIQUE INDEX api_tokens_token_hash_idx ON api_tokens(token_hash);
CREATE INDEX api_tokens_user_id_active_idx ON api_tokens(user_id) WHERE revoked_at IS NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS api_tokens_user_id_active_idx;
DROP INDEX IF EXISTS api_tokens_token_hash_idx;
DROP TABLE IF EXISTS api_tokens;
-- +goose StatementEnd
