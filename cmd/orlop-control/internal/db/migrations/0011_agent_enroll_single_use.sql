-- +goose Up
-- +goose StatementBegin
-- Make per-pod agent-enroll tokens single-use (issue #6). The enroll handler
-- spends the token once the cert is minted; a replayed or concurrently-raced
-- token finds consumed_at already set and is rejected, so an observer that
-- captured the bearer (proxy, log, env-var leak) cannot trade it for a second
-- cert. NULL = never consumed, which is the permanent state for
-- device/admin/api tokens — their multi-use sessions are deliberately never
-- consumed here.
ALTER TABLE access_tokens ADD COLUMN consumed_at TIMESTAMPTZ;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE access_tokens DROP COLUMN IF EXISTS consumed_at;
-- +goose StatementEnd
