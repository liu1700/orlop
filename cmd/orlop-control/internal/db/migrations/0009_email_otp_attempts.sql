-- +goose Up
-- +goose StatementBegin
-- Per-code attempt counter for email OTPs. A 6-digit OTP's only defense against
-- brute force was an in-memory (per-process, reset-on-restart) rate limiter;
-- this caps guesses per code so a leaked/bypassed limiter can't grind the 10^6
-- space within the code's TTL. The code is consumed after a small budget of
-- wrong guesses.
ALTER TABLE email_otps ADD COLUMN attempts INT NOT NULL DEFAULT 0;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE email_otps DROP COLUMN IF EXISTS attempts;
-- +goose StatementEnd
