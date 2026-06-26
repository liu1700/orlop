-- name: CreateEmailOTP :one
INSERT INTO email_otps (email, code_hash, expires_at)
VALUES ($1, $2, $3)
RETURNING *;

-- name: GetLatestEmailOTPForUpdate :one
SELECT * FROM email_otps
WHERE email = $1
ORDER BY created_at DESC
LIMIT 1
FOR UPDATE;

-- name: ConsumeEmailOTP :one
UPDATE email_otps
SET consumed_at = $2
WHERE id = $1 AND consumed_at IS NULL
RETURNING *;

-- name: IncrementEmailOTPAttempts :one
UPDATE email_otps
SET attempts = attempts + 1
WHERE id = $1
RETURNING attempts;
