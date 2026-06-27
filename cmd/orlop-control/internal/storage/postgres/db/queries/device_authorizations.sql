-- name: CreateDeviceAuthorization :one
INSERT INTO device_authorizations (device_code_hash, user_code_hash, status, expires_at)
VALUES ($1, $2, 'pending', $3)
RETURNING *;

-- name: GetDeviceAuthorizationByDeviceCodeHash :one
SELECT * FROM device_authorizations WHERE device_code_hash = $1;

-- name: GetDeviceAuthorizationByUserCodeHash :one
SELECT * FROM device_authorizations WHERE user_code_hash = $1;

-- name: GetPendingDeviceAuthorizationByUserCodeHashForUpdate :one
SELECT * FROM device_authorizations
WHERE user_code_hash = $1
FOR UPDATE;

-- name: TouchDeviceAuthorizationPoll :exec
UPDATE device_authorizations
SET last_polled_at = $2
WHERE id = $1;

-- name: ApproveDeviceAuthorization :one
UPDATE device_authorizations
SET status = 'approved', approved_at = now(), tenant_id = $2, user_id = $3, allocation_id = $4
WHERE id = $1 AND status = 'pending'
RETURNING *;

-- name: DenyDeviceAuthorization :one
UPDATE device_authorizations
SET status = 'denied', tenant_id = $2, user_id = $3
WHERE id = $1 AND status = 'pending'
RETURNING *;

-- name: MarkDeviceAuthorizationExchanged :exec
UPDATE device_authorizations SET status = 'exchanged' WHERE id = $1;

-- name: MarkDeviceAuthorizationExpired :exec
UPDATE device_authorizations SET status = 'expired' WHERE id = $1 AND status = 'pending';
