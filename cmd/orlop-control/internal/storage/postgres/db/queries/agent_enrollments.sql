-- name: CreateAgentEnrollment :one
INSERT INTO agent_enrollments (user_id, cert_serial, cert_not_after)
VALUES ($1, $2, $3)
RETURNING *;

-- name: ListActiveEnrollmentsForUser :many
SELECT * FROM agent_enrollments
WHERE user_id = $1 AND cert_not_after > now()
ORDER BY enrolled_at DESC;

-- name: GetActiveEnrollmentByFingerprint :one
SELECT * FROM agent_enrollments
WHERE lower(cert_serial) = lower($1) AND cert_not_after > now();

-- name: GetAgentEnrollment :one
-- Resolve a single enrollment by its id (a disk_allocations.bound_agent_id FK),
-- used to revoke the bound leaf's serial on lease release (issue #5).
SELECT * FROM agent_enrollments WHERE id = $1;
