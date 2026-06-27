-- name: AddCertRevocation :exec
-- Record a revoked cert serial (issue #5). Idempotent: a serial already on the
-- deny-list is left untouched (the first revocation's reason/expiry win).
INSERT INTO cert_revocations (cert_serial, tenant_id, expires_at, reason)
VALUES ($1, $2, $3, $4)
ON CONFLICT (cert_serial) DO NOTHING;

-- name: ListActiveCertRevocations :many
-- The deny-list the reconcile loop pushes to data-plane servers: serials whose
-- certs have not yet expired (an expired cert fails verification anyway).
SELECT cert_serial, expires_at
FROM cert_revocations
WHERE expires_at > now()
ORDER BY expires_at;

-- name: DeleteExpiredCertRevocations :exec
-- Housekeeping: drop rows whose certs have already expired.
DELETE FROM cert_revocations WHERE expires_at <= now();

-- name: ListActiveServerOpsAddrs :many
-- Distinct orlop-server ops addresses that currently host at least one placed
-- tenant — the push targets for the deny-list reconcile.
SELECT DISTINCT sp.ops_addr
FROM server_vms sv
JOIN server_pool sp ON sp.data_addr = sv.data_addr;
