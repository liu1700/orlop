-- +goose Up
-- +goose StatementBegin
-- Serial deny-list for the data-plane revocation kill switch (issue #5). When a
-- mount lease releases (or is force-released), the control plane records the
-- bound agent leaf's serial here; a reconcile loop pushes the active set to
-- orlop-server, which refuses the cert at session start. cert_serial is
-- uppercase hex, matching agent_enrollments.cert_serial. expires_at = the
-- cert's NotAfter, so an entry can be pruned once the cert would expire anyway.
CREATE TABLE cert_revocations (
    cert_serial TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL DEFAULT '',
    expires_at  TIMESTAMPTZ NOT NULL,
    reason      TEXT NOT NULL DEFAULT '',
    revoked_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX cert_revocations_expires_at_idx ON cert_revocations (expires_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS cert_revocations;
-- +goose StatementEnd
