package sqlite

import (
	"context"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
)

var _ storage.RevocationStore = (*Store)(nil)

func (s *Store) AddCertRevocation(ctx context.Context, rev storage.CertRevocation) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO cert_revocations (cert_serial, tenant_id, expires_at, reason, revoked_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(cert_serial) DO NOTHING`,
		rev.Serial, rev.TenantID, micros(rev.ExpiresAt), rev.Reason, nowMicros())
	return mapErr(err)
}

func (s *Store) ListActiveCertRevocations(ctx context.Context) ([]storage.CertRevocation, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT cert_serial, expires_at FROM cert_revocations WHERE expires_at > ? ORDER BY expires_at`,
		nowMicros())
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []storage.CertRevocation{}
	for rows.Next() {
		var serial string
		var exp int64
		if err := rows.Scan(&serial, &exp); err != nil {
			return nil, mapErr(err)
		}
		out = append(out, storage.CertRevocation{Serial: serial, ExpiresAt: timeFromMicros(exp)})
	}
	return out, mapErr(rows.Err())
}

func (s *Store) ListActiveServerOpsAddrs(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT DISTINCT sp.ops_addr
		 FROM server_vms sv JOIN server_pool sp ON sp.data_addr = sv.data_addr`)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var addr string
		if err := rows.Scan(&addr); err != nil {
			return nil, mapErr(err)
		}
		out = append(out, addr)
	}
	return out, mapErr(rows.Err())
}
