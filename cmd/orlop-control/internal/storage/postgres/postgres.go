// Package postgres is the Postgres-backed implementation of the storage
// interfaces. It adapts the sqlc-generated queries (subpackage db/sqlcdb) to the
// driver-agnostic domain types in package storage — this is the one place
// pgx/pgtype is allowed to meet the domain.
//
// One *Store value implements every storage role interface; a consumer depends
// only on the narrow interface it needs (e.g. storage.RevocationStore).
package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage/postgres/db/sqlcdb"
)

// Store is the Postgres adapter backing the storage interfaces.
type Store struct {
	pool *pgxpool.Pool
	q    *sqlcdb.Queries
}

// New builds a Store over an existing pool (migrations already applied).
func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool, q: sqlcdb.New(pool)}
}

// mapErr translates pgx sentinels to storage-level domain errors so callers
// never import the driver to interpret a result.
func mapErr(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return storage.ErrNotFound
	}
	return err
}

func ts(t time.Time) pgtype.Timestamptz { return pgtype.Timestamptz{Time: t, Valid: true} }

// --- storage.RevocationStore ---

var _ storage.RevocationStore = (*Store)(nil)

func (s *Store) AddCertRevocation(ctx context.Context, rev storage.CertRevocation) error {
	return mapErr(s.q.AddCertRevocation(ctx, sqlcdb.AddCertRevocationParams{
		CertSerial: rev.Serial,
		TenantID:   rev.TenantID,
		ExpiresAt:  ts(rev.ExpiresAt),
		Reason:     rev.Reason,
	}))
}

func (s *Store) ListActiveCertRevocations(ctx context.Context) ([]storage.CertRevocation, error) {
	rows, err := s.q.ListActiveCertRevocations(ctx)
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]storage.CertRevocation, len(rows))
	for i, r := range rows {
		out[i] = storage.CertRevocation{Serial: r.CertSerial, ExpiresAt: r.ExpiresAt.Time}
	}
	return out, nil
}

func (s *Store) ListActiveServerOpsAddrs(ctx context.Context) ([]string, error) {
	addrs, err := s.q.ListActiveServerOpsAddrs(ctx)
	return addrs, mapErr(err)
}
