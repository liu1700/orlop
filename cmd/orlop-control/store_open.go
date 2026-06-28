package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage/postgres"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage/sqlite"
)

// openStore opens the storage backend named by databaseURL. A "sqlite:" scheme
// selects the embedded SQLite backend — schema applied on open, zero external
// dependencies, for local quick-start and self-hosting; anything else is a
// Postgres connection string. The returned pool is non-nil only for Postgres
// (the "postgres" CA-secrets backend needs it); closeFn releases the backend.
func openStore(ctx context.Context, databaseURL string) (st storage.Store, pool *pgxpool.Pool, closeFn func() error, err error) {
	if path, ok := sqlitePath(databaseURL); ok {
		s, err := sqlite.Open(ctx, path)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("open sqlite: %w", err)
		}
		return s, nil, s.Close, nil
	}
	p, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open pgxpool: %w", err)
	}
	return postgres.New(p), p, func() error { p.Close(); return nil }, nil
}

// schemaVerifier is implemented by both storage backends (postgres.Store,
// sqlite.Store). It checks the live database against storage.RequiredSchema.
type schemaVerifier interface {
	VerifySchema(ctx context.Context) error
}

// verifyStoreSchema runs the backend's schema self-check if it has one. A gap
// (a missing table or column the code requires) returns a *storage.SchemaGapError
// whose message names what is absent and how to converge — so an in-place
// upgrade that skipped a migration fails fast here rather than as an opaque
// runtime error later. See issue #39.
func verifyStoreSchema(ctx context.Context, st storage.Store) error {
	v, ok := st.(schemaVerifier)
	if !ok {
		return nil
	}
	return v.VerifySchema(ctx)
}

// sqlitePath extracts the database path from a "sqlite:" URL, accepting
// sqlite:FILE, sqlite://FILE, sqlite:///ABS/PATH, and sqlite::memory:.
func sqlitePath(databaseURL string) (string, bool) {
	const scheme = "sqlite:"
	if !strings.HasPrefix(databaseURL, scheme) {
		return "", false
	}
	return strings.TrimPrefix(strings.TrimPrefix(databaseURL, scheme), "//"), true
}
