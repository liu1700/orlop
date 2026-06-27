// Package db owns the control-plane Postgres schema, embedded goose
// migrations, and the sqlc-generated typed query API (subpackage sqlcdb).
package db

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/database"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// migrationsSubFS scopes the embedded FS to the "migrations" directory so
// migration files appear at the FS root, which is what goose expects.
func migrationsSubFS() (fs.FS, error) {
	return fs.Sub(migrationsFS, "migrations")
}

// MigrateUp opens databaseURL with the pgx stdlib driver, applies all pending
// migrations, and closes the connection. Idempotent: a second call against an
// up-to-date database is a no-op.
func MigrateUp(ctx context.Context, databaseURL string) error {
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer db.Close()
	return Migrate(ctx, db)
}

// Migrate applies pending migrations against an already-open *sql.DB. Useful
// for tests that want to share a connection or pool across migration and
// query execution.
func Migrate(ctx context.Context, db *sql.DB) error {
	sub, err := migrationsSubFS()
	if err != nil {
		return fmt.Errorf("sub fs: %w", err)
	}
	provider, err := goose.NewProvider(database.DialectPostgres, db, sub)
	if err != nil {
		return fmt.Errorf("goose provider: %w", err)
	}
	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("goose up: %w", err)
	}
	return nil
}
