package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage/postgres/db"
)

const migrateUsage = `usage:
  orlop-control migrate up [--database-url URL]   apply all pending migrations

Reads DATABASE_URL from the environment if --database-url is not set.
Migrations are embedded into the binary; no separate files are required at runtime.
`

func runMigrate(ctx context.Context, out io.Writer, args []string) error {
	if len(args) == 0 {
		return errors.New(migrateUsage)
	}
	switch args[0] {
	case "up":
		return runMigrateUp(ctx, out, args[1:])
	case "-h", "--help", "help":
		_, _ = fmt.Fprint(out, migrateUsage)
		return nil
	default:
		return fmt.Errorf("unknown migrate subcommand %q\n%s", args[0], migrateUsage)
	}
}

func runMigrateUp(ctx context.Context, out io.Writer, args []string) error {
	fs := flag.NewFlagSet("migrate up", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	databaseURL := fs.String("database-url", os.Getenv("DATABASE_URL"), "Postgres connection string")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *databaseURL == "" {
		return errors.New("--database-url or DATABASE_URL is required")
	}
	// The SQLite backend applies its schema on open (no goose). Open it once so
	// `migrate up` still initialises a fresh database file, then close.
	if _, ok := sqlitePath(*databaseURL); ok {
		st, _, closeStore, err := openStore(ctx, *databaseURL)
		if err != nil {
			return err
		}
		defer closeStore()
		if err := verifyStoreSchema(ctx, st); err != nil {
			return err
		}
		fmt.Fprintln(out, "sqlite schema applied")
		return nil
	}
	if err := db.MigrateUp(ctx, *databaseURL); err != nil {
		return err
	}
	// Self-check the result: a renumber/squash of an already-released migration
	// can leave goose reporting success while the schema is incomplete (#39).
	st, _, closeStore, err := openStore(ctx, *databaseURL)
	if err != nil {
		return err
	}
	defer closeStore()
	if err := verifyStoreSchema(ctx, st); err != nil {
		return err
	}
	fmt.Fprintln(out, "migrations applied")
	return nil
}
