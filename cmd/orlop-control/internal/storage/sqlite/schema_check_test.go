package sqlite

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
)

func TestVerifySchemaFresh(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	if err := s.VerifySchema(ctx); err != nil {
		t.Fatalf("fresh schema should verify clean; got %v", err)
	}
}

func TestOpenUpgradesLegacyMountLeaseTokenColumn(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "legacy.db")
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.ExecContext(ctx,
		`ALTER TABLE disk_allocations DROP COLUMN mount_lease_token_hash`); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s, err = Open(ctx, path)
	if err != nil {
		t.Fatalf("reopen legacy database: %v", err)
	}
	defer s.Close()
	if err := s.VerifySchema(ctx); err != nil {
		t.Fatalf("upgraded schema: %v", err)
	}
}

// TestVerifySchemaMissingColumn simulates the #39 hazard: an existing database
// whose access_tokens table predates the consumed_at column. Re-applying the
// CREATE TABLE IF NOT EXISTS schema does NOT add the column, so the self-check
// must catch it.
func TestVerifySchemaMissingColumn(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	if _, err := s.pool.ExecContext(ctx, `ALTER TABLE access_tokens DROP COLUMN consumed_at`); err != nil {
		t.Fatalf("drop column: %v", err)
	}

	var gap *storage.SchemaGapError
	if err := s.VerifySchema(ctx); !errors.As(err, &gap) {
		t.Fatalf("want *storage.SchemaGapError, got %v", err)
	} else if len(gap.MissingColumns) != 1 || gap.MissingColumns[0] != "access_tokens.consumed_at" {
		t.Fatalf("want access_tokens.consumed_at, got %v", gap.MissingColumns)
	}
}

func TestVerifySchemaMissingTable(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	if _, err := s.pool.ExecContext(ctx, `DROP TABLE cert_revocations`); err != nil {
		t.Fatalf("drop table: %v", err)
	}

	var gap *storage.SchemaGapError
	if err := s.VerifySchema(ctx); !errors.As(err, &gap) {
		t.Fatalf("want *storage.SchemaGapError, got %v", err)
	} else if len(gap.MissingTables) != 1 || gap.MissingTables[0] != "cert_revocations" {
		t.Fatalf("want cert_revocations, got %v", gap.MissingTables)
	}
}
