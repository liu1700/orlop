package sqlite

import (
	"context"
	"fmt"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
)

// VerifySchema checks the live database against storage.RequiredSchema and
// returns a *storage.SchemaGapError if any required table or column is missing.
//
// This matters for SQLite too: the schema is applied with CREATE TABLE IF NOT
// EXISTS on every open, so a fresh database gets the current schema — but an
// existing database file opened by a newer binary keeps its old tables, and a
// newly added column is NOT backfilled (IF NOT EXISTS is a no-op once the table
// exists). The self-check turns that silent gap into a fail-fast error.
func (s *Store) VerifySchema(ctx context.Context) error {
	tableRows, err := s.db.QueryContext(ctx,
		`SELECT name FROM sqlite_master WHERE type = 'table'`)
	if err != nil {
		return fmt.Errorf("list sqlite tables: %w", err)
	}
	defer tableRows.Close()

	present := map[string]map[string]bool{}
	var tables []string
	for tableRows.Next() {
		var name string
		if err := tableRows.Scan(&name); err != nil {
			return fmt.Errorf("scan sqlite table name: %w", err)
		}
		present[name] = map[string]bool{}
		tables = append(tables, name)
	}
	if err := tableRows.Err(); err != nil {
		return fmt.Errorf("list sqlite tables: %w", err)
	}

	// pragma_table_info is a table-valued function: one query per table yields
	// its columns. The table set is tiny (~11), so this stays a handful of
	// cheap reads on boot.
	for _, table := range tables {
		colRows, err := s.db.QueryContext(ctx,
			`SELECT name FROM pragma_table_info(?)`, table)
		if err != nil {
			return fmt.Errorf("read columns of %s: %w", table, err)
		}
		for colRows.Next() {
			var col string
			if err := colRows.Scan(&col); err != nil {
				colRows.Close()
				return fmt.Errorf("scan column of %s: %w", table, err)
			}
			present[table][col] = true
		}
		if err := colRows.Err(); err != nil {
			colRows.Close()
			return fmt.Errorf("read columns of %s: %w", table, err)
		}
		colRows.Close()
	}
	return storage.SchemaGap(present)
}
