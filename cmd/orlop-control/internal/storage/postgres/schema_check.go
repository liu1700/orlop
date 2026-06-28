package postgres

import (
	"context"
	"fmt"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
)

// VerifySchema checks the live database against storage.RequiredSchema and
// returns a *storage.SchemaGapError if any required table or column is missing.
// It reads the catalog in one pass (information_schema.columns covers both
// table and column existence) so the cost is a single query on boot.
func (s *Store) VerifySchema(ctx context.Context) error {
	rows, err := s.pool.Query(ctx,
		`SELECT table_name, column_name
		   FROM information_schema.columns
		  WHERE table_schema = current_schema()`)
	if err != nil {
		return fmt.Errorf("read information_schema: %w", err)
	}
	defer rows.Close()

	present := map[string]map[string]bool{}
	for rows.Next() {
		var table, column string
		if err := rows.Scan(&table, &column); err != nil {
			return fmt.Errorf("scan information_schema row: %w", err)
		}
		cols := present[table]
		if cols == nil {
			cols = map[string]bool{}
			present[table] = cols
		}
		cols[column] = true
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read information_schema: %w", err)
	}
	return storage.SchemaGap(present)
}
