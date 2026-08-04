package sqlite

import (
	"context"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
)

var _ storage.CapacityMetricsStore = (*Store)(nil)

func (s *Store) ListServerPoolCapacity(ctx context.Context) ([]storage.ServerPoolCapacity, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, total_bytes, free_bytes FROM server_pool ORDER BY id`)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()

	out := []storage.ServerPoolCapacity{}
	for rows.Next() {
		var row storage.ServerPoolCapacity
		if err := rows.Scan(&row.ServerID, &row.TotalBytes, &row.FreeBytes); err != nil {
			return nil, mapErr(err)
		}
		out = append(out, row)
	}
	return out, mapErr(rows.Err())
}

func (s *Store) CountPurgePendingAllocations(ctx context.Context) (int64, error) {
	var count int64
	err := s.db.QueryRowContext(ctx,
		`SELECT count(*) FROM disk_allocations
		 WHERE revoked_at IS NOT NULL AND purged_at IS NULL`).Scan(&count)
	return count, mapErr(err)
}
