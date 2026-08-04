package postgres

import (
	"context"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
)

var _ storage.CapacityMetricsStore = (*Store)(nil)

func (s *Store) ListServerPoolCapacity(ctx context.Context) ([]storage.ServerPoolCapacity, error) {
	rows, err := s.q.ListServerPoolCapacity(ctx)
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]storage.ServerPoolCapacity, len(rows))
	for i, row := range rows {
		out[i] = storage.ServerPoolCapacity{
			ServerID:   domainUUID(row.ID),
			TotalBytes: row.TotalBytes,
			FreeBytes:  row.FreeBytes,
		}
	}
	return out, nil
}

func (s *Store) CountPurgePendingAllocations(ctx context.Context) (int64, error) {
	count, err := s.q.CountPurgePendingAllocations(ctx)
	return count, mapErr(err)
}
