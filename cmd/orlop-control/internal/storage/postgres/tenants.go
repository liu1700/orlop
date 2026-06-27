package postgres

import (
	"context"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
)

var _ storage.TenantStore = (*Store)(nil)

func (s *Store) GetTenant(ctx context.Context, id string) (storage.Tenant, error) {
	row, err := s.q.GetTenant(ctx, id)
	if err != nil {
		return storage.Tenant{}, mapErr(err)
	}
	return storage.Tenant{
		Name:      row.Name,
		Suspended: row.SuspendedAt.Valid,
	}, nil
}
