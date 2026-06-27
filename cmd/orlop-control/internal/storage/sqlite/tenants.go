package sqlite

import (
	"context"
	"database/sql"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
)

var _ storage.TenantStore = (*Store)(nil)

func (s *Store) GetTenant(ctx context.Context, id string) (storage.Tenant, error) {
	var name string
	var suspended sql.NullInt64
	err := s.db.QueryRowContext(ctx,
		`SELECT name, suspended_at FROM tenants WHERE id = ?`, id).
		Scan(&name, &suspended)
	if err != nil {
		return storage.Tenant{}, mapErr(err)
	}
	return storage.Tenant{Name: name, Suspended: suspended.Valid}, nil
}
