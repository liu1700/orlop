package postgres

import (
	"context"

	"github.com/google/uuid"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage/postgres/db/sqlcdb"
)

var _ storage.AdminStore = (*Store)(nil)

func (s *Store) CreateTenant(ctx context.Context, id, name string) error {
	_, err := s.q.CreateTenant(ctx, sqlcdb.CreateTenantParams{ID: id, Name: name})
	return mapErr(err)
}

func (s *Store) GetUserByEmail(ctx context.Context, email string) (storage.User, error) {
	row, err := s.q.GetUserByEmail(ctx, email)
	if err != nil {
		return storage.User{}, mapErr(err)
	}
	return user(row), nil
}

func (s *Store) CreateUser(ctx context.Context, email, tenantID string) (storage.User, error) {
	row, err := s.q.CreateUser(ctx, sqlcdb.CreateUserParams{Email: email, TenantID: tenantID})
	if err != nil {
		return storage.User{}, mapErr(err)
	}
	return user(row), nil
}

func (s *Store) SuspendUser(ctx context.Context, id uuid.UUID) error {
	return mapErr(s.q.SuspendUser(ctx, pgUUID(id)))
}

func (s *Store) RegisterServerPool(ctx context.Context, in storage.ServerPool) (storage.ServerPool, error) {
	row, err := s.q.UpsertServerPool(ctx, sqlcdb.UpsertServerPoolParams{
		DataAddr:   in.DataAddr,
		OpsAddr:    in.OpsAddr,
		TotalBytes: in.TotalBytes,
		FreeBytes:  in.FreeBytes,
		Status:     in.Status,
	})
	if err != nil {
		return storage.ServerPool{}, mapErr(err)
	}
	return storage.ServerPool{
		DataAddr:   row.DataAddr,
		OpsAddr:    row.OpsAddr,
		TotalBytes: row.TotalBytes,
		FreeBytes:  row.FreeBytes,
		Status:     row.Status,
	}, nil
}
