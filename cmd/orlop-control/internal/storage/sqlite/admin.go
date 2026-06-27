package sqlite

import (
	"context"
	"database/sql"

	"github.com/google/uuid"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
)

var _ storage.AdminStore = (*Store)(nil)

// userColumns is the standard projection of a users row, in the order scanUser
// expects. Shared by every users read (here, sessions.go, allocations.go).
const userColumns = `id, email, tenant_id, role, suspended_at, quota_bytes`

func scanUser(r rowScanner) (storage.User, error) {
	var u storage.User
	var suspended sql.NullInt64
	if err := r.Scan(&u.ID, &u.Email, &u.TenantID, &u.Role, &suspended, &u.QuotaBytes); err != nil {
		return storage.User{}, mapErr(err)
	}
	u.Suspended = suspended.Valid
	return u, nil
}

func (s *Store) CreateTenant(ctx context.Context, id, name string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO tenants (id, name, created_at) VALUES (?, ?, ?)`,
		id, name, nowMicros())
	return mapErr(err)
}

func (s *Store) GetUserByEmail(ctx context.Context, email string) (storage.User, error) {
	return scanUser(s.db.QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE email = ?`, email))
}

func (s *Store) CreateUser(ctx context.Context, email, tenantID string) (storage.User, error) {
	return scanUser(s.db.QueryRowContext(ctx,
		`INSERT INTO users (id, email, tenant_id, created_at) VALUES (?, ?, ?, ?)
		 RETURNING `+userColumns,
		uuid.New(), email, tenantID, nowMicros()))
}

func (s *Store) SuspendUser(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET suspended_at = ? WHERE id = ?`, nowMicros(), id)
	return mapErr(err)
}

func (s *Store) RegisterServerPool(ctx context.Context, in storage.ServerPool) (storage.ServerPool, error) {
	status := in.Status
	if status == "" {
		status = "available"
	}
	now := nowMicros()
	var out storage.ServerPool
	err := s.db.QueryRowContext(ctx,
		`INSERT INTO server_pool (id, data_addr, ops_addr, total_bytes, free_bytes, status, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(data_addr) DO UPDATE SET
		     ops_addr = excluded.ops_addr, total_bytes = excluded.total_bytes,
		     free_bytes = excluded.free_bytes, status = excluded.status, updated_at = excluded.updated_at
		 RETURNING data_addr, ops_addr, total_bytes, free_bytes, status`,
		uuid.New(), in.DataAddr, in.OpsAddr, in.TotalBytes, in.FreeBytes, status, now, now).
		Scan(&out.DataAddr, &out.OpsAddr, &out.TotalBytes, &out.FreeBytes, &out.Status)
	if err != nil {
		return storage.ServerPool{}, mapErr(err)
	}
	return out, nil
}
