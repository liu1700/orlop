package sqlite

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
)

// SessionOps is implemented here; the full SessionStore (with Begin) is asserted
// once AllocationOps lands, since storage.Tx embeds both operation sets.
var _ storage.SessionOps = (*Store)(nil)

// --- access tokens ---

func (s *Store) CreateAccessToken(ctx context.Context, in storage.NewAccessToken) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO access_tokens (id, token_hash, purpose, user_id, tenant_id, expires_at, allocation_id, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		uuid.New(), in.TokenHash, in.Purpose, in.UserID, in.TenantID,
		micros(in.ExpiresAt), nullUUID(in.AllocationID), nowMicros())
	return mapErr(err)
}

func (s *Store) GetAccessTokenByHash(ctx context.Context, hash string) (storage.AccessTokenAuth, error) {
	var a storage.AccessTokenAuth
	var allocID uuid.NullUUID
	var expires int64
	var revoked, consumed, userSusp, tenSusp sql.NullInt64
	err := s.db.QueryRowContext(ctx,
		`SELECT t.purpose, t.user_id, t.tenant_id, t.allocation_id, t.expires_at, t.revoked_at, t.consumed_at,
		        u.suspended_at, ten.suspended_at
		 FROM access_tokens t
		 JOIN users u ON u.id = t.user_id
		 JOIN tenants ten ON ten.id = t.tenant_id
		 WHERE t.token_hash = ?`, hash).
		Scan(&a.Purpose, &a.UserID, &a.TenantID, &allocID, &expires, &revoked, &consumed, &userSusp, &tenSusp)
	if err != nil {
		return storage.AccessTokenAuth{}, mapErr(err)
	}
	a.AllocationID = ptrUUID(allocID)
	a.ExpiresAt = timeFromMicros(expires)
	a.Revoked = revoked.Valid
	a.Consumed = consumed.Valid
	a.UserSuspended = userSusp.Valid
	a.TenantSuspended = tenSusp.Valid
	return a, nil
}

func (s *Store) ConsumeAgentEnrollToken(ctx context.Context, hash string) (bool, error) {
	var id uuid.UUID
	err := s.db.QueryRowContext(ctx,
		`UPDATE access_tokens SET consumed_at = ?
		 WHERE token_hash = ? AND purpose = 'agent_enroll' AND consumed_at IS NULL
		 RETURNING id`, nowMicros(), hash).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil // already consumed, or not an agent-enroll token
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// --- users ---

func (s *Store) GetUser(ctx context.Context, id uuid.UUID) (storage.User, error) {
	return scanUser(s.db.QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE id = ?`, id))
}

func (s *Store) SumActiveAllocationBytes(ctx context.Context, userID uuid.UUID) (int64, error) {
	var total int64
	err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(size_bytes), 0) FROM disk_allocations WHERE user_id = ? AND revoked_at IS NULL`,
		userID).Scan(&total)
	return total, mapErr(err)
}
