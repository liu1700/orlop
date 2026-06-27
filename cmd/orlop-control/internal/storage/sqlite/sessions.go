package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
)

// SessionOps is implemented here; the full SessionStore (with Begin) is asserted
// once AllocationOps lands, since storage.Tx embeds both operation sets.
var _ storage.SessionOps = (*Store)(nil)

// --- device authorizations ---

const deviceAuthColumns = `id, status, user_id, tenant_id, allocation_id, expires_at, last_polled_at`

func scanDeviceAuth(r rowScanner) (storage.DeviceAuthorization, error) {
	var da storage.DeviceAuthorization
	var userID, allocID uuid.NullUUID
	var tenantID sql.NullString
	var expires int64
	var lastPolled sql.NullInt64
	if err := r.Scan(&da.ID, &da.Status, &userID, &tenantID, &allocID, &expires, &lastPolled); err != nil {
		return storage.DeviceAuthorization{}, mapErr(err)
	}
	da.UserID = ptrUUID(userID)
	da.AllocationID = ptrUUID(allocID)
	da.TenantID = tenantID.String
	da.ExpiresAt = timeFromMicros(expires)
	da.LastPolledAt = timePtrFromMicros(lastPolled)
	return da, nil
}

func (s *Store) CreateDeviceAuthorization(ctx context.Context, in storage.NewDeviceAuthorization) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO device_authorizations (id, device_code_hash, user_code_hash, status, expires_at, created_at)
		 VALUES (?, ?, ?, 'pending', ?, ?)`,
		uuid.New(), in.DeviceCodeHash, in.UserCodeHash, micros(in.ExpiresAt), nowMicros())
	return mapErr(err)
}

func (s *Store) GetDeviceAuthorizationByDeviceCodeHash(ctx context.Context, hash string) (storage.DeviceAuthorization, error) {
	return scanDeviceAuth(s.db.QueryRowContext(ctx,
		`SELECT `+deviceAuthColumns+` FROM device_authorizations WHERE device_code_hash = ?`, hash))
}

func (s *Store) GetDeviceAuthorizationByUserCodeHash(ctx context.Context, hash string) (storage.DeviceAuthorization, error) {
	return scanDeviceAuth(s.db.QueryRowContext(ctx,
		`SELECT `+deviceAuthColumns+` FROM device_authorizations WHERE user_code_hash = ?`, hash))
}

func (s *Store) MarkDeviceAuthorizationExpired(ctx context.Context, id uuid.UUID) error {
	// Conditional but :exec — matching zero rows (already resolved) is not an error.
	_, err := s.db.ExecContext(ctx,
		`UPDATE device_authorizations SET status = 'expired' WHERE id = ? AND status = 'pending'`, id)
	return mapErr(err)
}

func (s *Store) MarkDeviceAuthorizationExchanged(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE device_authorizations SET status = 'exchanged' WHERE id = ?`, id)
	return mapErr(err)
}

func (s *Store) TouchDeviceAuthorizationPoll(ctx context.Context, id uuid.UUID, at time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE device_authorizations SET last_polled_at = ? WHERE id = ?`, micros(at), id)
	return mapErr(err)
}

// ApproveDeviceAuthorization / DenyDeviceAuthorization are conditional on the row
// still being pending (RETURNING + 0 rows -> ErrNotFound), so a concurrent
// resolve loses cleanly.
func (s *Store) ApproveDeviceAuthorization(ctx context.Context, in storage.ResolveDeviceAuthorization) error {
	var id uuid.UUID
	err := s.db.QueryRowContext(ctx,
		`UPDATE device_authorizations
		 SET status = 'approved', approved_at = ?, tenant_id = ?, user_id = ?, allocation_id = ?
		 WHERE id = ? AND status = 'pending'
		 RETURNING id`,
		nowMicros(), in.TenantID, in.UserID, nullUUID(in.AllocationID), in.ID).Scan(&id)
	return mapErr(err)
}

func (s *Store) DenyDeviceAuthorization(ctx context.Context, in storage.ResolveDeviceAuthorization) error {
	var id uuid.UUID
	err := s.db.QueryRowContext(ctx,
		`UPDATE device_authorizations
		 SET status = 'denied', tenant_id = ?, user_id = ?
		 WHERE id = ? AND status = 'pending'
		 RETURNING id`,
		in.TenantID, in.UserID, in.ID).Scan(&id)
	return mapErr(err)
}

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

// --- refresh tokens ---

func (s *Store) CreateRefreshToken(ctx context.Context, in storage.NewRefreshToken) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO refresh_tokens (id, token_hash, family_id, user_id, tenant_id, expires_at, allocation_id, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		uuid.New(), in.TokenHash, in.FamilyID, in.UserID, in.TenantID,
		micros(in.ExpiresAt), nullUUID(in.AllocationID), nowMicros())
	return mapErr(err)
}

func (s *Store) GetRefreshTokenByHash(ctx context.Context, hash string) (storage.RefreshTokenAuth, error) {
	var a storage.RefreshTokenAuth
	var allocID uuid.NullUUID
	var expires int64
	var revoked, rotated, userSusp, tenSusp sql.NullInt64
	err := s.db.QueryRowContext(ctx,
		`SELECT t.id, t.family_id, t.user_id, t.tenant_id, t.allocation_id, t.expires_at, t.revoked_at, t.rotated_at,
		        u.suspended_at, ten.suspended_at
		 FROM refresh_tokens t
		 JOIN users u ON u.id = t.user_id
		 JOIN tenants ten ON ten.id = t.tenant_id
		 WHERE t.token_hash = ?`, hash).
		Scan(&a.ID, &a.FamilyID, &a.UserID, &a.TenantID, &allocID, &expires, &revoked, &rotated, &userSusp, &tenSusp)
	if err != nil {
		return storage.RefreshTokenAuth{}, mapErr(err)
	}
	a.AllocationID = ptrUUID(allocID)
	a.ExpiresAt = timeFromMicros(expires)
	a.Revoked = revoked.Valid
	a.Rotated = rotated.Valid
	a.UserSuspended = userSusp.Valid
	a.TenantSuspended = tenSusp.Valid
	return a, nil
}

func (s *Store) MarkRefreshTokenRotated(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE refresh_tokens SET rotated_at = ? WHERE id = ? AND rotated_at IS NULL AND revoked_at IS NULL`,
		nowMicros(), id)
	return mapErr(err)
}

func (s *Store) RevokeRefreshTokenFamily(ctx context.Context, familyID uuid.UUID) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE refresh_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL`,
		nowMicros(), familyID)
	return mapErr(err)
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
