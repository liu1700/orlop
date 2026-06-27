package sqlite

import (
	"context"
	"database/sql"

	"github.com/google/uuid"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
)

var _ storage.APITokenStore = (*Store)(nil)

func (s *Store) CreateAPIToken(ctx context.Context, in storage.NewAPIToken) (storage.APIToken, error) {
	id := uuid.New()
	now := nowMicros()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO api_tokens (id, user_id, name, token_hash, prefix, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, in.UserID, in.Name, in.TokenHash, in.Prefix, now, microsPtr(in.ExpiresAt))
	if err != nil {
		return storage.APIToken{}, mapErr(err)
	}
	return storage.APIToken{
		ID:        id,
		UserID:    in.UserID,
		Name:      in.Name,
		Prefix:    in.Prefix,
		CreatedAt: timeFromMicros(now),
	}, nil
}

func (s *Store) GetAPITokenByHash(ctx context.Context, hash string) (storage.APITokenAuth, error) {
	var a storage.APITokenAuth
	var revoked, expires, lastUsed, userSusp, tenSusp sql.NullInt64
	err := s.db.QueryRowContext(ctx,
		`SELECT t.id, t.user_id, u.tenant_id, t.revoked_at, t.expires_at, t.last_used_at,
		        u.suspended_at, ten.suspended_at
		 FROM api_tokens t
		 JOIN users u ON u.id = t.user_id
		 JOIN tenants ten ON ten.id = u.tenant_id
		 WHERE t.token_hash = ?`, hash).
		Scan(&a.ID, &a.UserID, &a.TenantID, &revoked, &expires, &lastUsed, &userSusp, &tenSusp)
	if err != nil {
		return storage.APITokenAuth{}, mapErr(err)
	}
	a.Revoked = revoked.Valid
	a.ExpiresAt = timePtrFromMicros(expires)
	a.LastUsedAt = timePtrFromMicros(lastUsed)
	a.UserSuspended = userSusp.Valid
	a.TenantSuspended = tenSusp.Valid
	return a, nil
}

func (s *Store) GetAPITokenByID(ctx context.Context, id uuid.UUID) (storage.APIToken, error) {
	var t storage.APIToken
	var created int64
	var lastUsed sql.NullInt64
	err := s.db.QueryRowContext(ctx,
		`SELECT id, user_id, name, prefix, created_at, last_used_at FROM api_tokens WHERE id = ?`, id).
		Scan(&t.ID, &t.UserID, &t.Name, &t.Prefix, &created, &lastUsed)
	if err != nil {
		return storage.APIToken{}, mapErr(err)
	}
	t.CreatedAt = timeFromMicros(created)
	t.LastUsedAt = timePtrFromMicros(lastUsed)
	return t, nil
}

func (s *Store) ListAPITokensByUser(ctx context.Context, userID uuid.UUID) ([]storage.APIToken, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, prefix, created_at, last_used_at FROM api_tokens
		 WHERE user_id = ? AND revoked_at IS NULL ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []storage.APIToken{}
	for rows.Next() {
		var t storage.APIToken
		var created int64
		var lastUsed sql.NullInt64
		if err := rows.Scan(&t.ID, &t.Name, &t.Prefix, &created, &lastUsed); err != nil {
			return nil, mapErr(err)
		}
		t.CreatedAt = timeFromMicros(created)
		t.LastUsedAt = timePtrFromMicros(lastUsed)
		out = append(out, t)
	}
	return out, mapErr(rows.Err())
}

func (s *Store) RevokeAPIToken(ctx context.Context, id, userID uuid.UUID) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE api_tokens SET revoked_at = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL`,
		nowMicros(), id, userID)
	return mapErr(err)
}

func (s *Store) TouchAPITokenLastUsed(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE api_tokens SET last_used_at = ? WHERE id = ?`, nowMicros(), id)
	return mapErr(err)
}
