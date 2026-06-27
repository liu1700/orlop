package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/db/sqlcdb"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
)

var (
	_ storage.SessionStore = (*Store)(nil)
	_ storage.Tx           = (*txStore)(nil)
)

// --- device authorizations ---

func (s *Store) CreateDeviceAuthorization(ctx context.Context, in storage.NewDeviceAuthorization) error {
	_, err := s.q.CreateDeviceAuthorization(ctx, sqlcdb.CreateDeviceAuthorizationParams{
		DeviceCodeHash: in.DeviceCodeHash,
		UserCodeHash:   in.UserCodeHash,
		ExpiresAt:      ts(in.ExpiresAt),
	})
	return mapErr(err)
}

func deviceAuth(row sqlcdb.DeviceAuthorization) storage.DeviceAuthorization {
	da := storage.DeviceAuthorization{
		ID:           domainUUID(row.ID),
		Status:       row.Status,
		UserID:       domainUUIDPtr(row.UserID),
		AllocationID: domainUUIDPtr(row.AllocationID),
		ExpiresAt:    timeOrZero(row.ExpiresAt),
		LastPolledAt: timePtr(row.LastPolledAt),
	}
	if row.TenantID.Valid {
		da.TenantID = row.TenantID.String
	}
	return da
}

func (s *Store) GetDeviceAuthorizationByDeviceCodeHash(ctx context.Context, hash string) (storage.DeviceAuthorization, error) {
	row, err := s.q.GetDeviceAuthorizationByDeviceCodeHash(ctx, hash)
	if err != nil {
		return storage.DeviceAuthorization{}, mapErr(err)
	}
	return deviceAuth(row), nil
}

func (s *Store) GetDeviceAuthorizationByUserCodeHash(ctx context.Context, hash string) (storage.DeviceAuthorization, error) {
	row, err := s.q.GetDeviceAuthorizationByUserCodeHash(ctx, hash)
	if err != nil {
		return storage.DeviceAuthorization{}, mapErr(err)
	}
	return deviceAuth(row), nil
}

func (s *Store) MarkDeviceAuthorizationExpired(ctx context.Context, id uuid.UUID) error {
	return mapErr(s.q.MarkDeviceAuthorizationExpired(ctx, pgUUID(id)))
}

func (s *Store) MarkDeviceAuthorizationExchanged(ctx context.Context, id uuid.UUID) error {
	return mapErr(s.q.MarkDeviceAuthorizationExchanged(ctx, pgUUID(id)))
}

func (s *Store) TouchDeviceAuthorizationPoll(ctx context.Context, id uuid.UUID, at time.Time) error {
	return mapErr(s.q.TouchDeviceAuthorizationPoll(ctx, sqlcdb.TouchDeviceAuthorizationPollParams{
		ID:           pgUUID(id),
		LastPolledAt: ts(at),
	}))
}

func (s *Store) ApproveDeviceAuthorization(ctx context.Context, in storage.ResolveDeviceAuthorization) error {
	_, err := s.q.ApproveDeviceAuthorization(ctx, sqlcdb.ApproveDeviceAuthorizationParams{
		ID:           pgUUID(in.ID),
		TenantID:     pgText(in.TenantID),
		UserID:       pgUUID(in.UserID),
		AllocationID: pgUUIDPtr(in.AllocationID),
	})
	return mapErr(err)
}

func (s *Store) DenyDeviceAuthorization(ctx context.Context, in storage.ResolveDeviceAuthorization) error {
	_, err := s.q.DenyDeviceAuthorization(ctx, sqlcdb.DenyDeviceAuthorizationParams{
		ID:       pgUUID(in.ID),
		TenantID: pgText(in.TenantID),
		UserID:   pgUUID(in.UserID),
	})
	return mapErr(err)
}

// --- access tokens ---

func (s *Store) CreateAccessToken(ctx context.Context, in storage.NewAccessToken) error {
	_, err := s.q.CreateAccessToken(ctx, sqlcdb.CreateAccessTokenParams{
		TokenHash:    in.TokenHash,
		Purpose:      in.Purpose,
		UserID:       pgUUID(in.UserID),
		TenantID:     in.TenantID,
		ExpiresAt:    ts(in.ExpiresAt),
		AllocationID: pgUUIDPtr(in.AllocationID),
	})
	return mapErr(err)
}

func (s *Store) GetAccessTokenByHash(ctx context.Context, hash string) (storage.AccessTokenAuth, error) {
	row, err := s.q.GetAccessTokenByHash(ctx, hash)
	if err != nil {
		return storage.AccessTokenAuth{}, mapErr(err)
	}
	return storage.AccessTokenAuth{
		Purpose:         row.Purpose,
		UserID:          domainUUID(row.UserID),
		TenantID:        row.TenantID,
		AllocationID:    domainUUIDPtr(row.AllocationID),
		ExpiresAt:       timeOrZero(row.ExpiresAt),
		Revoked:         row.RevokedAt.Valid,
		Consumed:        row.ConsumedAt.Valid,
		UserSuspended:   row.UserSuspendedAt.Valid,
		TenantSuspended: row.TenantSuspendedAt.Valid,
	}, nil
}

func (s *Store) ConsumeAgentEnrollToken(ctx context.Context, hash string) (bool, error) {
	if _, err := s.q.ConsumeAgentEnrollToken(ctx, hash); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// --- refresh tokens ---

func (s *Store) CreateRefreshToken(ctx context.Context, in storage.NewRefreshToken) error {
	_, err := s.q.CreateRefreshToken(ctx, sqlcdb.CreateRefreshTokenParams{
		TokenHash:    in.TokenHash,
		FamilyID:     pgUUID(in.FamilyID),
		UserID:       pgUUID(in.UserID),
		TenantID:     in.TenantID,
		ExpiresAt:    ts(in.ExpiresAt),
		AllocationID: pgUUIDPtr(in.AllocationID),
	})
	return mapErr(err)
}

func (s *Store) GetRefreshTokenByHash(ctx context.Context, hash string) (storage.RefreshTokenAuth, error) {
	row, err := s.q.GetRefreshTokenByHash(ctx, hash)
	if err != nil {
		return storage.RefreshTokenAuth{}, mapErr(err)
	}
	return storage.RefreshTokenAuth{
		ID:              domainUUID(row.ID),
		FamilyID:        domainUUID(row.FamilyID),
		UserID:          domainUUID(row.UserID),
		TenantID:        row.TenantID,
		AllocationID:    domainUUIDPtr(row.AllocationID),
		ExpiresAt:       timeOrZero(row.ExpiresAt),
		Revoked:         row.RevokedAt.Valid,
		Rotated:         row.RotatedAt.Valid,
		UserSuspended:   row.UserSuspendedAt.Valid,
		TenantSuspended: row.TenantSuspendedAt.Valid,
	}, nil
}

func (s *Store) MarkRefreshTokenRotated(ctx context.Context, id uuid.UUID) error {
	return mapErr(s.q.MarkRefreshTokenRotated(ctx, pgUUID(id)))
}

func (s *Store) RevokeRefreshTokenFamily(ctx context.Context, familyID uuid.UUID) error {
	return mapErr(s.q.RevokeRefreshTokenFamily(ctx, pgUUID(familyID)))
}

// --- users ---

func (s *Store) GetUser(ctx context.Context, id uuid.UUID) (storage.User, error) {
	u, err := s.q.GetUser(ctx, pgUUID(id))
	if err != nil {
		return storage.User{}, mapErr(err)
	}
	return storage.User{
		ID:         domainUUID(u.ID),
		Email:      u.Email,
		TenantID:   u.TenantID,
		Role:       u.Role,
		QuotaBytes: u.QuotaBytes,
		Suspended:  u.SuspendedAt.Valid,
	}, nil
}

func (s *Store) SumActiveAllocationBytes(ctx context.Context, userID uuid.UUID) (int64, error) {
	n, err := s.q.SumActiveAllocationBytes(ctx, pgUUID(userID))
	return n, mapErr(err)
}

// --- transactions ---

func (s *Store) Begin(ctx context.Context) (storage.Tx, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &txStore{Store: &Store{pool: s.pool, q: s.q.WithTx(tx)}, tx: tx}, nil
}

// txStore is a transaction-scoped Store: it reuses every adapter method through
// the embedded *Store (whose q is bound to the tx) and adds Commit/Rollback.
type txStore struct {
	*Store
	tx pgx.Tx
}

func (t *txStore) Commit(ctx context.Context) error   { return t.tx.Commit(ctx) }
func (t *txStore) Rollback(ctx context.Context) error { return t.tx.Rollback(ctx) }
