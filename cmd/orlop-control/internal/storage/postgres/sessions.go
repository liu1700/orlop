package postgres

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage/postgres/db/sqlcdb"
)

var (
	_ storage.SessionStore = (*Store)(nil)
	_ storage.Tx           = (*txStore)(nil)
)

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
