package postgres

import (
	"context"

	"github.com/google/uuid"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage/postgres/db/sqlcdb"
)

var _ storage.APITokenStore = (*Store)(nil)

func (s *Store) CreateAPIToken(ctx context.Context, in storage.NewAPIToken) (storage.APIToken, error) {
	row, err := s.q.CreateAPIToken(ctx, sqlcdb.CreateAPITokenParams{
		UserID:    pgUUID(in.UserID),
		Name:      in.Name,
		TokenHash: in.TokenHash,
		Prefix:    in.Prefix,
		ExpiresAt: tsPtr(in.ExpiresAt),
	})
	if err != nil {
		return storage.APIToken{}, mapErr(err)
	}
	return storage.APIToken{
		ID:        domainUUID(row.ID),
		UserID:    domainUUID(row.UserID),
		Name:      row.Name,
		Prefix:    row.Prefix,
		CreatedAt: timeOrZero(row.CreatedAt),
	}, nil
}

func (s *Store) GetAPITokenByHash(ctx context.Context, hash string) (storage.APITokenAuth, error) {
	row, err := s.q.GetAPITokenByHash(ctx, hash)
	if err != nil {
		return storage.APITokenAuth{}, mapErr(err)
	}
	return storage.APITokenAuth{
		ID:              domainUUID(row.ID),
		UserID:          domainUUID(row.UserID),
		TenantID:        row.UserTenantID,
		Revoked:         row.RevokedAt.Valid,
		ExpiresAt:       timePtr(row.ExpiresAt),
		LastUsedAt:      timePtr(row.LastUsedAt),
		UserSuspended:   row.UserSuspendedAt.Valid,
		TenantSuspended: row.TenantSuspendedAt.Valid,
	}, nil
}

func (s *Store) GetAPITokenByID(ctx context.Context, id uuid.UUID) (storage.APIToken, error) {
	row, err := s.q.GetAPITokenByID(ctx, pgUUID(id))
	if err != nil {
		return storage.APIToken{}, mapErr(err)
	}
	return storage.APIToken{
		ID:         domainUUID(row.ID),
		UserID:     domainUUID(row.UserID),
		Name:       row.Name,
		Prefix:     row.Prefix,
		CreatedAt:  timeOrZero(row.CreatedAt),
		LastUsedAt: timePtr(row.LastUsedAt),
	}, nil
}

func (s *Store) ListAPITokensByUser(ctx context.Context, userID uuid.UUID) ([]storage.APIToken, error) {
	rows, err := s.q.ListAPITokensByUser(ctx, pgUUID(userID))
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]storage.APIToken, len(rows))
	for i, r := range rows {
		out[i] = storage.APIToken{
			ID:         domainUUID(r.ID),
			Name:       r.Name,
			Prefix:     r.Prefix,
			CreatedAt:  timeOrZero(r.CreatedAt),
			LastUsedAt: timePtr(r.LastUsedAt),
		}
	}
	return out, nil
}

func (s *Store) RevokeAPIToken(ctx context.Context, id, userID uuid.UUID) error {
	return mapErr(s.q.RevokeAPIToken(ctx, sqlcdb.RevokeAPITokenParams{ID: pgUUID(id), UserID: pgUUID(userID)}))
}

func (s *Store) TouchAPITokenLastUsed(ctx context.Context, id uuid.UUID) error {
	return mapErr(s.q.TouchAPITokenLastUsed(ctx, pgUUID(id)))
}
