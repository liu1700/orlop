package storage

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// APIToken is a long-lived `orlop_` API token row (without the secret).
type APIToken struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	Name       string
	Prefix     string
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

// NewAPIToken is the input to mint an API token (hash already computed).
// ExpiresAt nil means the token never expires.
type NewAPIToken struct {
	UserID    uuid.UUID
	Name      string
	TokenHash string
	Prefix    string
	ExpiresAt *time.Time
}

// APITokenAuth is the result of authenticating an `orlop_` token: its state
// joined with the owner's user/tenant suspension state.
type APITokenAuth struct {
	ID              uuid.UUID
	UserID          uuid.UUID
	TenantID        string
	Revoked         bool
	ExpiresAt       *time.Time
	LastUsedAt      *time.Time
	UserSuspended   bool
	TenantSuspended bool
}

// APITokenStore is the data-access surface for API tokens.
type APITokenStore interface {
	CreateAPIToken(ctx context.Context, in NewAPIToken) (APIToken, error)
	GetAPITokenByHash(ctx context.Context, hash string) (APITokenAuth, error)
	GetAPITokenByID(ctx context.Context, id uuid.UUID) (APIToken, error)
	ListAPITokensByUser(ctx context.Context, userID uuid.UUID) ([]APIToken, error)
	RevokeAPIToken(ctx context.Context, id, userID uuid.UUID) error
	TouchAPITokenLastUsed(ctx context.Context, id uuid.UUID) error
}
