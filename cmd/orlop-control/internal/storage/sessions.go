package storage

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// --- domain types for the sessions subdomain ---

// AccessTokenAuth is the result of authenticating an opaque access token: the
// token's own state joined with the owner's user/tenant suspension state.
type AccessTokenAuth struct {
	Purpose         string
	UserID          uuid.UUID
	TenantID        string
	AllocationID    *uuid.UUID
	ExpiresAt       time.Time
	Revoked         bool
	Consumed        bool
	UserSuspended   bool
	TenantSuspended bool
}

// NewAccessToken is the create input for an access token (hash already computed).
type NewAccessToken struct {
	TokenHash    string
	Purpose      string
	UserID       uuid.UUID
	TenantID     string
	ExpiresAt    time.Time
	AllocationID *uuid.UUID
}

// User is the account a token/session belongs to (the fields the session layer
// reads).
type User struct {
	ID         uuid.UUID
	Email      string
	TenantID   string
	Role       string
	QuotaBytes int64
	Suspended  bool
}

// SessionOps is the read/write surface for the sessions subdomain, available
// both directly on a SessionStore and inside a SessionTx.
type SessionOps interface {
	// Access tokens.
	CreateAccessToken(ctx context.Context, in NewAccessToken) error
	GetAccessTokenByHash(ctx context.Context, hash string) (AccessTokenAuth, error)
	// ConsumeAgentEnrollToken atomically spends a single-use agent-enroll token;
	// returns true if this call consumed it, false if it was already consumed or
	// is not an agent-enroll token.
	ConsumeAgentEnrollToken(ctx context.Context, hash string) (bool, error)

	// Users.
	GetUser(ctx context.Context, id uuid.UUID) (User, error)
	SumActiveAllocationBytes(ctx context.Context, userID uuid.UUID) (int64, error)
}

// SessionStore is the sessions data layer plus transaction control.
type SessionStore interface {
	SessionOps
	beginner
}
