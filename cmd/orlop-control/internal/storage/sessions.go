package storage

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// --- domain types for the sessions / device-flow subdomain ---

// DeviceAuthorization is a device-flow authorization row. UserID/AllocationID
// are nil and TenantID is "" until an admin approves it.
type DeviceAuthorization struct {
	ID           uuid.UUID
	Status       string // pending | approved | denied | exchanged | expired
	UserID       *uuid.UUID
	TenantID     string
	AllocationID *uuid.UUID
	ExpiresAt    time.Time
	LastPolledAt *time.Time
}

// NewDeviceAuthorization is the input to create a pending authorization.
type NewDeviceAuthorization struct {
	DeviceCodeHash string
	UserCodeHash   string
	ExpiresAt      time.Time
}

// ResolveDeviceAuthorization approves or denies a pending authorization on
// behalf of an admin identity. AllocationID is the (optional) granted disk.
type ResolveDeviceAuthorization struct {
	ID           uuid.UUID
	TenantID     string
	UserID       uuid.UUID
	AllocationID *uuid.UUID
}

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

// RefreshTokenAuth is the result of looking up a refresh token, joined with the
// owner's suspension state.
type RefreshTokenAuth struct {
	ID              uuid.UUID
	FamilyID        uuid.UUID
	UserID          uuid.UUID
	TenantID        string
	AllocationID    *uuid.UUID
	ExpiresAt       time.Time
	Revoked         bool
	Rotated         bool
	UserSuspended   bool
	TenantSuspended bool
}

// NewAccessToken / NewRefreshToken are create inputs (hashes already computed).
type NewAccessToken struct {
	TokenHash    string
	Purpose      string
	UserID       uuid.UUID
	TenantID     string
	ExpiresAt    time.Time
	AllocationID *uuid.UUID
}

type NewRefreshToken struct {
	TokenHash    string
	FamilyID     uuid.UUID
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
	// Device authorizations.
	CreateDeviceAuthorization(ctx context.Context, in NewDeviceAuthorization) error
	GetDeviceAuthorizationByDeviceCodeHash(ctx context.Context, hash string) (DeviceAuthorization, error)
	GetDeviceAuthorizationByUserCodeHash(ctx context.Context, hash string) (DeviceAuthorization, error)
	MarkDeviceAuthorizationExpired(ctx context.Context, id uuid.UUID) error
	MarkDeviceAuthorizationExchanged(ctx context.Context, id uuid.UUID) error
	TouchDeviceAuthorizationPoll(ctx context.Context, id uuid.UUID, at time.Time) error
	// ApproveDeviceAuthorization / DenyDeviceAuthorization are conditional on the
	// row still being pending; ErrNotFound means another caller resolved it first.
	ApproveDeviceAuthorization(ctx context.Context, in ResolveDeviceAuthorization) error
	DenyDeviceAuthorization(ctx context.Context, in ResolveDeviceAuthorization) error

	// Access tokens.
	CreateAccessToken(ctx context.Context, in NewAccessToken) error
	GetAccessTokenByHash(ctx context.Context, hash string) (AccessTokenAuth, error)
	// ConsumeAgentEnrollToken atomically spends a single-use agent-enroll token;
	// returns true if this call consumed it, false if it was already consumed or
	// is not an agent-enroll token.
	ConsumeAgentEnrollToken(ctx context.Context, hash string) (bool, error)

	// Refresh tokens.
	CreateRefreshToken(ctx context.Context, in NewRefreshToken) error
	GetRefreshTokenByHash(ctx context.Context, hash string) (RefreshTokenAuth, error)
	MarkRefreshTokenRotated(ctx context.Context, id uuid.UUID) error
	RevokeRefreshTokenFamily(ctx context.Context, familyID uuid.UUID) error

	// Users.
	GetUser(ctx context.Context, id uuid.UUID) (User, error)
	SumActiveAllocationBytes(ctx context.Context, userID uuid.UUID) (int64, error)
}

// SessionStore is the sessions data layer plus transaction control.
type SessionStore interface {
	SessionOps
	beginner
}
