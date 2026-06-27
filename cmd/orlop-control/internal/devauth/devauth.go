// Package devauth implements the opaque bearer-token middleware that
// downstream endpoints (POST /agent/enroll, the admin-session dashboard, and
// future control-plane APIs) use to resolve {user_id, tenant_id} from an
// opaque access token.
//
// Storage invariants:
//   - access_token raw values exist only on the wire; the database stores
//     SHA-256 hex hashes.
//   - Single-use agent-enroll tokens are spent exactly once (the underlying
//     UPDATE is gated on consumed_at IS NULL).
package devauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
)

// Tunables fixed by the hosted-MVP design. Hardcoded rather than env-knob'd to
// keep moving parts to a minimum; tighten by code change if a deployment needs
// different values.
const (
	AdminSessionTTL = 30 * 24 * time.Hour

	// AgentEnrollTokenTTL is the lifetime of a per-pod, agent-scoped enroll
	// token minted by IssueAgentEnrollToken. It is short because the token is
	// injected into a pod at launch and traded for a cert at /agent/enroll
	// immediately; it never needs to survive a pod restart.
	AgentEnrollTokenTTL = 10 * time.Minute

	PurposeAdmin    = "admin_session"
	PurposeAPIToken = "api_token"
	// PurposeAgentEnroll marks an access_token minted for a single agent's pod
	// to trade at /agent/enroll. It carries the agent's allocation_id so the
	// enroll handler resolves the agent's allocation (and the cert gets the
	// per-agent SAN). It authenticates only on the enroll route (see
	// AuthenticateEnrollBearer / RequireEnrollBearer).
	PurposeAgentEnroll = "agent_enroll"

	AdminSessionCookie = "orlop_admin_session"
)

// Sentinel errors. Callers map these to HTTP status codes and audit
// outcomes; raw error text never leaks to clients.
var (
	ErrBearerMissing     = errors.New("missing bearer token")
	ErrTokenUnknown      = errors.New("unknown token")
	ErrTokenWrongPurpose = errors.New("token purpose mismatch")
	ErrTokenRevoked      = errors.New("token revoked")
	ErrTokenConsumed     = errors.New("token already consumed")
	ErrTokenExpired      = errors.New("token expired")
	ErrUserSuspended     = errors.New("user suspended")
	ErrTenantSuspended   = errors.New("tenant suspended")
)

// Service owns access-token issuance and validation. Safe for concurrent use.
type Service struct {
	store  storage.SessionStore
	logger *slog.Logger
	now    func() time.Time
	rand   func(p []byte) (int, error)
}

// NewService wires a Service against the given session store. logger may be nil
// (no-op).
func NewService(store storage.SessionStore, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Service{
		store:  store,
		logger: logger,
		now:    func() time.Time { return time.Now().UTC() },
		rand:   rand.Read,
	}
}

// --- boundary conversions: devauth.Identity still speaks pgtype.UUID (its
// consumers, the handlers, are migrated later); storage speaks uuid.UUID. ---

func toUUID(u pgtype.UUID) uuid.UUID {
	if !u.Valid {
		return uuid.UUID{}
	}
	return uuid.UUID(u.Bytes)
}

func fromUUID(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: true} }

func fromUUIDPtr(id *uuid.UUID) pgtype.UUID {
	if id == nil {
		return pgtype.UUID{}
	}
	return pgtype.UUID{Bytes: *id, Valid: true}
}

func toUUIDPtr(u pgtype.UUID) *uuid.UUID {
	if !u.Valid {
		return nil
	}
	id := uuid.UUID(u.Bytes)
	return &id
}

// Identity is what the bearer middleware injects into request context.
type Identity struct {
	UserID       pgtype.UUID
	TenantID     string
	Purpose      string
	AllocationID pgtype.UUID
}

// IssueAdminSession mints an admin_session bearer token. Used by the
// `orlop-control user seed` runbook command; never exposed over HTTP.
func (s *Service) IssueAdminSession(ctx context.Context, userID pgtype.UUID, tenantID string) (string, time.Time, error) {
	tok, err := s.randomToken()
	if err != nil {
		return "", time.Time{}, err
	}
	expires := s.now().Add(AdminSessionTTL)
	if err := s.store.CreateAccessToken(ctx, storage.NewAccessToken{
		TokenHash: hashCode(tok),
		Purpose:   PurposeAdmin,
		UserID:    toUUID(userID),
		TenantID:  tenantID,
		ExpiresAt: expires,
	}); err != nil {
		return "", time.Time{}, fmt.Errorf("create admin session: %w", err)
	}
	return tok, expires, nil
}

// AuthenticateEnrollBearer validates a bearer for the /agent/enroll route. It
// accepts a per-pod agent-scoped enroll token (PurposeAgentEnroll) minted by
// IssueAgentEnrollToken. The orthogonal `orlop_` API-token branch is handled in
// requireBearer.
func (s *Service) AuthenticateEnrollBearer(ctx context.Context, header string) (Identity, error) {
	raw := bearerToken(header)
	return s.authenticateRaw(ctx, raw, PurposeAgentEnroll)
}

// AuthenticateAdminSession validates an admin_session token (cookie value).
func (s *Service) AuthenticateAdminSession(ctx context.Context, raw string) (Identity, error) {
	return s.authenticateRaw(ctx, raw, PurposeAdmin)
}

// IssueAgentEnrollToken mints a short-lived, agent-scoped enroll token bound to
// a specific allocation. The orlop control-plane calls this at pod launch (via
// the service-token-gated POST /v1/agents/{id}/enroll-token) and injects the
// returned token directly as the mounter sidecar's ORLOP_ENROLL_TOKEN env. The
// pod trades it at /agent/enroll: because the token carries allocationID, the
// enroll handler resolves the agent's allocation and the cert gets the
// per-agent SAN (Phase 2), which the orlop server enforces (Phase 3).
//
// userID/tenantID are the agent owner's (agents.user_id and that user's
// tenant) — the same {user, tenant} the enroll handler resolves.
func (s *Service) IssueAgentEnrollToken(ctx context.Context, userID pgtype.UUID, tenantID string, allocationID pgtype.UUID) (token string, expiresAt time.Time, err error) {
	token, err = s.randomToken()
	if err != nil {
		return "", time.Time{}, err
	}
	expiresAt = s.now().Add(AgentEnrollTokenTTL)
	if err = s.store.CreateAccessToken(ctx, storage.NewAccessToken{
		TokenHash:    hashCode(token),
		Purpose:      PurposeAgentEnroll,
		UserID:       toUUID(userID),
		TenantID:     tenantID,
		ExpiresAt:    expiresAt,
		AllocationID: toUUIDPtr(allocationID),
	}); err != nil {
		return "", time.Time{}, fmt.Errorf("create agent enroll token: %w", err)
	}
	return token, expiresAt, nil
}

// ConsumeAgentEnrollToken atomically marks a single-use agent-enroll token
// spent, given the raw "Authorization: Bearer <token>" header. It returns true
// when this call consumed the token, and false when the token was already
// consumed — a replay, or the loser of a concurrent race — in which case the
// caller MUST reject the enroll rather than hand out a second cert.
//
// The underlying UPDATE matches only purpose='agent_enroll' rows.
func (s *Service) ConsumeAgentEnrollToken(ctx context.Context, header string) (bool, error) {
	raw := bearerToken(header)
	if raw == "" {
		return false, ErrBearerMissing
	}
	return s.store.ConsumeAgentEnrollToken(ctx, hashCode(raw))
}

// authenticateRaw resolves an Identity from an opaque token, requiring the
// stored purpose to match one of acceptedPurposes. Passing a single purpose
// preserves exact-equality semantics; passing more than one accepts any of them.
func (s *Service) authenticateRaw(ctx context.Context, raw string, acceptedPurposes ...string) (Identity, error) {
	if raw == "" {
		return Identity{}, ErrBearerMissing
	}
	row, err := s.store.GetAccessTokenByHash(ctx, hashCode(raw))
	if errors.Is(err, storage.ErrNotFound) {
		return Identity{}, ErrTokenUnknown
	}
	if err != nil {
		return Identity{}, err
	}
	purposeOK := false
	for _, p := range acceptedPurposes {
		if row.Purpose == p {
			purposeOK = true
			break
		}
	}
	if !purposeOK {
		return Identity{}, ErrTokenWrongPurpose
	}
	if row.Revoked {
		return Identity{}, ErrTokenRevoked
	}
	// Single-use enroll tokens (issue #6): once an agent-enroll token has been
	// spent on a successful /agent/enroll, consumed_at is set and any replay is
	// rejected here, cheaply, before the handler does any minting work. Admin/
	// api tokens are multi-use and never carry consumed_at, so this is a no-op
	// for them.
	if row.Consumed {
		return Identity{}, ErrTokenConsumed
	}
	if s.now().After(row.ExpiresAt) {
		return Identity{}, ErrTokenExpired
	}
	if row.UserSuspended {
		return Identity{}, ErrUserSuspended
	}
	if row.TenantSuspended {
		return Identity{}, ErrTenantSuspended
	}
	return Identity{UserID: fromUUID(row.UserID), TenantID: row.TenantID, Purpose: row.Purpose, AllocationID: fromUUIDPtr(row.AllocationID)}, nil
}

// --- helpers ---

// randomToken returns a 16-byte random value (128 bits) as base64-url
// without padding. 22 ASCII chars on the wire.
func (s *Service) randomToken() (string, error) {
	var b [16]byte
	if _, err := s.rand(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// hashCode is SHA-256 hex; constant-time index lookup via DB UNIQUE
// makes timing attacks against the hash space unproductive.
func hashCode(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func bearerToken(header string) string {
	const prefix = "Bearer "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(header[len(prefix):])
}
