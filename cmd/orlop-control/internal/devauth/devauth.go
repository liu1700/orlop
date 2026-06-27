// Package devauth implements the first-party device-code approval flow
// (issue #44, RFC 8628 shape) and the bearer-token middleware that
// downstream endpoints (POST /agent/enroll, future control-plane APIs)
// use to resolve {user_id, tenant_id} from an opaque access token.
//
// Storage invariants:
//   - device_code, user_code, access_token, and refresh_token raw values
//     exist only on the wire; the database stores SHA-256 hex hashes.
//   - A device authorization can be approved or denied exactly once
//     (the underlying UPDATE is gated on status = 'pending').
//   - Access tokens are short-lived. Refresh tokens are longer-lived,
//     rotate on every refresh, and old-token reuse revokes the family.
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

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/db/sqlcdb"
)

// Tunables fixed by issue #44 and the hosted-MVP design. Hardcoded
// rather than env-knob'd to keep moving parts to a minimum; tighten by
// code change if a deployment needs different values.
const (
	DeviceCodeTTL   = 10 * time.Minute
	AccessTokenTTL  = 1 * time.Hour
	RefreshTokenTTL = 30 * 24 * time.Hour
	AdminSessionTTL = 30 * 24 * time.Hour
	PollInterval    = 5 * time.Second

	// AgentEnrollTokenTTL is the lifetime of a per-pod, agent-scoped enroll
	// token minted by IssueAgentEnrollToken. It is short because the token is
	// injected into a pod at launch and traded for a cert at /agent/enroll
	// immediately; it never needs to survive a pod restart.
	AgentEnrollTokenTTL = 10 * time.Minute

	PurposeDevice   = "device"
	PurposeAdmin    = "admin_session"
	PurposeAPIToken = "api_token"
	// PurposeAgentEnroll marks an access_token minted for a single agent's pod
	// to trade at /agent/enroll. It carries the agent's allocation_id so the
	// enroll handler resolves the agent's allocation (and the cert gets the
	// per-agent SAN). It is NOT a device-flow token: it authenticates only on
	// the enroll route (see AuthenticateEnrollBearer / RequireEnrollBearer),
	// never on /agent/run or other device-purpose surfaces.
	PurposeAgentEnroll = "agent_enroll"

	AdminSessionCookie = "orlop_admin_session"
)

// userCodeAlphabet is Crockford-base32-ish: omits 0/1/I/L/O/U to
// minimise transcription error when a human reads ORL-K7Q9 from a
// terminal and types it into a browser.
const userCodeAlphabet = "ABCDEFGHJKMNPQRSTVWXYZ23456789"

// Sentinel errors. Callers map these to HTTP status codes and audit
// outcomes; raw error text never leaks to clients.
var (
	ErrBearerMissing           = errors.New("missing bearer token")
	ErrTokenUnknown            = errors.New("unknown token")
	ErrTokenWrongPurpose       = errors.New("token purpose mismatch")
	ErrTokenRevoked            = errors.New("token revoked")
	ErrTokenConsumed           = errors.New("token already consumed")
	ErrTokenExpired            = errors.New("token expired")
	ErrUserSuspended           = errors.New("user suspended")
	ErrTenantSuspended         = errors.New("tenant suspended")
	ErrUserCodeUnknown         = errors.New("unknown user_code")
	ErrUserCodeExpired         = errors.New("user_code expired")
	ErrUserCodeAlreadyResolved = errors.New("user_code already approved or denied")
)

// Service owns the device-flow state machine. Safe for concurrent use.
type Service struct {
	pool   *pgxpool.Pool
	q      *sqlcdb.Queries
	logger *slog.Logger
	now    func() time.Time
	rand   func(p []byte) (int, error)
}

// NewService wires a Service against the given pool. logger may be nil
// (no-op).
func NewService(pool *pgxpool.Pool, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Service{
		pool:   pool,
		q:      sqlcdb.New(pool),
		logger: logger,
		now:    func() time.Time { return time.Now().UTC() },
		rand:   rand.Read,
	}
}

// Identity is what the bearer middleware injects into request context.
type Identity struct {
	UserID       pgtype.UUID
	TenantID     string
	Purpose      string
	AllocationID pgtype.UUID
}

// CreateDeviceCode allocates a pending authorization. The returned
// deviceCode goes back to the polling client; the userCode is shown to
// the human for browser approval.
func (s *Service) CreateDeviceCode(ctx context.Context) (deviceCode, userCode string, expiresAt time.Time, err error) {
	deviceCode, err = s.randomToken()
	if err != nil {
		return "", "", time.Time{}, err
	}
	userCode, err = s.randomUserCode()
	if err != nil {
		return "", "", time.Time{}, err
	}
	expiresAt = s.now().Add(DeviceCodeTTL)
	if _, err = s.q.CreateDeviceAuthorization(ctx, sqlcdb.CreateDeviceAuthorizationParams{
		DeviceCodeHash: hashCode(deviceCode),
		UserCodeHash:   hashCode(userCode),
		ExpiresAt:      ts(expiresAt),
	}); err != nil {
		return "", "", time.Time{}, fmt.Errorf("create device authorization: %w", err)
	}
	s.logger.Info("device_authorization_created",
		"event", "device_code_created",
		"user_code_prefix", userCode[:4], // "ORL-"; no entropy leaked
		"expires_at", expiresAt,
	)
	return deviceCode, userCode, expiresAt, nil
}

// PollResult is what /auth/device/token returns. Status is one of:
// "ready", "authorization_pending", "slow_down", "expired_token",
// "access_denied". Tokens are non-empty only when Status == "ready".
type PollResult struct {
	Status           string
	AccessToken      string
	AccessExpiresAt  time.Time
	RefreshToken     string
	RefreshExpiresAt time.Time
	UserID           pgtype.UUID
	AllocationID     pgtype.UUID
	ExpiresIn        int
}

type RefreshResult struct {
	AccessToken      string
	AccessExpiresAt  time.Time
	RefreshToken     string
	RefreshExpiresAt time.Time
	UserID           pgtype.UUID
	AllocationID     pgtype.UUID
	ExpiresIn        int
}

type DeviceLookupResult struct {
	UserCode       string
	ExpiresAt      time.Time
	QuotaBytes     int64
	UsedBytes      int64
	RemainingBytes int64
}

// Poll exchanges a device_code for an access_token (when approved) or
// returns an OAuth-style error code. Single-use: a successful exchange
// marks the authorization 'exchanged' and subsequent polls return
// expired_token.
//
// Resolution order is: terminal states first (exchanged / expired /
// denied / TTL-expired), then slow_down for the remaining polls of a
// pending or just-approved row. The slow_down interval exists to bound
// brute-force on a *live* code; it would only delay the inevitable on
// a code whose decision is already recorded.
func (s *Service) Poll(ctx context.Context, deviceCode string) (PollResult, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return PollResult{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	qx := s.q.WithTx(tx)
	now := s.now()

	auth, err := qx.GetDeviceAuthorizationByDeviceCodeHash(ctx, hashCode(deviceCode))
	if errors.Is(err, pgx.ErrNoRows) {
		s.logger.Info("device_token_poll", "event", "device_token_poll", "outcome", "expired_token", "reason", "unknown_device_code")
		return PollResult{Status: "expired_token"}, nil
	}
	if err != nil {
		return PollResult{}, err
	}

	// Terminal states bypass slow_down — the answer is final, the
	// caller should stop polling.
	switch auth.Status {
	case "exchanged", "expired":
		if err := tx.Commit(ctx); err != nil {
			return PollResult{}, err
		}
		s.logAuthOutcome(auth, "device_token_poll", "expired_token", auth.Status)
		return PollResult{Status: "expired_token"}, nil
	case "denied":
		if err := tx.Commit(ctx); err != nil {
			return PollResult{}, err
		}
		s.logAuthOutcome(auth, "device_token_poll", "access_denied", "")
		return PollResult{Status: "access_denied"}, nil
	}

	// TTL-expiry check happens before slow_down too — surfacing
	// expired_token immediately is better than making a polling client
	// wait `interval` seconds to learn its code is dead.
	if !auth.ExpiresAt.Valid || now.After(auth.ExpiresAt.Time) {
		if auth.Status == "pending" {
			_ = qx.MarkDeviceAuthorizationExpired(ctx, auth.ID)
		}
		if err := tx.Commit(ctx); err != nil {
			return PollResult{}, err
		}
		s.logAuthOutcome(auth, "device_token_poll", "expired_token", "ttl")
		return PollResult{Status: "expired_token"}, nil
	}

	// slow_down: enforce minimum interval per record on still-live
	// codes. Always touch last_polled_at so abusive callers keep
	// tripping the limit.
	if auth.LastPolledAt.Valid && now.Sub(auth.LastPolledAt.Time) < PollInterval {
		_ = qx.TouchDeviceAuthorizationPoll(ctx, sqlcdb.TouchDeviceAuthorizationPollParams{
			ID: auth.ID, LastPolledAt: ts(now),
		})
		if err := tx.Commit(ctx); err != nil {
			return PollResult{}, err
		}
		s.logAuthOutcome(auth, "device_token_poll", "slow_down", "")
		return PollResult{Status: "slow_down"}, nil
	}
	if err := qx.TouchDeviceAuthorizationPoll(ctx, sqlcdb.TouchDeviceAuthorizationPollParams{
		ID: auth.ID, LastPolledAt: ts(now),
	}); err != nil {
		return PollResult{}, err
	}

	switch auth.Status {
	case "pending":
		if err := tx.Commit(ctx); err != nil {
			return PollResult{}, err
		}
		s.logAuthOutcome(auth, "device_token_poll", "authorization_pending", "")
		return PollResult{Status: "authorization_pending"}, nil
	case "approved":
		// fall through to mint
	default:
		if err := tx.Commit(ctx); err != nil {
			return PollResult{}, err
		}
		s.logAuthOutcome(auth, "device_token_poll", "expired_token", "unknown_status:"+auth.Status)
		return PollResult{Status: "expired_token"}, nil
	}

	if !auth.UserID.Valid || !auth.TenantID.Valid {
		return PollResult{}, errors.New("approved authorization missing user_id or tenant_id")
	}
	issued, err := s.issueDeviceSession(ctx, qx, auth.UserID, auth.TenantID.String, auth.AllocationID, pgtype.UUID{}, now)
	if err != nil {
		return PollResult{}, err
	}
	if err := qx.MarkDeviceAuthorizationExchanged(ctx, auth.ID); err != nil {
		return PollResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return PollResult{}, err
	}
	s.logAuthOutcome(auth, "device_token_exchange", "ready", "")
	return PollResult{
		Status:           "ready",
		AccessToken:      issued.AccessToken,
		AccessExpiresAt:  issued.AccessExpiresAt,
		RefreshToken:     issued.RefreshToken,
		RefreshExpiresAt: issued.RefreshExpiresAt,
		UserID:           auth.UserID,
		AllocationID:     auth.AllocationID,
		ExpiresIn:        int(AccessTokenTTL.Seconds()),
	}, nil
}

// Refresh rotates a refresh token and returns a fresh local session.
// Reuse of an already-rotated token revokes the entire token family.
func (s *Service) Refresh(ctx context.Context, rawRefreshToken string) (RefreshResult, error) {
	if rawRefreshToken == "" {
		return RefreshResult{}, ErrBearerMissing
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return RefreshResult{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	qx := s.q.WithTx(tx)
	now := s.now()

	row, err := qx.GetRefreshTokenByHash(ctx, hashCode(rawRefreshToken))
	if errors.Is(err, pgx.ErrNoRows) {
		return RefreshResult{}, ErrTokenUnknown
	}
	if err != nil {
		return RefreshResult{}, err
	}
	if row.RotatedAt.Valid {
		if revokeErr := qx.RevokeRefreshTokenFamily(ctx, row.FamilyID); revokeErr != nil {
			return RefreshResult{}, revokeErr
		}
		if err := tx.Commit(ctx); err != nil {
			return RefreshResult{}, err
		}
		s.logger.Warn("refresh_token_reuse",
			"event", "refresh_token_reuse",
			"family_id", uuidString(row.FamilyID),
			"tenant_id", row.TenantID,
			"user_id", uuidString(row.UserID),
		)
		return RefreshResult{}, ErrTokenRevoked
	}
	if row.RevokedAt.Valid {
		return RefreshResult{}, ErrTokenRevoked
	}
	if !row.ExpiresAt.Valid || now.After(row.ExpiresAt.Time) {
		return RefreshResult{}, ErrTokenExpired
	}
	if row.UserSuspendedAt.Valid {
		return RefreshResult{}, ErrUserSuspended
	}
	if row.TenantSuspendedAt.Valid {
		return RefreshResult{}, ErrTenantSuspended
	}
	if err := qx.MarkRefreshTokenRotated(ctx, row.ID); err != nil {
		return RefreshResult{}, err
	}
	issued, err := s.issueDeviceSession(ctx, qx, row.UserID, row.TenantID, row.AllocationID, row.FamilyID, now)
	if err != nil {
		return RefreshResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return RefreshResult{}, err
	}
	s.logger.Info("refresh_token_rotated",
		"event", "refresh_token_rotated",
		"family_id", uuidString(row.FamilyID),
		"tenant_id", row.TenantID,
		"user_id", uuidString(row.UserID),
	)
	return issued, nil
}

// ApproveByUserCode marks a pending authorization approved on behalf of
// the calling admin session's identity. Single-use; ErrUserCodeAlreadyResolved
// if another caller already approved/denied.
func (s *Service) ApproveByUserCode(ctx context.Context, userCode string, ident Identity) error {
	return s.resolveByUserCode(ctx, userCode, ident, pgtype.UUID{}, true)
}

// ApproveByUserCodeWithAllocation marks a pending authorization approved and
// links the storage allocation granted to the device.
func (s *Service) ApproveByUserCodeWithAllocation(ctx context.Context, userCode string, ident Identity, allocationID pgtype.UUID) error {
	if !allocationID.Valid {
		return errors.New("allocation_id required")
	}
	return s.resolveByUserCode(ctx, userCode, ident, allocationID, true)
}

// DenyByUserCode is the negative twin of ApproveByUserCode.
func (s *Service) DenyByUserCode(ctx context.Context, userCode string, ident Identity) error {
	return s.resolveByUserCode(ctx, userCode, ident, pgtype.UUID{}, false)
}

// LookupDeviceApproval validates a user_code for the logged-in user and returns
// quota state for the size picker.
func (s *Service) LookupDeviceApproval(ctx context.Context, userCode string, ident Identity) (DeviceLookupResult, error) {
	code := NormalizeUserCode(userCode)
	auth, err := s.q.GetDeviceAuthorizationByUserCodeHash(ctx, hashCode(code))
	if errors.Is(err, pgx.ErrNoRows) {
		s.logger.Info("device_lookup", "event", "device_lookup", "outcome", "user_code_unknown", "tenant_id", ident.TenantID)
		return DeviceLookupResult{}, ErrUserCodeUnknown
	}
	if err != nil {
		return DeviceLookupResult{}, err
	}
	if !auth.ExpiresAt.Valid || s.now().After(auth.ExpiresAt.Time) {
		s.logAuthOutcome(auth, "device_lookup", "user_code_expired", "")
		return DeviceLookupResult{}, ErrUserCodeExpired
	}
	if auth.Status != "pending" {
		s.logAuthOutcome(auth, "device_lookup", "already_resolved", auth.Status)
		return DeviceLookupResult{}, ErrUserCodeAlreadyResolved
	}
	user, err := s.q.GetUser(ctx, ident.UserID)
	if err != nil {
		return DeviceLookupResult{}, err
	}
	used, err := s.q.SumActiveAllocationBytes(ctx, ident.UserID)
	if err != nil {
		return DeviceLookupResult{}, err
	}
	remaining := user.QuotaBytes - used
	if remaining < 0 {
		remaining = 0
	}
	return DeviceLookupResult{
		UserCode:       code,
		ExpiresAt:      auth.ExpiresAt.Time,
		QuotaBytes:     user.QuotaBytes,
		UsedBytes:      used,
		RemainingBytes: remaining,
	}, nil
}

func (s *Service) resolveByUserCode(ctx context.Context, userCode string, ident Identity, allocationID pgtype.UUID, approve bool) error {
	code := NormalizeUserCode(userCode)
	auth, err := s.q.GetDeviceAuthorizationByUserCodeHash(ctx, hashCode(code))
	if errors.Is(err, pgx.ErrNoRows) {
		s.logger.Info("device_approval", "event", "device_approval", "outcome", "user_code_unknown", "tenant_id", ident.TenantID)
		return ErrUserCodeUnknown
	}
	if err != nil {
		return err
	}
	if !auth.ExpiresAt.Valid || s.now().After(auth.ExpiresAt.Time) {
		s.logAuthOutcome(auth, "device_approval", "user_code_expired", "")
		return ErrUserCodeExpired
	}
	if auth.Status != "pending" {
		s.logAuthOutcome(auth, "device_approval", "already_resolved", auth.Status)
		return ErrUserCodeAlreadyResolved
	}
	tenantParam := pgtype.Text{String: ident.TenantID, Valid: true}
	if approve {
		if _, err := s.q.ApproveDeviceAuthorization(ctx, sqlcdb.ApproveDeviceAuthorizationParams{
			ID: auth.ID, TenantID: tenantParam, UserID: ident.UserID, AllocationID: allocationID,
		}); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				s.logAuthOutcome(auth, "device_approval", "race_already_resolved", "")
				return ErrUserCodeAlreadyResolved
			}
			return err
		}
		s.logger.Info("device_approval",
			"event", "device_approval",
			"outcome", "approved",
			"tenant_id", ident.TenantID,
			"authorization_id", uuidString(auth.ID),
		)
		return nil
	}
	if _, err := s.q.DenyDeviceAuthorization(ctx, sqlcdb.DenyDeviceAuthorizationParams{
		ID: auth.ID, TenantID: tenantParam, UserID: ident.UserID,
	}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrUserCodeAlreadyResolved
		}
		return err
	}
	s.logger.Info("device_approval",
		"event", "device_approval",
		"outcome", "denied",
		"tenant_id", ident.TenantID,
		"authorization_id", uuidString(auth.ID),
	)
	return nil
}

// IssueAdminSession mints an admin_session bearer token. Used by the
// `orlop-control user seed` runbook command; never exposed over HTTP.
func (s *Service) IssueAdminSession(ctx context.Context, userID pgtype.UUID, tenantID string) (string, time.Time, error) {
	return s.issueAdminSession(ctx, s.q, userID, tenantID, s.now())
}

func (s *Service) issueAdminSession(ctx context.Context, q *sqlcdb.Queries, userID pgtype.UUID, tenantID string, now time.Time) (string, time.Time, error) {
	tok, err := s.randomToken()
	if err != nil {
		return "", time.Time{}, err
	}
	expires := now.Add(AdminSessionTTL)
	if _, err := q.CreateAccessToken(ctx, sqlcdb.CreateAccessTokenParams{
		TokenHash: hashCode(tok),
		Purpose:   PurposeAdmin,
		UserID:    userID,
		TenantID:  tenantID,
		ExpiresAt: ts(expires),
	}); err != nil {
		return "", time.Time{}, fmt.Errorf("create admin session: %w", err)
	}
	return tok, expires, nil
}

// AuthenticateBearer parses an "Authorization: Bearer <token>" header
// and validates a device-flow access_token.
func (s *Service) AuthenticateBearer(ctx context.Context, header string) (Identity, error) {
	raw := bearerToken(header)
	return s.authenticateRaw(ctx, raw, PurposeDevice)
}

// AuthenticateEnrollBearer validates a bearer for the /agent/enroll route. It
// accepts EITHER a device-flow access_token (the existing CLI/login path) OR a
// per-pod agent-scoped enroll token (PurposeAgentEnroll) minted by
// IssueAgentEnrollToken. The widened purpose set is scoped to the enroll route
// only (see RequireEnrollBearer); /agent/run and other surfaces keep using
// AuthenticateBearer (device-only).
func (s *Service) AuthenticateEnrollBearer(ctx context.Context, header string) (Identity, error) {
	raw := bearerToken(header)
	return s.authenticateRaw(ctx, raw, PurposeDevice, PurposeAgentEnroll)
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
// tenant) — the same {user, tenant} the enroll handler would otherwise resolve
// from a device session, so no synthetic principal is introduced.
func (s *Service) IssueAgentEnrollToken(ctx context.Context, userID pgtype.UUID, tenantID string, allocationID pgtype.UUID) (token string, expiresAt time.Time, err error) {
	token, err = s.randomToken()
	if err != nil {
		return "", time.Time{}, err
	}
	expiresAt = s.now().Add(AgentEnrollTokenTTL)
	if _, err = s.q.CreateAccessToken(ctx, sqlcdb.CreateAccessTokenParams{
		TokenHash:    hashCode(token),
		Purpose:      PurposeAgentEnroll,
		UserID:       userID,
		TenantID:     tenantID,
		ExpiresAt:    ts(expiresAt),
		AllocationID: allocationID,
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
// The underlying UPDATE matches only purpose='agent_enroll' rows, so device-
// session enrolls (the CLI path) never match and return false; the enroll
// handler therefore calls this only for PurposeAgentEnroll identities and
// leaves multi-use device sessions untouched.
func (s *Service) ConsumeAgentEnrollToken(ctx context.Context, header string) (bool, error) {
	raw := bearerToken(header)
	if raw == "" {
		return false, ErrBearerMissing
	}
	if _, err := s.q.ConsumeAgentEnrollToken(ctx, hashCode(raw)); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// authenticateRaw resolves an Identity from an opaque token, requiring the
// stored purpose to match one of acceptedPurposes. Passing a single purpose
// preserves the original exact-equality semantics; passing more than one (the
// enroll route) accepts any of them.
func (s *Service) authenticateRaw(ctx context.Context, raw string, acceptedPurposes ...string) (Identity, error) {
	if raw == "" {
		return Identity{}, ErrBearerMissing
	}
	row, err := s.q.GetAccessTokenByHash(ctx, hashCode(raw))
	if errors.Is(err, pgx.ErrNoRows) {
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
	if row.RevokedAt.Valid {
		return Identity{}, ErrTokenRevoked
	}
	// Single-use enroll tokens (issue #6): once an agent-enroll token has been
	// spent on a successful /agent/enroll, consumed_at is set and any replay is
	// rejected here, cheaply, before the handler does any minting work. Device/
	// admin/api tokens are multi-use and never carry consumed_at, so this is a
	// no-op for them.
	if row.ConsumedAt.Valid {
		return Identity{}, ErrTokenConsumed
	}
	if !row.ExpiresAt.Valid || s.now().After(row.ExpiresAt.Time) {
		return Identity{}, ErrTokenExpired
	}
	if row.UserSuspendedAt.Valid {
		return Identity{}, ErrUserSuspended
	}
	if row.TenantSuspendedAt.Valid {
		return Identity{}, ErrTenantSuspended
	}
	return Identity{UserID: row.UserID, TenantID: row.TenantID, Purpose: row.Purpose, AllocationID: row.AllocationID}, nil
}

// --- helpers ---

func (s *Service) issueDeviceSession(
	ctx context.Context,
	q *sqlcdb.Queries,
	userID pgtype.UUID,
	tenantID string,
	allocationID pgtype.UUID,
	familyID pgtype.UUID,
	now time.Time,
) (RefreshResult, error) {
	accessToken, err := s.randomToken()
	if err != nil {
		return RefreshResult{}, err
	}
	refreshToken, err := s.randomToken()
	if err != nil {
		return RefreshResult{}, err
	}
	if !familyID.Valid {
		familyID, err = s.randomUUID()
		if err != nil {
			return RefreshResult{}, err
		}
	}
	accessExpiresAt := now.Add(AccessTokenTTL)
	refreshExpiresAt := now.Add(RefreshTokenTTL)
	if _, err := q.CreateAccessToken(ctx, sqlcdb.CreateAccessTokenParams{
		TokenHash:    hashCode(accessToken),
		Purpose:      PurposeDevice,
		UserID:       userID,
		TenantID:     tenantID,
		ExpiresAt:    ts(accessExpiresAt),
		AllocationID: allocationID,
	}); err != nil {
		return RefreshResult{}, err
	}
	if _, err := q.CreateRefreshToken(ctx, sqlcdb.CreateRefreshTokenParams{
		TokenHash:    hashCode(refreshToken),
		FamilyID:     familyID,
		UserID:       userID,
		TenantID:     tenantID,
		ExpiresAt:    ts(refreshExpiresAt),
		AllocationID: allocationID,
	}); err != nil {
		return RefreshResult{}, err
	}
	return RefreshResult{
		AccessToken:      accessToken,
		AccessExpiresAt:  accessExpiresAt,
		RefreshToken:     refreshToken,
		RefreshExpiresAt: refreshExpiresAt,
		UserID:           userID,
		AllocationID:     allocationID,
		ExpiresIn:        int(AccessTokenTTL.Seconds()),
	}, nil
}

// randomToken returns a 16-byte random value (128 bits) as base64-url
// without padding. 22 ASCII chars on the wire.
func (s *Service) randomToken() (string, error) {
	var b [16]byte
	if _, err := s.rand(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func (s *Service) randomUUID() (pgtype.UUID, error) {
	var u pgtype.UUID
	if _, err := s.rand(u.Bytes[:]); err != nil {
		return pgtype.UUID{}, err
	}
	u.Bytes[6] = (u.Bytes[6] & 0x0f) | 0x40
	u.Bytes[8] = (u.Bytes[8] & 0x3f) | 0x80
	u.Valid = true
	return u, nil
}

// randomUserCode returns "ORL-XXXX" using a confusable-free alphabet.
// 30^4 ≈ 810k combinations; with a 10-min TTL and per-IP rate limiting
// on the approval endpoint, brute-force is infeasible for MVP.
func (s *Service) randomUserCode() (string, error) {
	var b [4]byte
	if _, err := s.rand(b[:]); err != nil {
		return "", err
	}
	out := make([]byte, 4)
	n := byte(len(userCodeAlphabet))
	for i, x := range b {
		out[i] = userCodeAlphabet[x%n]
	}
	return "ORL-" + string(out), nil
}

// NormalizeUserCode upper-cases, strips spaces and dashes, and
// re-inserts the canonical "ORL-" prefix when present. Lookup miss is
// returned by the DB layer for invalid input.
func NormalizeUserCode(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "-", "")
	if len(s) >= 3 && s[:3] == "ORL" {
		return "ORL-" + s[3:]
	}
	return s
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

func ts(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t, Valid: true}
}

func uuidString(u pgtype.UUID) string {
	if !u.Valid {
		return ""
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", u.Bytes[0:4], u.Bytes[4:6], u.Bytes[6:8], u.Bytes[8:10], u.Bytes[10:16])
}

func (s *Service) logAuthOutcome(auth sqlcdb.DeviceAuthorization, event, outcome, reason string) {
	attrs := []any{
		"event", event,
		"outcome", outcome,
		"authorization_id", uuidString(auth.ID),
	}
	if reason != "" {
		attrs = append(attrs, "reason", reason)
	}
	if auth.TenantID.Valid {
		attrs = append(attrs, "tenant_id", auth.TenantID.String)
	}
	if auth.UserID.Valid {
		attrs = append(attrs, "user_id", uuidString(auth.UserID))
	}
	s.logger.Info(event, attrs...)
}
