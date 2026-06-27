package devauth_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/db"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/db/sqlcdb"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/devauth"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage/postgres"
)

func testDatabaseURL() string { return os.Getenv("TEST_DATABASE_URL") }

var (
	migrateOnce sync.Once
	migrateErr  error
)

func openTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := testDatabaseURL()
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping postgres-backed devauth test")
	}
	migrateOnce.Do(func() {
		migrateErr = db.MigrateUp(context.Background(), url)
	})
	if migrateErr != nil {
		t.Fatalf("migrate up: %v", migrateErr)
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			"TRUNCATE TABLE disk_allocations, refresh_tokens, access_tokens, device_authorizations, agent_enrollments, server_vms, users, tenants RESTART IDENTITY CASCADE")
		pool.Close()
	})
	return pool
}

// seedTenantUser creates one tenant + one user and returns an admin
// Identity bound to them. Used to drive Approve / Deny.
func seedTenantUser(t *testing.T, pool *pgxpool.Pool, tenantID, email string) devauth.Identity {
	t.Helper()
	q := sqlcdb.New(pool)
	ctx := context.Background()
	if _, err := q.CreateTenant(ctx, sqlcdb.CreateTenantParams{ID: tenantID, Name: tenantID}); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	user, err := q.CreateUser(ctx, sqlcdb.CreateUserParams{Email: email, TenantID: tenantID})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	return devauth.Identity{UserID: user.ID, TenantID: tenantID, Purpose: devauth.PurposeAdmin}
}

func issueApprovedSession(t *testing.T, pool *pgxpool.Pool, svc *devauth.Service) devauth.PollResult {
	t.Helper()
	ident := seedTenantUser(t, pool, "acme", "alice@acme.example")
	ctx := context.Background()
	deviceCode, userCode, _, err := svc.CreateDeviceCode(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ApproveByUserCode(ctx, userCode, ident); err != nil {
		t.Fatal(err)
	}
	time.Sleep(devauth.PollInterval + 200*time.Millisecond)
	res, err := svc.Poll(ctx, deviceCode)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func hashForTest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestEndToEndDeviceFlowHappyPath(t *testing.T) {
	pool := openTestPool(t)
	svc := devauth.NewService(postgres.New(pool), nil)
	ident := seedTenantUser(t, pool, "acme", "alice@acme.example")
	ctx := context.Background()

	deviceCode, userCode, expiresAt, err := svc.CreateDeviceCode(ctx)
	if err != nil {
		t.Fatalf("create device code: %v", err)
	}
	if !expiresAt.After(time.Now()) {
		t.Fatalf("expiresAt %v not in the future", expiresAt)
	}
	if len(deviceCode) != 22 || len(userCode) != 8 {
		t.Fatalf("token shapes: deviceCode=%q userCode=%q", deviceCode, userCode)
	}

	// First poll before approval → authorization_pending.
	res, err := svc.Poll(ctx, deviceCode)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "authorization_pending" {
		t.Fatalf("status = %s, want authorization_pending", res.Status)
	}

	// Approve.
	if err := svc.ApproveByUserCode(ctx, userCode, ident); err != nil {
		t.Fatalf("approve: %v", err)
	}

	// Wait past PollInterval so the next poll is not slow_down'd.
	time.Sleep(devauth.PollInterval + 200*time.Millisecond)

	res, err = svc.Poll(ctx, deviceCode)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "ready" || res.AccessToken == "" || res.RefreshToken == "" {
		t.Fatalf("status = %s, access = %q, refresh = %q, want ready+tokens", res.Status, res.AccessToken, res.RefreshToken)
	}
	if res.ExpiresIn != int(devauth.AccessTokenTTL.Seconds()) {
		t.Fatalf("expires_in = %d, want %d", res.ExpiresIn, int(devauth.AccessTokenTTL.Seconds()))
	}
	if !res.AccessExpiresAt.After(time.Now()) || !res.RefreshExpiresAt.After(res.AccessExpiresAt) {
		t.Fatalf("bad expiries: access=%v refresh=%v", res.AccessExpiresAt, res.RefreshExpiresAt)
	}

	// Authenticate the issued token.
	got, err := svc.AuthenticateBearer(ctx, "Bearer "+res.AccessToken)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if got.TenantID != "acme" {
		t.Fatalf("tenant_id = %s, want acme", got.TenantID)
	}
	if got.Purpose != devauth.PurposeDevice {
		t.Fatalf("purpose = %s, want %s", got.Purpose, devauth.PurposeDevice)
	}

	// Token should be stored as a hash, not plaintext: scan access_tokens
	// for the raw value and ensure it never appears.
	rows, err := pool.Query(ctx, "SELECT token_hash FROM access_tokens")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			t.Fatal(err)
		}
		if hash == res.AccessToken {
			t.Fatal("access_token stored as plaintext")
		}
	}
	rowsRefresh, err := pool.Query(ctx, "SELECT token_hash FROM refresh_tokens")
	if err != nil {
		t.Fatal(err)
	}
	defer rowsRefresh.Close()
	for rowsRefresh.Next() {
		var hash string
		if err := rowsRefresh.Scan(&hash); err != nil {
			t.Fatal(err)
		}
		if hash == res.RefreshToken {
			t.Fatal("refresh_token stored as plaintext")
		}
	}

	// Same for device_authorizations: device_code and user_code must not
	// appear in their hash columns.
	rows2, err := pool.Query(ctx, "SELECT device_code_hash, user_code_hash FROM device_authorizations")
	if err != nil {
		t.Fatal(err)
	}
	defer rows2.Close()
	for rows2.Next() {
		var dh, uh string
		if err := rows2.Scan(&dh, &uh); err != nil {
			t.Fatal(err)
		}
		if dh == deviceCode || uh == userCode {
			t.Fatal("device_code or user_code stored as plaintext")
		}
	}

	// Second exchange must fail (single-use).
	res, err = svc.Poll(ctx, deviceCode)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "expired_token" {
		t.Fatalf("second exchange status = %s, want expired_token", res.Status)
	}
}

func TestRefreshRotatesTokens(t *testing.T) {
	pool := openTestPool(t)
	svc := devauth.NewService(postgres.New(pool), nil)
	res := issueApprovedSession(t, pool, svc)
	ctx := context.Background()

	refreshed, err := svc.Refresh(ctx, res.RefreshToken)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if refreshed.AccessToken == "" || refreshed.RefreshToken == "" {
		t.Fatalf("missing refreshed tokens: %#v", refreshed)
	}
	if refreshed.AccessToken == res.AccessToken || refreshed.RefreshToken == res.RefreshToken {
		t.Fatalf("tokens did not rotate")
	}
	if _, err := svc.AuthenticateBearer(ctx, "Bearer "+refreshed.AccessToken); err != nil {
		t.Fatalf("refreshed access token should authenticate: %v", err)
	}
}

func TestRefreshReuseRevokesFamily(t *testing.T) {
	pool := openTestPool(t)
	svc := devauth.NewService(postgres.New(pool), nil)
	res := issueApprovedSession(t, pool, svc)
	ctx := context.Background()

	refreshed, err := svc.Refresh(ctx, res.RefreshToken)
	if err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	if _, err := svc.Refresh(ctx, res.RefreshToken); !errors.Is(err, devauth.ErrTokenRevoked) {
		t.Fatalf("reuse refresh error = %v, want ErrTokenRevoked", err)
	}
	if _, err := svc.Refresh(ctx, refreshed.RefreshToken); !errors.Is(err, devauth.ErrTokenRevoked) {
		t.Fatalf("family refresh after reuse = %v, want ErrTokenRevoked", err)
	}
}

func TestRefreshRejectsSuspendedUserAndTenant(t *testing.T) {
	pool := openTestPool(t)
	svc := devauth.NewService(postgres.New(pool), nil)
	res := issueApprovedSession(t, pool, svc)
	ctx := context.Background()
	q := sqlcdb.New(pool)

	row, err := q.GetRefreshTokenByHash(ctx, hashForTest(res.RefreshToken))
	if err != nil {
		t.Fatal(err)
	}
	if err := q.SuspendUser(ctx, row.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Refresh(ctx, res.RefreshToken); !errors.Is(err, devauth.ErrUserSuspended) {
		t.Fatalf("suspended user refresh = %v, want ErrUserSuspended", err)
	}
	if err := q.UnsuspendUser(ctx, row.UserID); err != nil {
		t.Fatal(err)
	}
	if err := q.SuspendTenant(ctx, row.TenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Refresh(ctx, res.RefreshToken); !errors.Is(err, devauth.ErrTenantSuspended) {
		t.Fatalf("suspended tenant refresh = %v, want ErrTenantSuspended", err)
	}
}

func TestSlowDownReturnedWhenPollingTooFast(t *testing.T) {
	pool := openTestPool(t)
	svc := devauth.NewService(postgres.New(pool), nil)
	_ = seedTenantUser(t, pool, "acme", "alice@acme.example")
	ctx := context.Background()

	deviceCode, _, _, err := svc.CreateDeviceCode(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Poll(ctx, deviceCode); err != nil {
		t.Fatal(err)
	}
	res, err := svc.Poll(ctx, deviceCode)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "slow_down" {
		t.Fatalf("status = %s, want slow_down", res.Status)
	}
}

func TestExpiredCodeReturnsExpiredToken(t *testing.T) {
	pool := openTestPool(t)
	svc := devauth.NewService(postgres.New(pool), nil)
	_ = seedTenantUser(t, pool, "acme", "alice@acme.example")
	ctx := context.Background()

	deviceCode, _, _, err := svc.CreateDeviceCode(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Force-expire by rewriting expires_at into the past.
	if _, err := pool.Exec(ctx, "UPDATE device_authorizations SET expires_at = now() - interval '1 minute'"); err != nil {
		t.Fatal(err)
	}
	res, err := svc.Poll(ctx, deviceCode)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "expired_token" {
		t.Fatalf("status = %s, want expired_token", res.Status)
	}
}

func TestUnknownDeviceCodeReturnsExpiredToken(t *testing.T) {
	pool := openTestPool(t)
	svc := devauth.NewService(postgres.New(pool), nil)
	ctx := context.Background()
	res, err := svc.Poll(ctx, "this-device-code-does-not-exist")
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "expired_token" {
		t.Fatalf("status = %s, want expired_token", res.Status)
	}
}

func TestDeniedCodeReturnsAccessDenied(t *testing.T) {
	pool := openTestPool(t)
	svc := devauth.NewService(postgres.New(pool), nil)
	ident := seedTenantUser(t, pool, "acme", "alice@acme.example")
	ctx := context.Background()

	deviceCode, userCode, _, err := svc.CreateDeviceCode(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.DenyByUserCode(ctx, userCode, ident); err != nil {
		t.Fatal(err)
	}
	res, err := svc.Poll(ctx, deviceCode)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "access_denied" {
		t.Fatalf("status = %s, want access_denied", res.Status)
	}
}

func TestApproveTwiceFails(t *testing.T) {
	pool := openTestPool(t)
	svc := devauth.NewService(postgres.New(pool), nil)
	ident := seedTenantUser(t, pool, "acme", "alice@acme.example")
	ctx := context.Background()

	_, userCode, _, err := svc.CreateDeviceCode(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ApproveByUserCode(ctx, userCode, ident); err != nil {
		t.Fatal(err)
	}
	if err := svc.ApproveByUserCode(ctx, userCode, ident); !errors.Is(err, devauth.ErrUserCodeAlreadyResolved) {
		t.Fatalf("second approve error = %v, want ErrUserCodeAlreadyResolved", err)
	}
}

func TestApproveExpiredCodeFails(t *testing.T) {
	pool := openTestPool(t)
	svc := devauth.NewService(postgres.New(pool), nil)
	ident := seedTenantUser(t, pool, "acme", "alice@acme.example")
	ctx := context.Background()

	_, userCode, _, err := svc.CreateDeviceCode(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "UPDATE device_authorizations SET expires_at = now() - interval '1 minute'"); err != nil {
		t.Fatal(err)
	}
	if err := svc.ApproveByUserCode(ctx, userCode, ident); !errors.Is(err, devauth.ErrUserCodeExpired) {
		t.Fatalf("approve error = %v, want ErrUserCodeExpired", err)
	}
}

func TestApproveUnknownUserCode(t *testing.T) {
	pool := openTestPool(t)
	svc := devauth.NewService(postgres.New(pool), nil)
	ident := seedTenantUser(t, pool, "acme", "alice@acme.example")
	ctx := context.Background()
	if err := svc.ApproveByUserCode(ctx, "ORL-XXXX", ident); !errors.Is(err, devauth.ErrUserCodeUnknown) {
		t.Fatalf("approve unknown = %v, want ErrUserCodeUnknown", err)
	}
}

func TestAuthenticateRejectsRevokedToken(t *testing.T) {
	pool := openTestPool(t)
	svc := devauth.NewService(postgres.New(pool), nil)
	ident := seedTenantUser(t, pool, "acme", "alice@acme.example")
	ctx := context.Background()

	deviceCode, userCode, _, err := svc.CreateDeviceCode(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ApproveByUserCode(ctx, userCode, ident); err != nil {
		t.Fatal(err)
	}
	time.Sleep(devauth.PollInterval + 200*time.Millisecond)
	res, err := svc.Poll(ctx, deviceCode)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "UPDATE access_tokens SET revoked_at = now() WHERE purpose = 'device'"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AuthenticateBearer(ctx, "Bearer "+res.AccessToken); !errors.Is(err, devauth.ErrTokenRevoked) {
		t.Fatalf("authenticate revoked = %v, want ErrTokenRevoked", err)
	}
}

func TestAuthenticateRejectsSuspendedUser(t *testing.T) {
	pool := openTestPool(t)
	svc := devauth.NewService(postgres.New(pool), nil)
	ident := seedTenantUser(t, pool, "acme", "alice@acme.example")
	ctx := context.Background()

	deviceCode, userCode, _, err := svc.CreateDeviceCode(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ApproveByUserCode(ctx, userCode, ident); err != nil {
		t.Fatal(err)
	}
	time.Sleep(devauth.PollInterval + 200*time.Millisecond)
	res, err := svc.Poll(ctx, deviceCode)
	if err != nil {
		t.Fatal(err)
	}
	q := sqlcdb.New(pool)
	if err := q.SuspendUser(ctx, ident.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AuthenticateBearer(ctx, "Bearer "+res.AccessToken); !errors.Is(err, devauth.ErrUserSuspended) {
		t.Fatalf("authenticate suspended user = %v, want ErrUserSuspended", err)
	}
}

func TestAuthenticateRejectsSuspendedTenant(t *testing.T) {
	pool := openTestPool(t)
	svc := devauth.NewService(postgres.New(pool), nil)
	ident := seedTenantUser(t, pool, "acme", "alice@acme.example")
	ctx := context.Background()

	deviceCode, userCode, _, err := svc.CreateDeviceCode(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ApproveByUserCode(ctx, userCode, ident); err != nil {
		t.Fatal(err)
	}
	time.Sleep(devauth.PollInterval + 200*time.Millisecond)
	res, err := svc.Poll(ctx, deviceCode)
	if err != nil {
		t.Fatal(err)
	}
	q := sqlcdb.New(pool)
	if err := q.SuspendTenant(ctx, "acme"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AuthenticateBearer(ctx, "Bearer "+res.AccessToken); !errors.Is(err, devauth.ErrTenantSuspended) {
		t.Fatalf("authenticate suspended tenant = %v, want ErrTenantSuspended", err)
	}
}

func TestAuthenticateRejectsAdminPurposeOnBearer(t *testing.T) {
	pool := openTestPool(t)
	svc := devauth.NewService(postgres.New(pool), nil)
	ident := seedTenantUser(t, pool, "acme", "alice@acme.example")
	ctx := context.Background()

	tok, _, err := svc.IssueAdminSession(ctx, ident.UserID, ident.TenantID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AuthenticateBearer(ctx, "Bearer "+tok); !errors.Is(err, devauth.ErrTokenWrongPurpose) {
		t.Fatalf("authenticate admin-as-bearer = %v, want ErrTokenWrongPurpose", err)
	}
	if _, err := svc.AuthenticateAdminSession(ctx, tok); err != nil {
		t.Fatalf("admin session should authenticate: %v", err)
	}
}

// TestAgentEnrollTokenAuthenticatesOnEnroll proves the Phase 4 mint primitive:
// a token minted with PurposeAgentEnroll (IssueAgentEnrollToken) authenticates
// via AuthenticateEnrollBearer — the validator behind the /agent/enroll route —
// and resolves to an Identity carrying the bound allocation_id. The same token
// is rejected by the device-only AuthenticateBearer (so it never works on
// /agent/run), confirming the widened purpose set is scoped to enroll.
func TestAgentEnrollTokenAuthenticatesOnEnroll(t *testing.T) {
	pool := openTestPool(t)
	svc := devauth.NewService(postgres.New(pool), nil)
	ident := seedTenantUser(t, pool, "acme", "alice@acme.example")
	ctx := context.Background()

	// Provision an allocation the enroll token will be bound to.
	q := sqlcdb.New(pool)
	alloc, err := q.UpsertAgentAllocation(ctx, sqlcdb.UpsertAgentAllocationParams{
		UserID:    ident.UserID,
		AgentID:   pgtype.Text{String: "agent-xyz", Valid: true},
		SizeBytes: 1 << 30,
	})
	if err != nil {
		t.Fatalf("upsert allocation: %v", err)
	}

	tok, expiresAt, err := svc.IssueAgentEnrollToken(ctx, ident.UserID, ident.TenantID, alloc.ID)
	if err != nil {
		t.Fatalf("issue agent enroll token: %v", err)
	}
	if tok == "" {
		t.Fatal("empty token")
	}
	// Short TTL: well under an hour from now.
	if d := time.Until(expiresAt); d <= 0 || d > time.Hour {
		t.Fatalf("expiresAt out of range: %v from now", d)
	}

	// Accepted on the enroll path, with the bound allocation surfaced.
	got, err := svc.AuthenticateEnrollBearer(ctx, "Bearer "+tok)
	if err != nil {
		t.Fatalf("AuthenticateEnrollBearer = %v, want nil", err)
	}
	if got.AllocationID != alloc.ID {
		t.Errorf("identity allocation = %v; want %v", got.AllocationID, alloc.ID)
	}
	if got.UserID != ident.UserID {
		t.Errorf("identity user = %v; want %v", got.UserID, ident.UserID)
	}
	if got.TenantID != ident.TenantID {
		t.Errorf("identity tenant = %q; want %q", got.TenantID, ident.TenantID)
	}
	if got.Purpose != devauth.PurposeAgentEnroll {
		t.Errorf("identity purpose = %q; want %q", got.Purpose, devauth.PurposeAgentEnroll)
	}

	// Rejected by the device-only bearer (e.g. /agent/run) — purpose mismatch.
	if _, err := svc.AuthenticateBearer(ctx, "Bearer "+tok); !errors.Is(err, devauth.ErrTokenWrongPurpose) {
		t.Fatalf("device-only AuthenticateBearer = %v, want ErrTokenWrongPurpose", err)
	}
}
