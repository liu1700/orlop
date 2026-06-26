package allocations_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/allocations"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/db"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/db/sqlcdb"
)

const (
	GiB = int64(1) << 30
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
		t.Skip("TEST_DATABASE_URL not set; skipping postgres-backed allocations test")
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
			"TRUNCATE TABLE server_pool, disk_allocations, refresh_tokens, access_tokens, device_authorizations, agent_enrollments, server_vms, users, tenants RESTART IDENTITY CASCADE")
		pool.Close()
	})
	return pool
}

// seedUser creates a tenant + user with the given quota and returns the
// user row.
func seedUser(t *testing.T, pool *pgxpool.Pool, email string, quotaBytes int64) sqlcdb.User {
	t.Helper()
	q := sqlcdb.New(pool)
	ctx := context.Background()
	tenantID := "tenant-" + email
	if _, err := q.CreateTenant(ctx, sqlcdb.CreateTenantParams{ID: tenantID, Name: tenantID}); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	user, err := q.CreateUser(ctx, sqlcdb.CreateUserParams{Email: email, TenantID: tenantID})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	// Override default quota so each test can pick its own.
	if _, err := pool.Exec(ctx, "UPDATE users SET quota_bytes = $1 WHERE id = $2", quotaBytes, user.ID); err != nil {
		t.Fatalf("set quota: %v", err)
	}
	user.QuotaBytes = quotaBytes
	return user
}

// seedAgent creates an agent_enrollments row for the given user and returns
// its UUID. Cert serial is randomised so multiple agents per user work.
func seedAgent(t *testing.T, pool *pgxpool.Pool, userID pgtype.UUID) pgtype.UUID {
	t.Helper()
	q := sqlcdb.New(pool)
	var serial [8]byte
	if _, err := rand.Read(serial[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	row, err := q.CreateAgentEnrollment(context.Background(), sqlcdb.CreateAgentEnrollmentParams{
		UserID:       userID,
		CertSerial:   hex.EncodeToString(serial[:]),
		CertNotAfter: pgtype.Timestamptz{Time: time.Now().Add(24 * time.Hour), Valid: true},
	})
	if err != nil {
		t.Fatalf("create enrollment: %v", err)
	}
	return row.ID
}

// withSvc constructs the service for a fresh test.
func withSvc(t *testing.T) (*allocations.Service, *pgxpool.Pool) {
	t.Helper()
	pool := openTestPool(t)
	return allocations.NewService(pool, nil), pool
}

func TestAllocateHappyPath(t *testing.T) {
	svc, pool := withSvc(t)
	user := seedUser(t, pool, "alice@acme.example", 10*GiB)

	a, err := svc.Allocate(context.Background(), user.ID, 5*GiB)
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if a.SizeBytes != 5*GiB {
		t.Fatalf("size: got %d want %d", a.SizeBytes, 5*GiB)
	}
	if a.BoundAgentID != nil || a.BoundAt != nil || a.LeaseExpiresAt != nil {
		t.Fatalf("expected Free state, got bound=%v boundAt=%v lease=%v",
			a.BoundAgentID, a.BoundAt, a.LeaseExpiresAt)
	}
	if a.RevokedAt != nil {
		t.Fatalf("expected non-revoked, got %v", a.RevokedAt)
	}
}

func TestAllocateQuotaExceeded(t *testing.T) {
	svc, pool := withSvc(t)
	ctx := context.Background()
	user := seedUser(t, pool, "alice@acme.example", 10*GiB)

	if _, err := svc.Allocate(ctx, user.ID, 6*GiB); err != nil {
		t.Fatalf("first Allocate: %v", err)
	}
	_, err := svc.Allocate(ctx, user.ID, 5*GiB)
	if !errors.Is(err, allocations.ErrQuotaExceeded) {
		t.Fatalf("want ErrQuotaExceeded, got %v", err)
	}

	// And no second row exists.
	var n int
	if err := pool.QueryRow(ctx, "SELECT COUNT(*) FROM disk_allocations").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("rows: got %d want 1", n)
	}
}

func TestRevokeIdempotentAndDecrementsQuota(t *testing.T) {
	svc, pool := withSvc(t)
	ctx := context.Background()
	user := seedUser(t, pool, "alice@acme.example", 10*GiB)

	a, err := svc.Allocate(ctx, user.ID, 5*GiB)
	if err != nil {
		t.Fatal(err)
	}

	if err := svc.Revoke(ctx, a.ID, user.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	// Idempotent: second Revoke is a no-op.
	if err := svc.Revoke(ctx, a.ID, user.ID); err != nil {
		t.Fatalf("Revoke (second): %v", err)
	}

	// Active sum drops to zero; total row count stays at 1 (soft delete).
	var sum int64
	if err := pool.QueryRow(ctx,
		"SELECT COALESCE(SUM(size_bytes),0) FROM disk_allocations WHERE user_id=$1 AND revoked_at IS NULL",
		user.ID).Scan(&sum); err != nil {
		t.Fatal(err)
	}
	if sum != 0 {
		t.Fatalf("active sum: got %d want 0", sum)
	}
	var total int
	if err := pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM disk_allocations WHERE user_id=$1", user.ID).Scan(&total); err != nil {
		t.Fatal(err)
	}
	if total != 1 {
		t.Fatalf("rows: got %d want 1 (soft delete keeps the row)", total)
	}
}

func TestAllocateConcurrentRace(t *testing.T) {
	svc, pool := withSvc(t)
	ctx := context.Background()
	user := seedUser(t, pool, "alice@acme.example", 10*GiB)

	// Two concurrent allocates of 6 GiB each — sum is 12, quota is 10.
	// Exactly one must succeed.
	type result struct {
		ok  bool
		err error
	}
	results := make(chan result, 2)
	start := make(chan struct{})
	for i := 0; i < 2; i++ {
		go func() {
			<-start
			_, err := svc.Allocate(ctx, user.ID, 6*GiB)
			results <- result{ok: err == nil, err: err}
		}()
	}
	close(start)

	var successes, quotaErrs int
	for i := 0; i < 2; i++ {
		r := <-results
		if r.ok {
			successes++
		} else if errors.Is(r.err, allocations.ErrQuotaExceeded) {
			quotaErrs++
		} else {
			t.Fatalf("unexpected error: %v", r.err)
		}
	}
	if successes != 1 || quotaErrs != 1 {
		t.Fatalf("got %d successes / %d quota errors; want 1 / 1", successes, quotaErrs)
	}
}

func TestBindHappyPathAndAlreadyBound(t *testing.T) {
	svc, pool := withSvc(t)
	ctx := context.Background()
	user := seedUser(t, pool, "alice@acme.example", 10*GiB)
	agent1 := seedAgent(t, pool, user.ID)
	agent2 := seedAgent(t, pool, user.ID)

	a, err := svc.Allocate(ctx, user.ID, 5*GiB)
	if err != nil {
		t.Fatal(err)
	}

	bound, err := svc.Bind(ctx, a.ID, user.ID, agent1)
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if bound.BoundAgentID == nil || bound.BoundAgentID.Bytes != agent1.Bytes {
		t.Fatalf("BoundAgentID: got %v want %v", bound.BoundAgentID, agent1)
	}
	if bound.BoundAt == nil {
		t.Fatalf("BoundAt is nil; want set")
	}

	// Re-binding to a second agent must fail.
	if _, err := svc.Bind(ctx, a.ID, user.ID, agent2); !errors.Is(err, allocations.ErrAlreadyBound) {
		t.Fatalf("rebind: got %v want ErrAlreadyBound", err)
	}
}

func TestBindRevokedFails(t *testing.T) {
	svc, pool := withSvc(t)
	ctx := context.Background()
	user := seedUser(t, pool, "alice@acme.example", 10*GiB)
	agent := seedAgent(t, pool, user.ID)

	a, err := svc.Allocate(ctx, user.ID, 5*GiB)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Revoke(ctx, a.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Bind(ctx, a.ID, user.ID, agent); !errors.Is(err, allocations.ErrRevoked) {
		t.Fatalf("Bind after revoke: got %v want ErrRevoked", err)
	}
}

func TestListForUserExcludesRevokedAndOtherUsers(t *testing.T) {
	svc, pool := withSvc(t)
	ctx := context.Background()
	alice := seedUser(t, pool, "alice@acme.example", 10*GiB)
	bob := seedUser(t, pool, "bob@acme.example", 10*GiB)

	a1, _ := svc.Allocate(ctx, alice.ID, 1*GiB)
	a2, _ := svc.Allocate(ctx, alice.ID, 2*GiB)
	a3, _ := svc.Allocate(ctx, alice.ID, 3*GiB)
	if err := svc.Revoke(ctx, a2.ID, alice.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Allocate(ctx, bob.ID, 4*GiB); err != nil {
		t.Fatal(err)
	}

	got, err := svc.ListForUser(ctx, alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("len: got %d want 2", len(got))
	}
	gotIDs := map[pgtype.UUID]bool{got[0].ID: true, got[1].ID: true}
	if !gotIDs[a1.ID] || !gotIDs[a3.ID] {
		t.Fatalf("missing expected ids: got %v", gotIDs)
	}
}

// AcquireMountLease unconditionally takes over: an allocation is single-agent, so the
// handler's ownership check (not the lease row) provides exclusivity. A second acquire —
// here by a second enrollment of the same owner, the way a one-shot pod re-mounts with a
// fresh cert — takes the lease over rather than erroring.
func TestAcquireMountLeaseTakesOver(t *testing.T) {
	svc, pool := withSvc(t)
	ctx := context.Background()
	user := seedUser(t, pool, "alice@acme.example", 10*GiB)
	agent1 := seedAgent(t, pool, user.ID)
	agent2 := seedAgent(t, pool, user.ID)

	a, _ := svc.Allocate(ctx, user.ID, 5*GiB)
	if _, err := svc.Bind(ctx, a.ID, user.ID, agent1); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AcquireMountLease(ctx, a.ID, agent1, allocations.LeaseTTL); err != nil {
		t.Fatalf("agent1 acquire: %v", err)
	}
	got, err := svc.AcquireMountLease(ctx, a.ID, agent2, allocations.LeaseTTL)
	if err != nil {
		t.Fatalf("second acquire should take over, got %v", err)
	}
	if got.BoundAgentID == nil || got.BoundAgentID.Bytes != agent2.Bytes {
		t.Fatalf("BoundAgentID after takeover: got %v want %v", got.BoundAgentID, agent2)
	}
}

func TestAcquireMountLeaseSameAgentRecoversAfterExpiry(t *testing.T) {
	svc, pool := withSvc(t)
	ctx := context.Background()
	user := seedUser(t, pool, "alice@acme.example", 10*GiB)
	agent := seedAgent(t, pool, user.ID)

	a, _ := svc.Allocate(ctx, user.ID, 5*GiB)
	if _, err := svc.Bind(ctx, a.ID, user.ID, agent); err != nil {
		t.Fatal(err)
	}

	if _, err := svc.AcquireMountLease(ctx, a.ID, agent, 100*time.Millisecond); err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	time.Sleep(250 * time.Millisecond)
	if _, err := svc.AcquireMountLease(ctx, a.ID, agent, allocations.LeaseTTL); err != nil {
		t.Fatalf("re-acquire after expiry: %v", err)
	}
}

// The same agent re-acquiring its OWN still-live lease takes it over (refreshes the
// expiry) instead of erroring — the one-shot-pod model re-mounts the same agent every
// turn, and a leaked lease from the prior pod must not block the next one.
func TestAcquireMountLeaseSameAgentTakesOverLiveLease(t *testing.T) {
	svc, pool := withSvc(t)
	ctx := context.Background()
	user := seedUser(t, pool, "alice@acme.example", 10*GiB)
	agent := seedAgent(t, pool, user.ID)

	a, _ := svc.Allocate(ctx, user.ID, 5*GiB)
	if _, err := svc.Bind(ctx, a.ID, user.ID, agent); err != nil {
		t.Fatal(err)
	}
	first, err := svc.AcquireMountLease(ctx, a.ID, agent, allocations.LeaseTTL)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	// No wait — the lease is still live. The same agent must re-acquire (takeover),
	// not get ErrAlreadyMounted.
	second, err := svc.AcquireMountLease(ctx, a.ID, agent, allocations.LeaseTTL)
	if err != nil {
		t.Fatalf("same-agent re-acquire of a live lease: got %v, want success (takeover)", err)
	}
	if second.BoundAgentID == nil || second.BoundAgentID.Bytes != agent.Bytes {
		t.Fatalf("BoundAgentID after takeover: got %v want %v", second.BoundAgentID, agent)
	}
	if !second.LeaseExpiresAt.After(first.LeaseExpiresAt.Add(-time.Second)) {
		t.Fatalf("takeover should refresh the lease expiry")
	}
}

func TestAcquireMountLeaseDifferentAgentCanTakeOverAfterExpiry(t *testing.T) {
	svc, pool := withSvc(t)
	ctx := context.Background()
	user := seedUser(t, pool, "alice@acme.example", 10*GiB)
	agent1 := seedAgent(t, pool, user.ID)
	agent2 := seedAgent(t, pool, user.ID)

	a, _ := svc.Allocate(ctx, user.ID, 5*GiB)
	if _, err := svc.Bind(ctx, a.ID, user.ID, agent1); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AcquireMountLease(ctx, a.ID, agent1, 100*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(250 * time.Millisecond)
	got, err := svc.AcquireMountLease(ctx, a.ID, agent2, allocations.LeaseTTL)
	if err != nil {
		t.Fatalf("agent2 takeover: %v", err)
	}
	if got.BoundAgentID == nil || got.BoundAgentID.Bytes != agent2.Bytes {
		t.Fatalf("BoundAgentID: got %v want %v", got.BoundAgentID, agent2)
	}
}

func TestRefreshMountLeaseExtends(t *testing.T) {
	svc, pool := withSvc(t)
	ctx := context.Background()
	user := seedUser(t, pool, "alice@acme.example", 10*GiB)
	agent := seedAgent(t, pool, user.ID)

	a, _ := svc.Allocate(ctx, user.ID, 5*GiB)
	if _, err := svc.Bind(ctx, a.ID, user.ID, agent); err != nil {
		t.Fatal(err)
	}
	first, err := svc.AcquireMountLease(ctx, a.ID, agent, 1*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	second, err := svc.RefreshMountLease(ctx, a.ID, agent, 5*time.Second)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if !second.LeaseExpiresAt.After(*first.LeaseExpiresAt) {
		t.Fatalf("lease did not extend: first=%v second=%v",
			first.LeaseExpiresAt, second.LeaseExpiresAt)
	}
}

func TestRefreshMountLeaseAfterExpiryFails(t *testing.T) {
	svc, pool := withSvc(t)
	ctx := context.Background()
	user := seedUser(t, pool, "alice@acme.example", 10*GiB)
	agent := seedAgent(t, pool, user.ID)

	a, _ := svc.Allocate(ctx, user.ID, 5*GiB)
	if _, err := svc.Bind(ctx, a.ID, user.ID, agent); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AcquireMountLease(ctx, a.ID, agent, 100*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(250 * time.Millisecond)
	if _, err := svc.RefreshMountLease(ctx, a.ID, agent, allocations.LeaseTTL); !errors.Is(err, allocations.ErrLeaseLost) {
		t.Fatalf("Refresh after expiry: got %v want ErrLeaseLost", err)
	}
}

func TestRevokeWhileMountedRefreshFails(t *testing.T) {
	// Spec test #11: revoking a Mounted allocation must immediately surface
	// as ErrRevoked on the next Refresh call (force-revoke policy).
	svc, pool := withSvc(t)
	ctx := context.Background()
	user := seedUser(t, pool, "alice@acme.example", 10*GiB)
	agent := seedAgent(t, pool, user.ID)

	a, _ := svc.Allocate(ctx, user.ID, 5*GiB)
	if _, err := svc.Bind(ctx, a.ID, user.ID, agent); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AcquireMountLease(ctx, a.ID, agent, allocations.LeaseTTL); err != nil {
		t.Fatal(err)
	}
	if err := svc.Revoke(ctx, a.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RefreshMountLease(ctx, a.ID, agent, allocations.LeaseTTL); !errors.Is(err, allocations.ErrRevoked) {
		t.Fatalf("Refresh after revoke: got %v want ErrRevoked", err)
	}
}

func TestReleaseFreesForRebinding(t *testing.T) {
	svc, pool := withSvc(t)
	ctx := context.Background()
	user := seedUser(t, pool, "alice@acme.example", 10*GiB)
	agent1 := seedAgent(t, pool, user.ID)
	agent2 := seedAgent(t, pool, user.ID)

	a, _ := svc.Allocate(ctx, user.ID, 5*GiB)
	if _, err := svc.Bind(ctx, a.ID, user.ID, agent1); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AcquireMountLease(ctx, a.ID, agent1, allocations.LeaseTTL); err != nil {
		t.Fatal(err)
	}
	if err := svc.ReleaseMountLease(ctx, a.ID, agent1); err != nil {
		t.Fatalf("Release: %v", err)
	}

	// After release, agent2 can Bind + Acquire.
	if _, err := svc.Bind(ctx, a.ID, user.ID, agent2); err != nil {
		t.Fatalf("rebind to agent2: %v", err)
	}
	if _, err := svc.AcquireMountLease(ctx, a.ID, agent2, allocations.LeaseTTL); err != nil {
		t.Fatalf("agent2 acquire: %v", err)
	}

	// Allocation still counts against quota.
	var sum int64
	if err := pool.QueryRow(ctx,
		"SELECT COALESCE(SUM(size_bytes),0) FROM disk_allocations WHERE user_id=$1 AND revoked_at IS NULL",
		user.ID).Scan(&sum); err != nil {
		t.Fatal(err)
	}
	if sum != 5*GiB {
		t.Fatalf("active sum: got %d want %d", sum, 5*GiB)
	}
}

func TestReleaseIsIdempotent(t *testing.T) {
	svc, pool := withSvc(t)
	ctx := context.Background()
	user := seedUser(t, pool, "alice@acme.example", 10*GiB)
	agent := seedAgent(t, pool, user.ID)

	a, _ := svc.Allocate(ctx, user.ID, 5*GiB)
	if _, err := svc.Bind(ctx, a.ID, user.ID, agent); err != nil {
		t.Fatal(err)
	}
	if err := svc.ReleaseMountLease(ctx, a.ID, agent); err != nil {
		t.Fatal(err)
	}
	// Second call on an already-Free row is a no-op.
	if err := svc.ReleaseMountLease(ctx, a.ID, agent); err != nil {
		t.Fatalf("second Release: %v", err)
	}
}
