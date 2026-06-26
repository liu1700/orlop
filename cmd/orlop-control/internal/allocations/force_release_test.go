package allocations_test

// Tests in this file do NOT call t.Parallel(). openTestPool's cleanup
// TRUNCATEs every shared table, which races concurrently-running tests in
// this package — observed as intermittent "allocations: not found" and
// "users_tenant_id_fkey" failures in CI. Each test here is sub-100ms so
// serial execution costs nothing meaningful.

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/allocations"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/db/sqlcdb"
)

func TestForceReleaseMountLeaseClearsActiveLease(t *testing.T) {
	ctx := context.Background()
	pool := openTestPool(t)
	svc := allocations.NewService(pool, nil)

	user := seedUser(t, pool, "force-release-clear@example.com", 10*GiB)
	alloc, err := svc.Allocate(ctx, user.ID, GiB)
	if err != nil {
		t.Fatal(err)
	}
	agent := seedAgent(t, pool, user.ID)
	if _, err := svc.Bind(ctx, alloc.ID, user.ID, agent); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AcquireMountLease(ctx, alloc.ID, agent, allocations.LeaseTTL); err != nil {
		t.Fatal(err)
	}

	if err := svc.ForceReleaseMountLease(ctx, alloc.ID, user.ID); err != nil {
		t.Fatalf("force release: %v", err)
	}

	q := sqlcdb.New(pool)
	row, err := q.GetAllocation(ctx, alloc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if row.BoundAgentID.Valid {
		t.Fatalf("bound_agent_id still set: %+v", row.BoundAgentID)
	}
	if row.BoundAt.Valid {
		t.Fatalf("bound_at still set: %+v", row.BoundAt)
	}
	if row.LeaseExpiresAt.Valid {
		t.Fatalf("lease_expires_at still set: %+v", row.LeaseExpiresAt)
	}
}

func TestForceReleaseMountLeaseIdempotent(t *testing.T) {
	ctx := context.Background()
	pool := openTestPool(t)
	svc := allocations.NewService(pool, nil)

	user := seedUser(t, pool, "force-release-idem@example.com", 10*GiB)
	alloc, err := svc.Allocate(ctx, user.ID, GiB)
	if err != nil {
		t.Fatal(err)
	}

	if err := svc.ForceReleaseMountLease(ctx, alloc.ID, user.ID); err != nil {
		t.Fatalf("first call: %v", err)
	}
	if err := svc.ForceReleaseMountLease(ctx, alloc.ID, user.ID); err != nil {
		t.Fatalf("second call: %v", err)
	}
}

func TestForceReleaseMountLeaseRevoked(t *testing.T) {
	ctx := context.Background()
	pool := openTestPool(t)
	svc := allocations.NewService(pool, nil)

	user := seedUser(t, pool, "force-release-revoked@example.com", 10*GiB)
	alloc, err := svc.Allocate(ctx, user.ID, GiB)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Revoke(ctx, alloc.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	err = svc.ForceReleaseMountLease(ctx, alloc.ID, user.ID)
	if !errors.Is(err, allocations.ErrRevoked) {
		t.Fatalf("err = %v, want ErrRevoked", err)
	}
}

func TestForceReleaseMountLeaseWrongUser(t *testing.T) {
	ctx := context.Background()
	pool := openTestPool(t)
	svc := allocations.NewService(pool, nil)

	owner := seedUser(t, pool, "force-release-owner@example.com", 10*GiB)
	other := seedUser(t, pool, "force-release-other@example.com", 10*GiB)
	alloc, err := svc.Allocate(ctx, owner.ID, GiB)
	if err != nil {
		t.Fatal(err)
	}
	err = svc.ForceReleaseMountLease(ctx, alloc.ID, other.ID)
	if !errors.Is(err, allocations.ErrWrongUser) {
		t.Fatalf("err = %v, want ErrWrongUser", err)
	}
}

func TestForceReleaseMountLeaseNotFound(t *testing.T) {
	ctx := context.Background()
	pool := openTestPool(t)
	svc := allocations.NewService(pool, nil)

	user := seedUser(t, pool, "force-release-notfound@example.com", 10*GiB)
	var randBytes [16]byte
	if _, err := rand.Read(randBytes[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	missing := pgtype.UUID{Bytes: randBytes, Valid: true}
	err := svc.ForceReleaseMountLease(ctx, missing, user.ID)
	if !errors.Is(err, allocations.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}
