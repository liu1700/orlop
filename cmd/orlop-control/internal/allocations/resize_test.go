package allocations_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/allocations"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/db/sqlcdb"
)

// fakeTenantResizer records the sizes Resize asked it to apply on the data plane.
type fakeTenantResizer struct {
	calls []int64
	err   error
}

func (f *fakeTenantResizer) ResizeTenant(_ context.Context, _, _ string, sizeBytes int64) (uint32, error) {
	f.calls = append(f.calls, sizeBytes)
	if f.err != nil {
		return 0, f.err
	}
	return 1, nil
}

// placeTenant seeds a server_pool row and binds the tenant to it via server_vms,
// mimicking what Reserve does at enroll. data_addr/ops_addr are derived from the
// tenant id so each test's server is unique.
func placeTenant(t *testing.T, pool *pgxpool.Pool, tenantID string, totalBytes, freeBytes int64) {
	t.Helper()
	q := sqlcdb.New(pool)
	ctx := context.Background()
	if _, err := q.UpsertServerPool(ctx, sqlcdb.UpsertServerPoolParams{
		DataAddr:   "data-" + tenantID,
		OpsAddr:    "ops-" + tenantID,
		TotalBytes: totalBytes,
		FreeBytes:  freeBytes,
		Status:     "available",
	}); err != nil {
		t.Fatalf("upsert server pool: %v", err)
	}
	if _, err := q.CreateServerVM(ctx, sqlcdb.CreateServerVMParams{
		TenantID: tenantID,
		DataAddr: "data-" + tenantID,
		Status:   "active",
	}); err != nil {
		t.Fatalf("create server vm: %v", err)
	}
}

func TestResizeUnplacedUpdatesSizeOnly(t *testing.T) {
	svc, pool := withSvc(t)
	q := sqlcdb.New(pool)
	user := seedUser(t, pool, "unplaced@x.test", 10*GiB)
	alloc, err := q.InsertAllocation(context.Background(), sqlcdb.InsertAllocationParams{UserID: user.ID, SizeBytes: 1 * GiB})
	if err != nil {
		t.Fatalf("insert allocation: %v", err)
	}

	resizer := &fakeTenantResizer{}
	got, err := svc.Resize(context.Background(), resizer, alloc.ID, user.ID, 4*GiB)
	if err != nil {
		t.Fatalf("Resize: %v", err)
	}
	if got.SizeBytes != 4*GiB {
		t.Errorf("size = %d, want %d", got.SizeBytes, 4*GiB)
	}
	// No server placement → the data plane must not be touched.
	if len(resizer.calls) != 0 {
		t.Errorf("data plane called for unplaced tenant: %v", resizer.calls)
	}
}

func TestResizeGrowDebitsPoolAndCallsDataPlane(t *testing.T) {
	svc, pool := withSvc(t)
	q := sqlcdb.New(pool)
	user := seedUser(t, pool, "grow@x.test", 10*GiB)
	placeTenant(t, pool, user.TenantID, 10*GiB, 10*GiB)
	alloc, err := q.InsertAllocation(context.Background(), sqlcdb.InsertAllocationParams{UserID: user.ID, SizeBytes: 1 * GiB})
	if err != nil {
		t.Fatalf("insert allocation: %v", err)
	}

	resizer := &fakeTenantResizer{}
	got, err := svc.Resize(context.Background(), resizer, alloc.ID, user.ID, 4*GiB)
	if err != nil {
		t.Fatalf("Resize: %v", err)
	}
	if got.SizeBytes != 4*GiB {
		t.Errorf("alloc size = %d, want %d", got.SizeBytes, 4*GiB)
	}
	if len(resizer.calls) != 1 || resizer.calls[0] != 4*GiB {
		t.Errorf("data plane calls = %v, want [%d]", resizer.calls, 4*GiB)
	}
	// free_bytes must drop by the grow delta (3 GiB), from 10 → 7.
	sp, err := q.GetServerPoolByDataAddr(context.Background(), "data-"+user.TenantID)
	if err != nil {
		t.Fatalf("get server pool: %v", err)
	}
	if want := 7 * GiB; sp.FreeBytes != want {
		t.Errorf("free_bytes = %d, want %d", sp.FreeBytes, want)
	}
}

func TestResizeGrowsOnDrainingServer(t *testing.T) {
	svc, pool := withSvc(t)
	q := sqlcdb.New(pool)
	user := seedUser(t, pool, "drain-grow@x.test", 10*GiB)
	placeTenant(t, pool, user.TenantID, 10*GiB, 10*GiB)
	// Past its high-water mark: the server takes no new tenants, but this
	// resident must still be able to grow in place (ReserveCapacityForGrowth).
	if _, err := pool.Exec(context.Background(),
		"UPDATE server_pool SET status='draining' WHERE data_addr=$1", "data-"+user.TenantID); err != nil {
		t.Fatalf("mark draining: %v", err)
	}
	alloc, err := q.InsertAllocation(context.Background(), sqlcdb.InsertAllocationParams{UserID: user.ID, SizeBytes: 1 * GiB})
	if err != nil {
		t.Fatalf("insert allocation: %v", err)
	}

	resizer := &fakeTenantResizer{}
	got, err := svc.Resize(context.Background(), resizer, alloc.ID, user.ID, 4*GiB)
	if err != nil {
		t.Fatalf("Resize on draining server: %v", err)
	}
	if got.SizeBytes != 4*GiB {
		t.Errorf("size = %d, want %d", got.SizeBytes, 4*GiB)
	}
	if len(resizer.calls) != 1 || resizer.calls[0] != 4*GiB {
		t.Errorf("data plane calls = %v, want [%d]", resizer.calls, 4*GiB)
	}
}

func TestResizeGrowNoCapacityLeavesEverythingUnchanged(t *testing.T) {
	svc, pool := withSvc(t)
	q := sqlcdb.New(pool)
	user := seedUser(t, pool, "nocap@x.test", 100*GiB)
	placeTenant(t, pool, user.TenantID, 10*GiB, 1*GiB) // only 1 GiB free
	alloc, err := q.InsertAllocation(context.Background(), sqlcdb.InsertAllocationParams{UserID: user.ID, SizeBytes: 1 * GiB})
	if err != nil {
		t.Fatalf("insert allocation: %v", err)
	}

	resizer := &fakeTenantResizer{}
	// delta of 3 GiB exceeds the 1 GiB free → ErrNoCapacity, nothing applied.
	if _, err := svc.Resize(context.Background(), resizer, alloc.ID, user.ID, 4*GiB); !errors.Is(err, allocations.ErrNoCapacity) {
		t.Fatalf("err = %v, want ErrNoCapacity", err)
	}
	if len(resizer.calls) != 0 {
		t.Errorf("data plane called despite no capacity: %v", resizer.calls)
	}
	a, err := q.GetAllocation(context.Background(), alloc.ID)
	if err != nil {
		t.Fatalf("get allocation: %v", err)
	}
	if a.SizeBytes != 1*GiB {
		t.Errorf("size = %d, want unchanged %d", a.SizeBytes, 1*GiB)
	}
	sp, err := q.GetServerPoolByDataAddr(context.Background(), "data-"+user.TenantID)
	if err != nil {
		t.Fatalf("get server pool: %v", err)
	}
	if sp.FreeBytes != 1*GiB {
		t.Errorf("free_bytes = %d, want unchanged %d", sp.FreeBytes, 1*GiB)
	}
}
