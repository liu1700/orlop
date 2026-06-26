package db_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/allocations"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/db/sqlcdb"
)

const GiBServer = int64(1) << 30

// upsertServer is a convenience helper for tests. host is used as the data
// addr; ops_addr is derived as "ops-<host>" so assertions can distinguish them.
func upsertServer(t *testing.T, q *sqlcdb.Queries, host string, total, free int64, status string) sqlcdb.ServerPool {
	t.Helper()
	row, err := q.UpsertServerPool(context.Background(), sqlcdb.UpsertServerPoolParams{
		DataAddr:   host,
		OpsAddr:    "ops-" + host,
		TotalBytes: total,
		FreeBytes:  free,
		Status:     status,
	})
	if err != nil {
		t.Fatalf("UpsertServerPool(%s): %v", host, err)
	}
	return row
}

func TestUpsertServerPoolCreate(t *testing.T) {
	pool := openTestPool(t)
	q := sqlcdb.New(pool)

	row := upsertServer(t, q, "srv1.example.com", 10*GiBServer, 10*GiBServer, "")

	if row.DataAddr != "srv1.example.com" {
		t.Fatalf("fqdn = %q, want %q", row.DataAddr, "srv1.example.com")
	}
	if row.TotalBytes != 10*GiBServer {
		t.Fatalf("total_bytes = %d, want %d", row.TotalBytes, 10*GiBServer)
	}
	if row.FreeBytes != 10*GiBServer {
		t.Fatalf("free_bytes = %d, want %d", row.FreeBytes, 10*GiBServer)
	}
	if row.Status != allocations.ServerStatusAvailable {
		t.Fatalf("status = %q, want %q (default)", row.Status, allocations.ServerStatusAvailable)
	}
	if !row.ID.Valid {
		t.Fatal("id not set")
	}
}

func TestUpsertServerPoolUpdate(t *testing.T) {
	pool := openTestPool(t)
	q := sqlcdb.New(pool)

	orig := upsertServer(t, q, "srv2.example.com", 10*GiBServer, 10*GiBServer, allocations.ServerStatusAvailable)

	// update: shrink capacity, set draining
	updated := upsertServer(t, q, "srv2.example.com", 8*GiBServer, 4*GiBServer, allocations.ServerStatusDraining)

	if updated.ID != orig.ID {
		t.Fatalf("id changed on upsert: got %v want %v", updated.ID, orig.ID)
	}
	if updated.TotalBytes != 8*GiBServer {
		t.Fatalf("total_bytes not updated: got %d", updated.TotalBytes)
	}
	if updated.FreeBytes != 4*GiBServer {
		t.Fatalf("free_bytes not updated: got %d", updated.FreeBytes)
	}
	if updated.Status != allocations.ServerStatusDraining {
		t.Fatalf("status not updated: got %q", updated.Status)
	}
}

func TestPickBestAvailableServer(t *testing.T) {
	pool := openTestPool(t)
	q := sqlcdb.New(pool)
	ctx := context.Background()

	upsertServer(t, q, "big.example.com", 20*GiBServer, 16*GiBServer, allocations.ServerStatusAvailable)
	upsertServer(t, q, "small.example.com", 10*GiBServer, 4*GiBServer, allocations.ServerStatusAvailable)
	upsertServer(t, q, "drain.example.com", 10*GiBServer, 8*GiBServer, allocations.ServerStatusDraining)
	upsertServer(t, q, "unavail.example.com", 10*GiBServer, 8*GiBServer, allocations.ServerStatusUnavailable)

	// Request >= 6 GiB: big qualifies (small has 4 GiB, drain/unavail excluded by status).
	row, err := q.PickBestAvailableServer(ctx, 6*GiBServer)
	if err != nil {
		t.Fatalf("PickBestAvailableServer(6 GiB): %v", err)
	}
	if row.DataAddr != "big.example.com" {
		t.Fatalf("fqdn = %q, want big.example.com", row.DataAddr)
	}

	// Request >= 1 byte: big wins (largest free_bytes first).
	best, err := q.PickBestAvailableServer(ctx, 1)
	if err != nil {
		t.Fatalf("PickBestAvailableServer(1): %v", err)
	}
	if best.DataAddr != "big.example.com" {
		t.Fatalf("fqdn = %q, want big.example.com (highest free_bytes)", best.DataAddr)
	}

	// Request > big: no rows.
	_, err = q.PickBestAvailableServer(ctx, 20*GiBServer)
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("expected pgx.ErrNoRows when no server fits, got %v", err)
	}
}

func TestReserveCapacityDecrement(t *testing.T) {
	pool := openTestPool(t)
	q := sqlcdb.New(pool)
	ctx := context.Background()

	srv := upsertServer(t, q, "srv3.example.com", 10*GiBServer, 10*GiBServer, allocations.ServerStatusAvailable)

	reserved, err := q.ReserveCapacity(ctx, sqlcdb.ReserveCapacityParams{
		FreeBytes: 3 * GiBServer,
		ID:        srv.ID,
	})
	if err != nil {
		t.Fatalf("ReserveCapacity: %v", err)
	}
	want := 7 * GiBServer
	if reserved.FreeBytes != want {
		t.Fatalf("free_bytes after reserve = %d, want %d", reserved.FreeBytes, want)
	}
}

func serverStatusByAddr(t *testing.T, q *sqlcdb.Queries, addr string) string {
	t.Helper()
	row, err := q.GetServerPoolByDataAddr(context.Background(), addr)
	if err != nil {
		t.Fatalf("GetServerPoolByDataAddr(%s): %v", addr, err)
	}
	return row.Status
}

func TestReserveCapacityForGrowthAllowsDraining(t *testing.T) {
	pool := openTestPool(t)
	q := sqlcdb.New(pool)
	ctx := context.Background()

	srv := upsertServer(t, q, "growdrain.example.com", 10*GiBServer, 8*GiBServer, allocations.ServerStatusDraining)
	got, err := q.ReserveCapacityForGrowth(ctx, sqlcdb.ReserveCapacityForGrowthParams{FreeBytes: 2 * GiBServer, ID: srv.ID})
	if err != nil {
		t.Fatalf("ReserveCapacityForGrowth on draining server: %v", err)
	}
	if got.FreeBytes != 6*GiBServer {
		t.Fatalf("free_bytes = %d, want %d", got.FreeBytes, 6*GiBServer)
	}
}

func TestReserveCapacityForGrowthRejectsUnavailable(t *testing.T) {
	pool := openTestPool(t)
	q := sqlcdb.New(pool)
	ctx := context.Background()

	srv := upsertServer(t, q, "growunavail.example.com", 10*GiBServer, 8*GiBServer, allocations.ServerStatusUnavailable)
	if _, err := q.ReserveCapacityForGrowth(ctx, sqlcdb.ReserveCapacityForGrowthParams{FreeBytes: 2 * GiBServer, ID: srv.ID}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("expected pgx.ErrNoRows on unavailable server, got %v", err)
	}
}

func TestReconcileServerStatusFlipsByBuffer(t *testing.T) {
	pool := openTestPool(t)
	q := sqlcdb.New(pool)
	ctx := context.Background()

	// 10% free (< 15% buffer): available → draining.
	upsertServer(t, q, "low.example.com", 10*GiBServer, 1*GiBServer, allocations.ServerStatusAvailable)
	// 50% free (>= 15% buffer): draining → available.
	upsertServer(t, q, "high.example.com", 10*GiBServer, 5*GiBServer, allocations.ServerStatusDraining)
	// operator-disabled, below buffer: must stay unavailable.
	upsertServer(t, q, "off.example.com", 10*GiBServer, 1*GiBServer, allocations.ServerStatusUnavailable)

	if err := q.ReconcileServerStatus(ctx, 0.15); err != nil {
		t.Fatalf("ReconcileServerStatus: %v", err)
	}

	if got := serverStatusByAddr(t, q, "low.example.com"); got != allocations.ServerStatusDraining {
		t.Errorf("low-free server status = %q, want draining", got)
	}
	if got := serverStatusByAddr(t, q, "high.example.com"); got != allocations.ServerStatusAvailable {
		t.Errorf("high-free server status = %q, want available", got)
	}
	if got := serverStatusByAddr(t, q, "off.example.com"); got != allocations.ServerStatusUnavailable {
		t.Errorf("unavailable server status = %q, want unavailable (untouched)", got)
	}
}

func TestReserveCapacityInsufficientReturnsNoRows(t *testing.T) {
	pool := openTestPool(t)
	q := sqlcdb.New(pool)
	ctx := context.Background()

	srv := upsertServer(t, q, "srv4.example.com", 10*GiBServer, 2*GiBServer, allocations.ServerStatusAvailable)

	_, err := q.ReserveCapacity(ctx, sqlcdb.ReserveCapacityParams{
		FreeBytes: 5 * GiBServer,
		ID:        srv.ID,
	})
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("expected pgx.ErrNoRows when insufficient capacity, got %v", err)
	}
}

func TestReserveCapacityWrongStatusReturnsNoRows(t *testing.T) {
	pool := openTestPool(t)
	q := sqlcdb.New(pool)
	ctx := context.Background()

	srv := upsertServer(t, q, "srv5.example.com", 10*GiBServer, 10*GiBServer, allocations.ServerStatusDraining)

	_, err := q.ReserveCapacity(ctx, sqlcdb.ReserveCapacityParams{
		FreeBytes: 1 * GiBServer,
		ID:        srv.ID,
	})
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("expected pgx.ErrNoRows when status != available, got %v", err)
	}
}

func TestReleaseCapacityIncrement(t *testing.T) {
	pool := openTestPool(t)
	q := sqlcdb.New(pool)
	ctx := context.Background()

	srv := upsertServer(t, q, "srv6.example.com", 10*GiBServer, 6*GiBServer, allocations.ServerStatusAvailable)

	released, err := q.ReleaseCapacity(ctx, sqlcdb.ReleaseCapacityParams{
		FreeBytes: 3 * GiBServer,
		ID:        srv.ID,
	})
	if err != nil {
		t.Fatalf("ReleaseCapacity: %v", err)
	}
	if released.FreeBytes != 9*GiBServer {
		t.Fatalf("free_bytes = %d, want %d", released.FreeBytes, 9*GiBServer)
	}
}

func TestReleaseCapacityClampToTotal(t *testing.T) {
	pool := openTestPool(t)
	q := sqlcdb.New(pool)
	ctx := context.Background()

	// Start with free_bytes already at max.
	srv := upsertServer(t, q, "srv7.example.com", 10*GiBServer, 10*GiBServer, allocations.ServerStatusAvailable)

	// Releasing more than remaining space should clamp to total_bytes.
	released, err := q.ReleaseCapacity(ctx, sqlcdb.ReleaseCapacityParams{
		FreeBytes: 5 * GiBServer,
		ID:        srv.ID,
	})
	if err != nil {
		t.Fatalf("ReleaseCapacity: %v", err)
	}
	if released.FreeBytes != 10*GiBServer {
		t.Fatalf("free_bytes = %d, want %d (clamped to total)", released.FreeBytes, 10*GiBServer)
	}
}

func TestReserveCapacityConcurrent(t *testing.T) {
	pool := openTestPool(t)
	ctx := context.Background()
	q := sqlcdb.New(pool)

	// Server with exactly 5 GiB free; two goroutines each try to reserve 4 GiB.
	// Only one can succeed.
	srv := upsertServer(t, q, "srv8.example.com", 10*GiBServer, 5*GiBServer, allocations.ServerStatusAvailable)

	type result struct {
		row sqlcdb.ServerPool
		err error
	}
	results := make(chan result, 2)
	start := make(chan struct{})

	for i := 0; i < 2; i++ {
		go func() {
			<-start
			row, err := q.ReserveCapacity(ctx, sqlcdb.ReserveCapacityParams{
				FreeBytes: 4 * GiBServer,
				ID:        srv.ID,
			})
			results <- result{row: row, err: err}
		}()
	}
	close(start)

	var successes, noRowErrs int
	for i := 0; i < 2; i++ {
		r := <-results
		if r.err == nil {
			successes++
		} else if errors.Is(r.err, pgx.ErrNoRows) {
			noRowErrs++
		} else {
			t.Fatalf("unexpected error: %v", r.err)
		}
	}
	if successes != 1 || noRowErrs != 1 {
		t.Fatalf("got %d successes / %d no-row errors; want 1 / 1", successes, noRowErrs)
	}

	// Verify the winning reservation was applied.
	got, err := q.GetServerPoolByDataAddr(ctx, "srv8.example.com")
	if err != nil {
		t.Fatalf("GetServerPoolByDataAddr: %v", err)
	}
	if got.FreeBytes != 1*GiBServer {
		t.Fatalf("free_bytes after concurrent reserve = %d, want %d", got.FreeBytes, 1*GiBServer)
	}
}
