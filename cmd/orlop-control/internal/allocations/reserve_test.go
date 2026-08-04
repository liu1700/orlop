package allocations_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/allocations"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage/postgres"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage/postgres/db/sqlcdb"
)

// fakeServerAdmin implements allocations.ServerAdmin for tests.
type fakeServerAdmin struct {
	mu    sync.Mutex
	calls []registerCall
	err   error // if non-nil, return this error
}

type registerCall struct {
	OpsAddr   string
	TenantID  string
	Name      string
	SizeBytes int64
}

func (f *fakeServerAdmin) RegisterTenant(_ context.Context, opsAddr, tenantID, ownerTenantID, name string, sizeBytes int64) (uint32, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, registerCall{OpsAddr: opsAddr, TenantID: tenantID, Name: name, SizeBytes: sizeBytes})
	if f.err != nil {
		return 0, f.err
	}
	return 1, nil
}

func (f *fakeServerAdmin) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// seedReservePool creates a tenant row and a server_pool row, returns the pool row.
// Tests pass a single host name; data_addr and ops_addr are derived as
// "data-<host>" and "ops-<host>" so assertions can distinguish them.
func seedReservePool(t *testing.T, q *sqlcdb.Queries, tenantID, host string, totalBytes, freeBytes int64) sqlcdb.ServerPool {
	t.Helper()
	ctx := context.Background()
	if _, err := q.CreateTenant(ctx, sqlcdb.CreateTenantParams{ID: tenantID, Name: tenantID}); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	srv, err := q.UpsertServerPool(ctx, sqlcdb.UpsertServerPoolParams{
		DataAddr:   "data-" + host,
		OpsAddr:    "ops-" + host,
		TotalBytes: totalBytes,
		FreeBytes:  freeBytes,
		Status:     allocations.ServerStatusAvailable,
	})
	if err != nil {
		t.Fatalf("upsert server pool: %v", err)
	}
	return srv
}

func seedReserveOwner(t *testing.T, q *sqlcdb.Queries, suffix string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	id := uuid.New()
	tenantID := "u_owner_" + suffix
	if _, err := q.CreateTenant(ctx, sqlcdb.CreateTenantParams{ID: tenantID, Name: tenantID}); err != nil {
		t.Fatalf("create owner tenant: %v", err)
	}
	if err := q.EnsureUserWithID(ctx, sqlcdb.EnsureUserWithIDParams{
		ID: pgtype.UUID{Bytes: id, Valid: true}, TenantID: tenantID, Email: suffix + "@test.invalid",
	}); err != nil {
		t.Fatalf("create owner: %v", err)
	}
	return id
}

func TestReserveIdempotent(t *testing.T) {
	pool := openTestPool(t)
	q := sqlcdb.New(pool)
	ctx := context.Background()
	svc := allocations.NewService(postgres.New(pool), nil)
	api := &fakeServerAdmin{}

	seedReservePool(t, q, "t-idem", "srv-idem.example.com", 10*GiB, 10*GiB)
	ownerID := seedReserveOwner(t, q, "idem")

	// Pre-insert server_vms row to simulate already-placed tenant.
	if _, err := q.CreateServerVM(ctx, sqlcdb.CreateServerVMParams{
		TenantID: "t-idem",
		DataAddr: "already-placed.example.com",
		Status:   "active",
	}); err != nil {
		t.Fatalf("create server vm: %v", err)
	}

	dataAddr, err := svc.Reserve(ctx, api, ownerID, "t-idem", "u_owner", "T-Idem", GiB)
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if dataAddr != "already-placed.example.com" {
		t.Fatalf("data_addr = %q, want already-placed.example.com", dataAddr)
	}
	if api.callCount() != 0 {
		t.Fatalf("admin API called %d times, want 0 (idempotent)", api.callCount())
	}
}

func TestReserveHappyPath(t *testing.T) {
	pool := openTestPool(t)
	q := sqlcdb.New(pool)
	ctx := context.Background()
	svc := allocations.NewService(postgres.New(pool), nil)
	api := &fakeServerAdmin{}

	srv := seedReservePool(t, q, "t-happy", "srv-happy.example.com", 10*GiB, 10*GiB)
	ownerID := seedReserveOwner(t, q, "happy")

	dataAddr, err := svc.Reserve(ctx, api, ownerID, "t-happy", "u_owner", "Happy Tenant", 2*GiB)
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if dataAddr != "data-srv-happy.example.com" {
		t.Fatalf("data_addr = %q, want data-srv-happy.example.com", dataAddr)
	}

	// Admin API called once with correct args (ops_addr, not data_addr).
	if api.callCount() != 1 {
		t.Fatalf("admin API called %d times, want 1", api.callCount())
	}
	call := api.calls[0]
	if call.TenantID != "t-happy" || call.SizeBytes != 2*GiB || call.OpsAddr != "ops-srv-happy.example.com" {
		t.Fatalf("unexpected admin call: %+v", call)
	}

	// server_vms row inserted with the data_addr (what the FUSE client uses).
	vm, err := q.GetServerVMByTenant(ctx, "t-happy")
	if err != nil {
		t.Fatalf("GetServerVMByTenant: %v", err)
	}
	if vm.DataAddr != "data-srv-happy.example.com" || vm.Status != "active" {
		t.Fatalf("unexpected server vm: %+v", vm)
	}

	// server_pool free_bytes decremented.
	updated, err := q.GetServerPoolByDataAddr(ctx, "data-srv-happy.example.com")
	if err != nil {
		t.Fatalf("GetServerPoolByDataAddr: %v", err)
	}
	if updated.FreeBytes != srv.FreeBytes-2*GiB {
		t.Fatalf("free_bytes = %d, want %d", updated.FreeBytes, srv.FreeBytes-2*GiB)
	}
}

func TestReserveConcurrentAgentsDebitOwnerOnce(t *testing.T) {
	pool := openTestPool(t)
	q := sqlcdb.New(pool)
	ctx := context.Background()
	svc := allocations.NewService(postgres.New(pool), nil)
	api := &fakeServerAdmin{}

	srv := seedReservePool(t, q, "t-agent-a", "srv-shared.example.com", 10*GiB, 10*GiB)
	if _, err := q.CreateTenant(ctx, sqlcdb.CreateTenantParams{ID: "t-agent-b", Name: "t-agent-b"}); err != nil {
		t.Fatal(err)
	}
	ownerID := seedReserveOwner(t, q, "shared")

	start := make(chan struct{})
	errCh := make(chan error, 2)
	for _, tenantID := range []string{"t-agent-a", "t-agent-b"} {
		tenantID := tenantID
		go func() {
			<-start
			_, err := svc.Reserve(ctx, api, ownerID, tenantID, "u_owner", tenantID, 2*GiB)
			errCh <- err
		}()
	}
	close(start)
	for range 2 {
		if err := <-errCh; err != nil {
			t.Fatalf("Reserve: %v", err)
		}
	}

	updated, err := q.GetServerPoolByDataAddr(ctx, srv.DataAddr)
	if err != nil {
		t.Fatal(err)
	}
	if updated.FreeBytes != srv.FreeBytes-2*GiB {
		t.Fatalf("free_bytes = %d, want one account debit %d", updated.FreeBytes, srv.FreeBytes-2*GiB)
	}
	reservations, err := q.ListOwnerCapacityReservations(ctx, pgtype.UUID{Bytes: ownerID, Valid: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(reservations) != 1 {
		t.Fatalf("owner reservations = %d, want 1", len(reservations))
	}
}

func TestReserveNoCapacity(t *testing.T) {
	pool := openTestPool(t)
	q := sqlcdb.New(pool)
	ctx := context.Background()
	svc := allocations.NewService(postgres.New(pool), nil)
	api := &fakeServerAdmin{}

	if _, err := q.CreateTenant(ctx, sqlcdb.CreateTenantParams{ID: "t-nocap", Name: "t-nocap"}); err != nil {
		t.Fatal(err)
	}
	ownerID := seedReserveOwner(t, q, "nocap")
	if _, err := q.UpsertServerPool(ctx, sqlcdb.UpsertServerPoolParams{
		DataAddr:   "data-tiny.example.com",
		OpsAddr:    "ops-tiny.example.com",
		TotalBytes: GiB,
		FreeBytes:  GiB / 2,
		Status:     allocations.ServerStatusAvailable,
	}); err != nil {
		t.Fatal(err)
	}

	_, err := svc.Reserve(ctx, api, ownerID, "t-nocap", "u_owner", "T", 2*GiB)
	if !errors.Is(err, allocations.ErrNoCapacity) {
		t.Fatalf("err = %v, want ErrNoCapacity", err)
	}
	if api.callCount() != 0 {
		t.Fatal("admin API should not be called when no capacity")
	}
}

func TestReserveNoCapacityEmptyPool(t *testing.T) {
	pool := openTestPool(t)
	q := sqlcdb.New(pool)
	ctx := context.Background()
	svc := allocations.NewService(postgres.New(pool), nil)
	api := &fakeServerAdmin{}

	if _, err := q.CreateTenant(ctx, sqlcdb.CreateTenantParams{ID: "t-empty", Name: "t-empty"}); err != nil {
		t.Fatal(err)
	}
	ownerID := seedReserveOwner(t, q, "empty")

	_, err := svc.Reserve(ctx, api, ownerID, "t-empty", "u_owner", "T", GiB)
	if !errors.Is(err, allocations.ErrNoCapacity) {
		t.Fatalf("err = %v, want ErrNoCapacity", err)
	}
}

func TestReserveAdminAPIFails(t *testing.T) {
	pool := openTestPool(t)
	q := sqlcdb.New(pool)
	ctx := context.Background()
	svc := allocations.NewService(postgres.New(pool), nil)
	api := &fakeServerAdmin{err: fmt.Errorf("server down")}

	srv := seedReservePool(t, q, "t-apifail", "srv-apifail.example.com", 10*GiB, 10*GiB)
	ownerID := seedReserveOwner(t, q, "apifail")

	_, err := svc.Reserve(ctx, api, ownerID, "t-apifail", "u_owner", "T", 2*GiB)
	if err == nil {
		t.Fatal("expected error from admin API failure")
	}

	if api.callCount() != 1 {
		t.Fatalf("admin API called %d times, want 1", api.callCount())
	}

	// The active allocation still owns the account reservation. A retry reuses
	// it instead of leaking another debit on a different server.
	updated, err := q.GetServerPoolByDataAddr(ctx, "data-srv-apifail.example.com")
	if err != nil {
		t.Fatalf("GetServerPoolByDataAddr: %v", err)
	}
	if updated.FreeBytes != srv.FreeBytes-2*GiB {
		t.Fatalf("free_bytes = %d, want %d (owner reservation retained)", updated.FreeBytes, srv.FreeBytes-2*GiB)
	}

	// No server_vms row.
	if _, err := q.GetServerVMByTenant(ctx, "t-apifail"); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("expected no server_vms row, got err=%v", err)
	}
}

func TestReserveCreateServerVMRaceLoses(t *testing.T) {
	// The fake admin inserts a competing server_vms row before Reserve's
	// CreateServerVM call, simulating a concurrent winner.
	pool := openTestPool(t)
	q := sqlcdb.New(pool)
	ctx := context.Background()
	svc := allocations.NewService(postgres.New(pool), nil)

	srv := seedReservePool(t, q, "t-race", "srv-race.example.com", 10*GiB, 10*GiB)
	ownerID := seedReserveOwner(t, q, "race")

	// racingAPI inserts the "winner" row as a side-effect of RegisterTenant.
	api := &racingFakeAdmin{pool: pool, tenantID: "t-race", winnerDataAddr: "data-srv-race.example.com"}

	dataAddr, err := svc.Reserve(ctx, api, ownerID, "t-race", "u_owner", "T", 2*GiB)
	if err != nil {
		t.Fatalf("Reserve race: %v", err)
	}
	// Should return the winner's data_addr.
	if dataAddr != "data-srv-race.example.com" {
		t.Fatalf("data_addr = %q, want data-srv-race.example.com", dataAddr)
	}

	// The owner's one reservation remains; the competing placement reuses it.
	updated, err := q.GetServerPoolByDataAddr(ctx, "data-srv-race.example.com")
	if err != nil {
		t.Fatalf("GetServerPoolByDataAddr: %v", err)
	}
	if updated.FreeBytes != srv.FreeBytes-2*GiB {
		t.Fatalf("free_bytes = %d, want %d (one owner reservation)", updated.FreeBytes, srv.FreeBytes-2*GiB)
	}
}

// racingFakeAdmin inserts a server_vms row for tenantID when RegisterTenant is
// called, simulating a concurrent Reserve that inserted first.
type racingFakeAdmin struct {
	pool           *pgxpool.Pool
	tenantID       string
	winnerDataAddr string
}

func (r *racingFakeAdmin) RegisterTenant(ctx context.Context, _, tenantID, _, _ string, _ int64) (uint32, error) {
	_, err := r.pool.Exec(ctx,
		"INSERT INTO server_vms (tenant_id, data_addr, status) VALUES ($1, $2, 'active')",
		r.tenantID, r.winnerDataAddr,
	)
	if err != nil {
		return 0, fmt.Errorf("racing admin: insert winner vm: %w", err)
	}
	return 1, nil
}

// cancellingAdmin cancels the provided context as a side-effect of
// RegisterTenant, simulating a client disconnect during the admin API call.
type cancellingAdmin struct {
	cancel context.CancelFunc
}

func (a *cancellingAdmin) RegisterTenant(_ context.Context, _, _, _, _ string, _ int64) (uint32, error) {
	a.cancel()
	return 0, fmt.Errorf("cancellingAdmin: context cancelled by client")
}

// TestReserveCompensationSurvivesContextCancel verifies that the compensating
// ReleaseCapacity call succeeds even when the parent context is cancelled
// (e.g. client disconnect during the admin API call). If compensation used the
// same cancelled context, free_bytes would not be restored.
func TestReserveCompensationSurvivesContextCancel(t *testing.T) {
	pool := openTestPool(t)
	q := sqlcdb.New(pool)

	// Use a real logger wired to discard so compensate logging does not panic.
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := allocations.NewService(postgres.New(pool), logger)

	srv := seedReservePool(t, q, "t-ctxcancel", "srv-ctxcancel.example.com", 10*GiB, 10*GiB)
	ownerID := seedReserveOwner(t, q, "ctxcancel")

	ctx, cancel := context.WithCancel(context.Background())
	api := &cancellingAdmin{cancel: cancel}

	_, err := svc.Reserve(ctx, api, ownerID, "t-ctxcancel", "u_owner", "T-CtxCancel", 2*GiB)
	if err == nil {
		t.Fatal("expected error from admin API failure")
	}

	// Cancellation does not discard the account's durable reservation; a later
	// retry for the active allocation will reuse it.
	updated, dbErr := q.GetServerPoolByDataAddr(context.Background(), "data-srv-ctxcancel.example.com")
	if dbErr != nil {
		t.Fatalf("GetServerPoolByDataAddr: %v", dbErr)
	}
	if updated.FreeBytes != srv.FreeBytes-2*GiB {
		t.Fatalf("free_bytes = %d, want %d (owner reservation retained)", updated.FreeBytes, srv.FreeBytes-2*GiB)
	}
}
