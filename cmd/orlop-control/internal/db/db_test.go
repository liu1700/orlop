package db_test

import (
	"context"
	"database/sql"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/db"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/db/sqlcdb"
)

// testDatabaseURL returns the connection string for the test Postgres or "" if
// not configured. Tests skip when empty so unit-test runs on dev machines
// without Postgres still pass.
func testDatabaseURL() string {
	return os.Getenv("TEST_DATABASE_URL")
}

var (
	migrateOnce sync.Once
	migrateErr  error
)

// openTestPool migrates once per process, returns a fresh pgxpool.Pool, and
// truncates all tables on test cleanup so tests are isolated without per-test
// transactions.
func openTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := testDatabaseURL()
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping postgres round-trip test")
	}
	migrateOnce.Do(func() {
		migrateErr = db.MigrateUp(context.Background(), url)
	})
	if migrateErr != nil {
		t.Fatalf("migrate up: %v", migrateErr)
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			"TRUNCATE TABLE server_pool, disk_allocations, agent_enrollments, server_vms, users, tenants RESTART IDENTITY CASCADE")
		pool.Close()
	})
	return pool
}

func TestMigrateUpIsIdempotent(t *testing.T) {
	url := testDatabaseURL()
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	if err := db.MigrateUp(ctx, url); err != nil {
		t.Fatalf("first migrate up: %v", err)
	}
	if err := db.MigrateUp(ctx, url); err != nil {
		t.Fatalf("second migrate up: %v", err)
	}

	conn, err := sql.Open("pgx", url)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	for _, table := range []string{"tenants", "users", "server_vms", "agent_enrollments"} {
		var exists bool
		row := conn.QueryRowContext(ctx,
			"SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = $1)",
			table,
		)
		if err := row.Scan(&exists); err != nil {
			t.Fatalf("check %s: %v", table, err)
		}
		if !exists {
			t.Fatalf("table %s does not exist after migrate up", table)
		}
	}
}

func TestRoundTripTenantAndServerVM(t *testing.T) {
	pool := openTestPool(t)
	ctx := context.Background()
	q := sqlcdb.New(pool)

	tenant, err := q.CreateTenant(ctx, sqlcdb.CreateTenantParams{
		ID:   "acme",
		Name: "Acme Corp",
	})
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	if tenant.ID != "acme" || tenant.Name != "Acme Corp" {
		t.Fatalf("unexpected tenant: %#v", tenant)
	}
	if !tenant.CreatedAt.Valid {
		t.Fatalf("tenant.CreatedAt not set")
	}

	vm, err := q.CreateServerVM(ctx, sqlcdb.CreateServerVMParams{
		TenantID: "acme",
		DataAddr: "acme.orlop.example",
		Status:   "pending",
	})
	if err != nil {
		t.Fatalf("create server vm: %v", err)
	}

	got, err := q.GetServerVMByTenant(ctx, "acme")
	if err != nil {
		t.Fatalf("get server vm: %v", err)
	}
	if got.ID != vm.ID {
		t.Fatalf("vm id mismatch: got %v want %v", got.ID, vm.ID)
	}
	if got.DataAddr != "acme.orlop.example" || got.Status != "pending" {
		t.Fatalf("unexpected vm: %#v", got)
	}

	if _, err := q.CreateServerVM(ctx, sqlcdb.CreateServerVMParams{
		TenantID: "acme",
		DataAddr: "acme-2.orlop.example",
		Status:   "pending",
	}); err == nil {
		t.Fatal("expected unique violation creating second server_vm for same tenant")
	}
}

func TestRoundTripActiveEnrollments(t *testing.T) {
	pool := openTestPool(t)
	ctx := context.Background()
	q := sqlcdb.New(pool)

	if _, err := q.CreateTenant(ctx, sqlcdb.CreateTenantParams{ID: "acme", Name: "Acme"}); err != nil {
		t.Fatal(err)
	}
	user, err := q.CreateUser(ctx, sqlcdb.CreateUserParams{
		Email:    "alice@acme.example",
		TenantID: "acme",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	now := time.Now().UTC()
	active := mustTimestamptz(t, now.Add(45*time.Minute))
	expired := mustTimestamptz(t, now.Add(-1*time.Hour))

	for _, e := range []sqlcdb.CreateAgentEnrollmentParams{
		{UserID: user.ID, CertSerial: "serial-active-1", CertNotAfter: active},
		{UserID: user.ID, CertSerial: "serial-active-2", CertNotAfter: active},
		{UserID: user.ID, CertSerial: "serial-expired", CertNotAfter: expired},
	} {
		if _, err := q.CreateAgentEnrollment(ctx, e); err != nil {
			t.Fatalf("create enrollment %s: %v", e.CertSerial, err)
		}
	}

	rows, err := q.ListActiveEnrollmentsForUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("list active: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("active count = %d, want 2; rows = %#v", len(rows), rows)
	}
	for _, r := range rows {
		if r.CertSerial == "serial-expired" {
			t.Fatalf("expired enrollment leaked into active list")
		}
		if !r.CertNotAfter.Time.After(now) {
			t.Fatalf("active row has cert_not_after %v not after now %v", r.CertNotAfter.Time, now)
		}
	}
}

func mustTimestamptz(t *testing.T, ts time.Time) pgtype.Timestamptz {
	t.Helper()
	var v pgtype.Timestamptz
	if err := v.Scan(ts); err != nil {
		t.Fatalf("timestamptz scan: %v", err)
	}
	return v
}
