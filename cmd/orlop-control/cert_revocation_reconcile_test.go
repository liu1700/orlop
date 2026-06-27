package main

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/db/sqlcdb"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/serverapi"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage/postgres"
)

type fakeRevPusher struct {
	mu    sync.Mutex
	byOps map[string][]serverapi.CertRevocation
}

func (f *fakeRevPusher) PushCertRevocations(_ context.Context, opsAddr string, revs []serverapi.CertRevocation) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.byOps == nil {
		f.byOps = map[string][]serverapi.CertRevocation{}
	}
	f.byOps[opsAddr] = revs
	return nil
}

// TestCertRevocationReconcilePushesActiveSet covers issue #5's convergence loop:
// the active deny-list is pushed to each server that hosts a placed tenant. The
// reconciler is driven through the Postgres storage adapter; rows are seeded
// with raw sqlc (those subdomains aren't migrated to storage yet).
func TestCertRevocationReconcilePushesActiveSet(t *testing.T) {
	pool := httpOpenTestPool(t)
	q := sqlcdb.New(pool)
	ctx := context.Background()

	// A placed tenant on a server (server_pool gives the ops_addr; server_vms
	// links the tenant to that server's data_addr).
	const dataAddr = "data-rev.orlop.example.com"
	const opsAddr = "ops-rev.orlop.example.com"
	if _, err := q.UpsertServerPool(ctx, sqlcdb.UpsertServerPoolParams{
		DataAddr:   dataAddr,
		OpsAddr:    opsAddr,
		TotalBytes: 10 << 30,
		FreeBytes:  10 << 30,
		Status:     "available",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.CreateTenant(ctx, sqlcdb.CreateTenantParams{ID: "acme", Name: "Acme"}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.CreateServerVM(ctx, sqlcdb.CreateServerVMParams{
		TenantID: "acme",
		DataAddr: dataAddr,
		Status:   "active",
	}); err != nil {
		t.Fatal(err)
	}

	// One active revocation, one already-expired (must be excluded).
	if err := q.AddCertRevocation(ctx, sqlcdb.AddCertRevocationParams{
		CertSerial: "AABBCC",
		TenantID:   "acme",
		ExpiresAt:  pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true},
		Reason:     "lease_released",
	}); err != nil {
		t.Fatal(err)
	}
	if err := q.AddCertRevocation(ctx, sqlcdb.AddCertRevocationParams{
		CertSerial: "DEAD",
		TenantID:   "acme",
		ExpiresAt:  pgtype.Timestamptz{Time: time.Now().Add(-time.Hour), Valid: true},
		Reason:     "lease_released",
	}); err != nil {
		t.Fatal(err)
	}

	fake := &fakeRevPusher{}
	rc := newCertRevocationReconciler(postgres.New(pool), fake, slog.New(slog.NewTextHandler(io.Discard, nil)))
	rc.reconcileOnce(ctx)

	revs, ok := fake.byOps[opsAddr]
	if !ok {
		t.Fatalf("expected a push to %s; got pushes to %v", opsAddr, keysOf(fake.byOps))
	}
	if len(revs) != 1 || revs[0].Serial != "AABBCC" {
		t.Fatalf("pushed revocations = %+v, want only the active serial AABBCC", revs)
	}
}

// fakeRevStore implements storage.RevocationStore with no database — three
// methods, the whole surface the reconciler needs. (Contrast with the old
// db.Store, whose 84 methods a fake had to embed.)
type fakeRevStore struct {
	revs  []storage.CertRevocation
	addrs []string
}

func (f fakeRevStore) AddCertRevocation(context.Context, storage.CertRevocation) error { return nil }
func (f fakeRevStore) ListActiveCertRevocations(context.Context) ([]storage.CertRevocation, error) {
	return f.revs, nil
}
func (f fakeRevStore) ListActiveServerOpsAddrs(context.Context) ([]string, error) {
	return f.addrs, nil
}

// TestCertRevocationReconcileWithFakeStore exercises the reconciler against a
// mock storage.RevocationStore — no Postgres required — showing the payoff of
// the narrow domain interface.
func TestCertRevocationReconcileWithFakeStore(t *testing.T) {
	store := fakeRevStore{
		revs:  []storage.CertRevocation{{Serial: "AABBCC", ExpiresAt: time.Unix(1_900_000_000, 0)}},
		addrs: []string{"ops-1.example.com", "ops-2.example.com"},
	}
	fake := &fakeRevPusher{}
	rc := newCertRevocationReconciler(store, fake, slog.New(slog.NewTextHandler(io.Discard, nil)))
	rc.reconcileOnce(context.Background())

	if len(fake.byOps) != 2 {
		t.Fatalf("pushed to %d servers, want 2 (%v)", len(fake.byOps), keysOf(fake.byOps))
	}
	for _, ops := range store.addrs {
		revs := fake.byOps[ops]
		if len(revs) != 1 || revs[0].Serial != "AABBCC" {
			t.Fatalf("push to %s = %+v, want [AABBCC]", ops, revs)
		}
	}
}

func keysOf(m map[string][]serverapi.CertRevocation) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
