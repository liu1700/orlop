package sqlite

import (
	"context"
	"testing"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
)

func TestCapacityMetricsReflectPoolAndPurgeTransitions(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	if _, err := store.RegisterServerPool(ctx, storage.ServerPool{
		DataAddr: "data:8443", OpsAddr: "ops:7878", TotalBytes: 1000, FreeBytes: 250,
	}); err != nil {
		t.Fatal(err)
	}
	pools, err := store.ListServerPoolCapacity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(pools) != 1 || pools[0].ServerID == [16]byte{} || pools[0].TotalBytes != 1000 || pools[0].FreeBytes != 250 {
		t.Fatalf("pool metrics = %+v", pools)
	}

	if err := store.CreateTenant(ctx, "tenant", "Tenant"); err != nil {
		t.Fatal(err)
	}
	user, err := store.CreateUser(ctx, "owner@example.com", "tenant")
	if err != nil {
		t.Fatal(err)
	}
	allocation, err := store.InsertAllocation(ctx, user.ID, 100)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeAllocation(ctx, allocation.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	if got, err := store.CountPurgePendingAllocations(ctx); err != nil || got != 1 {
		t.Fatalf("pending after revoke = %d, err = %v", got, err)
	}
	if _, err := store.MarkAllocationPurged(ctx, allocation.ID); err != nil {
		t.Fatal(err)
	}
	if got, err := store.CountPurgePendingAllocations(ctx); err != nil || got != 0 {
		t.Fatalf("pending after purge = %d, err = %v", got, err)
	}
}
