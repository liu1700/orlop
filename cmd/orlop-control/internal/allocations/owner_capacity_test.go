package allocations_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/allocations"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage/sqlite"
)

func TestResizeOwnerCapacityAdjustsLedgerOnce(t *testing.T) {
	ctx := context.Background()
	store, err := sqlite.Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ownerID := uuid.New()
	if err := store.EnsureTenant(ctx, "u_owner", "owner"); err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureUserWithID(ctx, storage.NewUser{ID: ownerID, TenantID: "u_owner", Email: "owner@test.invalid"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RegisterServerPool(ctx, storage.ServerPool{
		DataAddr: "data:1", OpsAddr: "ops:1", TotalBytes: 10 * GiB, FreeBytes: 10 * GiB, Status: "available",
	}); err != nil {
		t.Fatal(err)
	}
	server, err := store.GetServerPoolByDataAddr(ctx, "data:1")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ReserveCapacity(ctx, server.ID, 2*GiB); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateOwnerCapacityReservation(ctx, ownerID, server.ID, 2*GiB); err != nil {
		t.Fatal(err)
	}

	svc := allocations.NewService(store, nil)
	if err := svc.ResizeOwnerCapacity(ctx, ownerID, 3*GiB); err != nil {
		t.Fatal(err)
	}
	reservations, err := store.ListOwnerCapacityReservations(ctx, ownerID)
	if err != nil {
		t.Fatal(err)
	}
	if len(reservations) != 1 || reservations[0].SizeBytes != 3*GiB {
		t.Fatalf("reservations = %+v, want one 3 GiB row", reservations)
	}
	capacity, err := store.ListServerPoolCapacity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(capacity) != 1 || capacity[0].FreeBytes != 7*GiB {
		t.Fatalf("capacity = %+v, want 7 GiB free", capacity)
	}

	if err := svc.ResizeOwnerCapacity(ctx, ownerID, 1*GiB); err != nil {
		t.Fatal(err)
	}
	capacity, err = store.ListServerPoolCapacity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if capacity[0].FreeBytes != 9*GiB {
		t.Fatalf("free_bytes = %d, want 9 GiB after shrink", capacity[0].FreeBytes)
	}
}
