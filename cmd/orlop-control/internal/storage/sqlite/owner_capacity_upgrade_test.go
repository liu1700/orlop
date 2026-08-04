package sqlite

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/google/uuid"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
)

func TestSchemaUpgradeBackfillsOneReservationPerOwner(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "owner-capacity.db")
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	ownerID := uuid.New()
	if err := s.EnsureTenant(ctx, "u_owner", "owner"); err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureUserWithID(ctx, storage.NewUser{ID: ownerID, TenantID: "u_owner", Email: "owner@test.invalid"}); err != nil {
		t.Fatal(err)
	}
	for _, tenantID := range []string{"a_one", "a_two"} {
		if err := s.EnsureTenant(ctx, tenantID, tenantID); err != nil {
			t.Fatal(err)
		}
		if _, err := s.UpsertAgentAllocation(ctx, storage.NewAgentAllocation{
			UserID: ownerID, AgentID: tenantID, TenantID: tenantID, SizeBytes: 2 << 30,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.RegisterServerPool(ctx, storage.ServerPool{
		DataAddr: "data:1", OpsAddr: "ops:1", TotalBytes: 10 << 30, FreeBytes: 6 << 30, Status: "available",
	}); err != nil {
		t.Fatal(err)
	}
	for _, tenantID := range []string{"a_one", "a_two"} {
		if err := s.CreateServerVM(ctx, storage.NewServerVM{TenantID: tenantID, DataAddr: "data:1", Status: "active"}); err != nil {
			t.Fatal(err)
		}
	}
	// Emulate the pre-upgrade state: each of two agents debited the full 2 GiB
	// account budget, and no account-level ledger row existed.
	if _, err := s.db.ExecContext(ctx, `DELETE FROM owner_capacity_reservations`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE server_pool SET free_bytes = ?`, 6<<30); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	server, err := s.GetServerPoolByDataAddr(ctx, "data:1")
	if err != nil {
		t.Fatal(err)
	}
	if serverFree := func() int64 {
		var free int64
		if err := s.db.QueryRowContext(ctx, `SELECT free_bytes FROM server_pool WHERE data_addr = ?`, "data:1").Scan(&free); err != nil {
			t.Fatal(err)
		}
		return free
	}(); serverFree != 8<<30 {
		t.Fatalf("free_bytes = %d, want %d after removing agent multiplier", serverFree, int64(8<<30))
	}
	reservations, err := s.ListOwnerCapacityReservations(ctx, ownerID)
	if err != nil {
		t.Fatal(err)
	}
	if len(reservations) != 1 || reservations[0].SizeBytes != 2<<30 || reservations[0].DataAddr != server.DataAddr {
		t.Fatalf("reservations = %+v, want one 2 GiB owner reservation", reservations)
	}
}
