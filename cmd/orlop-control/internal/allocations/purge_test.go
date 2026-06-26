package allocations_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/allocations"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/db/sqlcdb"
)

// fakeAgentDataPurger records the data-plane calls the purge path makes.
type fakeAgentDataPurger struct {
	purgedAgents        []string
	unregisteredTenants []string
	fencedAllocations   []string
	purgeErr            error
	unregisterErr       error
}

func (f *fakeAgentDataPurger) PurgeAgentData(_ context.Context, _, _, agentID string) error {
	f.purgedAgents = append(f.purgedAgents, agentID)
	return f.purgeErr
}

func (f *fakeAgentDataPurger) UnregisterTenant(_ context.Context, _, tenantID string) error {
	f.unregisteredTenants = append(f.unregisteredTenants, tenantID)
	return f.unregisterErr
}

func (f *fakeAgentDataPurger) ClearActiveMountLease(_ context.Context, _, _, allocationID string) error {
	f.fencedAllocations = append(f.fencedAllocations, allocationID)
	return nil
}

// seedAgentAllocation creates a revocable agent allocation for the user.
func seedAgentAllocation(t *testing.T, pool *pgxpool.Pool, userID pgtype.UUID, agentID string, sizeBytes int64) sqlcdb.DiskAllocation {
	t.Helper()
	row, err := sqlcdb.New(pool).UpsertAgentAllocation(context.Background(), sqlcdb.UpsertAgentAllocationParams{
		UserID:    userID,
		AgentID:   pgtype.Text{String: agentID, Valid: true},
		SizeBytes: sizeBytes,
	})
	if err != nil {
		t.Fatalf("upsert agent allocation: %v", err)
	}
	return row
}

func revokeRow(t *testing.T, pool *pgxpool.Pool, alloc sqlcdb.DiskAllocation) {
	t.Helper()
	if _, err := sqlcdb.New(pool).RevokeAllocation(context.Background(), sqlcdb.RevokeAllocationParams{
		ID: alloc.ID, UserID: alloc.UserID,
	}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
}

func getAllocation(t *testing.T, pool *pgxpool.Pool, id pgtype.UUID) sqlcdb.DiskAllocation {
	t.Helper()
	row, err := sqlcdb.New(pool).GetAllocation(context.Background(), id)
	if err != nil {
		t.Fatalf("get allocation: %v", err)
	}
	return row
}

func TestPurgeLastAllocationUnregistersTenantAndReleasesCapacity(t *testing.T) {
	svc, pool := withSvc(t)
	ctx := context.Background()
	user := seedUser(t, pool, "purge-last@acme.example", 10*GiB)
	placeTenant(t, pool, user.TenantID, 100*GiB, 90*GiB) // 10 GiB notionally reserved
	alloc := seedAgentAllocation(t, pool, user.ID, "agent-last", 10*GiB)
	revokeRow(t, pool, alloc)

	api := &fakeAgentDataPurger{}
	if err := svc.PurgeAllocation(ctx, api, alloc.ID); err != nil {
		t.Fatalf("purge: %v", err)
	}

	if len(api.unregisteredTenants) != 1 || api.unregisteredTenants[0] != user.TenantID {
		t.Errorf("unregistered tenants = %v, want [%s]", api.unregisteredTenants, user.TenantID)
	}
	if len(api.purgedAgents) != 0 {
		t.Errorf("per-agent purge called on last-allocation path: %v", api.purgedAgents)
	}
	if len(api.fencedAllocations) != 1 {
		t.Errorf("fence calls = %d, want 1", len(api.fencedAllocations))
	}
	if row := getAllocation(t, pool, alloc.ID); !row.PurgedAt.Valid {
		t.Errorf("purged_at not set")
	}

	q := sqlcdb.New(pool)
	if _, err := q.GetServerVMByTenant(ctx, user.TenantID); !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("server_vms placement still present (err=%v)", err)
	}
	server, err := q.GetServerPoolByDataAddr(ctx, "data-"+user.TenantID)
	if err != nil {
		t.Fatalf("get server pool: %v", err)
	}
	if server.FreeBytes != 100*GiB {
		t.Errorf("free_bytes = %d, want %d (capacity released)", server.FreeBytes, 100*GiB)
	}
}

func TestPurgeWithSurvivingAgentPurgesSubtreeOnly(t *testing.T) {
	svc, pool := withSvc(t)
	ctx := context.Background()
	user := seedUser(t, pool, "purge-shared@acme.example", 10*GiB)
	placeTenant(t, pool, user.TenantID, 100*GiB, 90*GiB)
	doomed := seedAgentAllocation(t, pool, user.ID, "agent-doomed", 1*GiB)
	seedAgentAllocation(t, pool, user.ID, "agent-survivor", 1*GiB)
	revokeRow(t, pool, doomed)

	api := &fakeAgentDataPurger{}
	if err := svc.PurgeAllocation(ctx, api, doomed.ID); err != nil {
		t.Fatalf("purge: %v", err)
	}

	if len(api.purgedAgents) != 1 || api.purgedAgents[0] != "agent-doomed" {
		t.Errorf("purged agents = %v, want [agent-doomed]", api.purgedAgents)
	}
	if len(api.unregisteredTenants) != 0 {
		t.Errorf("tenant unregistered while a live agent remains: %v", api.unregisteredTenants)
	}
	if row := getAllocation(t, pool, doomed.ID); !row.PurgedAt.Valid {
		t.Errorf("purged_at not set")
	}

	q := sqlcdb.New(pool)
	if _, err := q.GetServerVMByTenant(ctx, user.TenantID); err != nil {
		t.Errorf("placement should survive: %v", err)
	}
	server, err := q.GetServerPoolByDataAddr(ctx, "data-"+user.TenantID)
	if err != nil {
		t.Fatalf("get server pool: %v", err)
	}
	if server.FreeBytes != 90*GiB {
		t.Errorf("free_bytes = %d, want %d (no release while survivors exist)", server.FreeBytes, 90*GiB)
	}
}

func TestPurgeNotRevoked(t *testing.T) {
	svc, pool := withSvc(t)
	user := seedUser(t, pool, "purge-live@acme.example", 10*GiB)
	alloc := seedAgentAllocation(t, pool, user.ID, "agent-live", 1*GiB)

	api := &fakeAgentDataPurger{}
	if err := svc.PurgeAllocation(context.Background(), api, alloc.ID); !errors.Is(err, allocations.ErrNotRevoked) {
		t.Fatalf("err = %v, want ErrNotRevoked", err)
	}
	if len(api.purgedAgents)+len(api.unregisteredTenants) != 0 {
		t.Errorf("data-plane calls made for a live allocation")
	}
}

func TestPurgeUnplacedTenantMarksPurgedWithoutDataPlane(t *testing.T) {
	svc, pool := withSvc(t)
	user := seedUser(t, pool, "purge-unplaced@acme.example", 10*GiB)
	alloc := seedAgentAllocation(t, pool, user.ID, "agent-unplaced", 1*GiB)
	revokeRow(t, pool, alloc)

	api := &fakeAgentDataPurger{}
	if err := svc.PurgeAllocation(context.Background(), api, alloc.ID); err != nil {
		t.Fatalf("purge: %v", err)
	}
	if len(api.purgedAgents)+len(api.unregisteredTenants)+len(api.fencedAllocations) != 0 {
		t.Errorf("data-plane calls made for an unplaced tenant")
	}
	if row := getAllocation(t, pool, alloc.ID); !row.PurgedAt.Valid {
		t.Errorf("purged_at not set")
	}
}

func TestPurgeIsIdempotentAndReleasesOnce(t *testing.T) {
	svc, pool := withSvc(t)
	ctx := context.Background()
	user := seedUser(t, pool, "purge-twice@acme.example", 10*GiB)
	placeTenant(t, pool, user.TenantID, 100*GiB, 90*GiB)
	alloc := seedAgentAllocation(t, pool, user.ID, "agent-twice", 10*GiB)
	revokeRow(t, pool, alloc)

	api := &fakeAgentDataPurger{}
	if err := svc.PurgeAllocation(ctx, api, alloc.ID); err != nil {
		t.Fatalf("first purge: %v", err)
	}
	if err := svc.PurgeAllocation(ctx, api, alloc.ID); err != nil {
		t.Fatalf("second purge: %v", err)
	}

	server, err := sqlcdb.New(pool).GetServerPoolByDataAddr(ctx, "data-"+user.TenantID)
	if err != nil {
		t.Fatalf("get server pool: %v", err)
	}
	if server.FreeBytes != 100*GiB {
		t.Errorf("free_bytes = %d, want %d (released exactly once)", server.FreeBytes, 100*GiB)
	}
	if len(api.unregisteredTenants) != 1 {
		t.Errorf("unregister calls = %d, want 1", len(api.unregisteredTenants))
	}
}
