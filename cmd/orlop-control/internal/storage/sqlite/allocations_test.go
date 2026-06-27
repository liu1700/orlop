package sqlite

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
)

// seedEnrollment creates an enrollment for u and returns its id (the lease's
// bound_agent_id FK target).
func seedEnrollment(t *testing.T, s *Store, userID uuid.UUID, serial string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	if err := s.CreateAgentEnrollment(ctx, storage.NewAgentEnrollment{UserID: userID, CertSerial: serial, CertNotAfter: time.Now().Add(time.Hour)}); err != nil {
		t.Fatalf("create enrollment: %v", err)
	}
	e, err := s.GetActiveEnrollmentByFingerprint(ctx, serial)
	if err != nil {
		t.Fatalf("get enrollment: %v", err)
	}
	return e.ID
}

func TestAllocationsLifecycle(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	u := seedUser(t, s, "acme", "a@acme.test")

	a, err := s.InsertAllocation(ctx, u.ID, 1000)
	if err != nil || a.SizeBytes != 1000 || a.UserID != u.ID {
		t.Fatalf("insert = %+v, err %v", a, err)
	}
	if got, _ := s.GetAllocation(ctx, a.ID); got.ID != a.ID {
		t.Fatalf("get mismatch")
	}
	if list, _ := s.ListAllocationsForUser(ctx, u.ID); len(list) != 1 {
		t.Fatalf("list = %d, want 1", len(list))
	}
	if resized, err := s.UpdateAllocationSize(ctx, a.ID, u.ID, 5000); err != nil || resized.SizeBytes != 5000 {
		t.Fatalf("resize = %+v, err %v", resized, err)
	}
	if n, _ := s.CountActiveAllocationsForUser(ctx, u.ID); n != 1 {
		t.Fatalf("count = %d, want 1", n)
	}
	// Revoke is idempotent for the owner, ErrNotFound for the wrong user.
	if err := s.RevokeAllocation(ctx, a.ID, uuid.New()); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("revoke wrong user = %v, want ErrNotFound", err)
	}
	if err := s.RevokeAllocation(ctx, a.ID, u.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := s.RevokeAllocation(ctx, a.ID, u.ID); err != nil {
		t.Fatalf("idempotent revoke: %v", err)
	}
	if list, _ := s.ListAllocationsForUser(ctx, u.ID); len(list) != 0 {
		t.Fatalf("revoked alloc still listed")
	}
	if n, _ := s.CountActiveAllocationsForUser(ctx, u.ID); n != 0 {
		t.Fatalf("count after revoke = %d, want 0", n)
	}
}

func TestProvisioningUpsertAndReassign(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if err := s.EnsureTenant(ctx, "u_owner", "u_owner"); err != nil {
		t.Fatalf("ensure tenant: %v", err)
	}
	if err := s.EnsureTenant(ctx, "u_owner", "u_owner"); err != nil {
		t.Fatalf("idempotent ensure tenant: %v", err)
	}
	owner := uuid.New()
	if err := s.EnsureUserWithID(ctx, storage.NewUser{ID: owner, TenantID: "u_owner", Email: "owner@x"}); err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	if err := s.EnsureTenant(ctx, "a_agent", "a_agent"); err != nil {
		t.Fatalf("ensure agent tenant: %v", err)
	}

	first, err := s.UpsertAgentAllocation(ctx, storage.NewAgentAllocation{UserID: owner, AgentID: "agent-1", TenantID: "a_agent", SizeBytes: 1024})
	if err != nil || first.AgentID != "agent-1" {
		t.Fatalf("upsert = %+v, err %v", first, err)
	}
	// Idempotent: same agent returns the same allocation id.
	again, err := s.UpsertAgentAllocation(ctx, storage.NewAgentAllocation{UserID: owner, AgentID: "agent-1", TenantID: "a_agent", SizeBytes: 9999})
	if err != nil || again.ID != first.ID {
		t.Fatalf("re-upsert id = %s, want %s (err %v)", again.ID, first.ID, err)
	}
	got, err := s.GetAllocationByAgent(ctx, "agent-1")
	if err != nil || got.ID != first.ID {
		t.Fatalf("get by agent = %+v, err %v", got, err)
	}

	// Reassign to a new owner (only user_id changes; tenant untouched).
	newOwner := uuid.New()
	if err := s.EnsureTenant(ctx, "u_new", "u_new"); err != nil {
		t.Fatalf("ensure new tenant: %v", err)
	}
	if err := s.EnsureUserWithID(ctx, storage.NewUser{ID: newOwner, TenantID: "u_new", Email: "new@x"}); err != nil {
		t.Fatalf("ensure new user: %v", err)
	}
	if err := s.ReassignAgentAllocation(ctx, "agent-1", newOwner); err != nil {
		t.Fatalf("reassign: %v", err)
	}
	if got, _ := s.GetAllocationByAgent(ctx, "agent-1"); got.UserID != newOwner || got.TenantID != "a_agent" {
		t.Fatalf("after reassign = %+v (want user %s, tenant a_agent)", got, newOwner)
	}
}

func TestMountLease(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	u := seedUser(t, s, "acme", "a@acme.test")
	a, _ := s.InsertAllocation(ctx, u.ID, 1000)
	agent1 := seedEnrollment(t, s, u.ID, "AGENT1")
	agent2 := seedEnrollment(t, s, u.ID, "AGENT2")
	ttl := time.Minute

	acq, err := s.AcquireMountLease(ctx, a.ID, agent1, ttl)
	if err != nil || acq.BoundAgentID == nil || *acq.BoundAgentID != agent1 || acq.LeaseExpiresAt == nil {
		t.Fatalf("acquire = %+v, err %v", acq, err)
	}
	boundAt := acq.BoundAt
	// Same-agent re-acquire preserves bound_at.
	reacq, err := s.AcquireMountLease(ctx, a.ID, agent1, ttl)
	if err != nil || reacq.BoundAt == nil || boundAt == nil || !reacq.BoundAt.Equal(*boundAt) {
		t.Fatalf("re-acquire bound_at changed: %+v vs %+v (err %v)", reacq.BoundAt, boundAt, err)
	}
	// Refresh extends the lease.
	if _, err := s.RefreshMountLease(ctx, a.ID, agent1, ttl); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	// Takeover by a different agent resets bound_at.
	if to, err := s.AcquireMountLease(ctx, a.ID, agent2, ttl); err != nil || to.BoundAgentID == nil || *to.BoundAgentID != agent2 {
		t.Fatalf("takeover = %+v, err %v", to, err)
	}
	// The displaced agent can no longer refresh.
	if _, err := s.RefreshMountLease(ctx, a.ID, agent1, ttl); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("displaced refresh = %v, want ErrNotFound", err)
	}
	// Release, then refresh fails (lease gone).
	if _, err := s.ReleaseMountLease(ctx, a.ID, agent2); err != nil {
		t.Fatalf("release: %v", err)
	}
	if _, err := s.RefreshMountLease(ctx, a.ID, agent2, ttl); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("refresh after release = %v, want ErrNotFound", err)
	}
	// Force-release after a re-acquire; wrong user fails.
	if _, err := s.AcquireMountLease(ctx, a.ID, agent1, ttl); err != nil {
		t.Fatalf("re-acquire: %v", err)
	}
	if err := s.ForceReleaseMountLease(ctx, a.ID, uuid.New()); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("force-release wrong user = %v, want ErrNotFound", err)
	}
	if err := s.ForceReleaseMountLease(ctx, a.ID, u.ID); err != nil {
		t.Fatalf("force-release: %v", err)
	}
}

func TestPurgeCAS(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	u := seedUser(t, s, "acme", "a@acme.test")
	a, _ := s.InsertAllocation(ctx, u.ID, 1000)

	// Cannot purge a live allocation.
	if _, err := s.MarkAllocationPurged(ctx, a.ID); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("purge live = %v, want ErrNotFound", err)
	}
	if err := s.RevokeAllocation(ctx, a.ID, u.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := s.MarkAllocationPurged(ctx, a.ID); err != nil {
		t.Fatalf("purge: %v", err)
	}
	// Second purge loses the CAS.
	if _, err := s.MarkAllocationPurged(ctx, a.ID); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("double purge = %v, want ErrNotFound", err)
	}

	// Purge-pending queue: a revoked agent allocation appears until purged.
	if err := s.EnsureTenant(ctx, "a_ag", "a_ag"); err != nil {
		t.Fatalf("ensure tenant: %v", err)
	}
	ag, _ := s.UpsertAgentAllocation(ctx, storage.NewAgentAllocation{UserID: u.ID, AgentID: "ag", TenantID: "a_ag", SizeBytes: 10})
	if err := s.RevokeAllocation(ctx, ag.ID, u.ID); err != nil {
		t.Fatalf("revoke agent alloc: %v", err)
	}
	pending, err := s.ListPurgePendingAllocations(ctx, 10)
	if err != nil || len(pending) != 1 || pending[0].AllocationID != ag.ID || pending[0].AgentID != "ag" {
		t.Fatalf("pending = %+v, err %v", pending, err)
	}
	if _, err := s.MarkAllocationPurged(ctx, ag.ID); err != nil {
		t.Fatalf("purge agent alloc: %v", err)
	}
	if pending, _ := s.ListPurgePendingAllocations(ctx, 10); len(pending) != 0 {
		t.Fatalf("purged alloc still pending: %+v", pending)
	}
}

func TestCapacityAndPlacement(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.RegisterServerPool(ctx, storage.ServerPool{DataAddr: "d:1", OpsAddr: "o:1", TotalBytes: 1000, FreeBytes: 1000}); err != nil {
		t.Fatalf("register: %v", err)
	}
	srv, err := s.GetServerPoolByDataAddr(ctx, "d:1")
	if err != nil {
		t.Fatalf("get pool: %v", err)
	}
	if pick, err := s.PickBestAvailableServer(ctx, 500); err != nil || pick.ID != srv.ID {
		t.Fatalf("pick = %+v, err %v", pick, err)
	}
	if _, err := s.PickBestAvailableServer(ctx, 2000); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("pick too big = %v, want ErrNotFound", err)
	}
	if err := s.ReserveCapacity(ctx, srv.ID, 600); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	// Now only 400 free: a second 600 reservation fails.
	if err := s.ReserveCapacity(ctx, srv.ID, 600); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("over-reserve = %v, want ErrNotFound", err)
	}
	// Release caps at total_bytes.
	if err := s.ReleaseCapacity(ctx, srv.ID, 10000); err != nil {
		t.Fatalf("release: %v", err)
	}
	if pick, _ := s.PickBestAvailableServer(ctx, 1000); pick.ID != srv.ID {
		t.Fatalf("capacity not restored to total")
	}

	// server_vms placement (the tenant must exist for the FK).
	if err := s.EnsureTenant(ctx, "acme", "acme"); err != nil {
		t.Fatalf("ensure tenant: %v", err)
	}
	if err := s.CreateServerVM(ctx, storage.NewServerVM{TenantID: "acme", DataAddr: "d:1", Status: "active"}); err != nil {
		t.Fatalf("create vm: %v", err)
	}
	vm, err := s.GetServerVMByTenant(ctx, "acme")
	if err != nil || vm.DataAddr != "d:1" || vm.Status != "active" {
		t.Fatalf("get vm = %+v, err %v", vm, err)
	}
	if n, err := s.DeleteServerVM(ctx, "acme"); err != nil || n != 1 {
		t.Fatalf("delete vm = %d, err %v", n, err)
	}
}

func TestTransactionCommitRollback(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	u := seedUser(t, s, "acme", "a@acme.test")

	// Commit makes the write visible.
	tx, err := s.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	a, err := tx.InsertAllocation(ctx, u.ID, 1000)
	if err != nil {
		t.Fatalf("insert in tx: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatalf("rollback after commit should be a no-op: %v", err)
	}
	if _, err := s.GetAllocation(ctx, a.ID); err != nil {
		t.Fatalf("committed alloc not visible: %v", err)
	}

	// Rollback discards the write.
	tx2, _ := s.Begin(ctx)
	b, err := tx2.InsertAllocation(ctx, u.ID, 2000)
	if err != nil {
		t.Fatalf("insert in tx2: %v", err)
	}
	if err := tx2.Rollback(ctx); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if _, err := s.GetAllocation(ctx, b.ID); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("rolled-back alloc visible: %v", err)
	}
}
