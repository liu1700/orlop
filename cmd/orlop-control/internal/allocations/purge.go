package allocations

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/db/sqlcdb"
)

// ErrNotRevoked is returned by PurgeAllocation when the allocation is still
// live — purge only ever erases data whose allocation was already revoked.
var ErrNotRevoked = errors.New("allocations: not revoked")

// ErrNotAgentAllocation is returned when the allocation has no agent_id, so
// its data has no addressable per-agent subtree on the data plane.
var ErrNotAgentAllocation = errors.New("allocations: no agent_id on allocation")

// AgentDataPurger is the slice of the orlop-server admin client the
// purge path drives. Defined on primitive types (like TenantResizer) so tests
// can stub it without a live server; satisfied by the serverapi adapter in
// main.go.
type AgentDataPurger interface {
	// PurgeAgentData erases the `/<agentID>` subtree inside the tenant's store.
	PurgeAgentData(ctx context.Context, opsAddr, tenantID, agentID string) error
	// UnregisterTenant tears down the whole tenant dir (last-allocation purge).
	UnregisterTenant(ctx context.Context, opsAddr, tenantID string) error
	// ClearActiveMountLease fences the allocation's active session first so a
	// straggler client can't keep writing into the subtree being erased.
	ClearActiveMountLease(ctx context.Context, opsAddr, tenantID, allocationID string) error
}

// PurgeAllocation erases a revoked allocation's backend data and releases the
// resources Revoke left behind. Revoke is metadata-only by design; this is the
// second half that actually frees the disk.
//
// Shape of the erase depends on whether the user still has live agents — the
// tenant directory is per-USER and chunks are deduped across its agents:
//
//   - other live allocations remain → per-agent subtree purge on the server
//     (manifests under /<agentID> + chunks that drop to refcount 0). The
//     tenant's pool reservation stays: it backs the surviving agents.
//   - this was the last one → unregister the whole tenant (os.RemoveAll of
//     the tenant dir), drop the server_vms placement so a future agent
//     re-Reserves cleanly, and release the allocation's size_bytes back to
//     server_pool.free_bytes.
//
// Idempotent and concurrency-safe: the purged_at CAS (MarkAllocationPurged)
// elects exactly one winner, and only the winner releases pool capacity, so
// the inline delete-agent purge and the on-demand sweeper can race freely.
// The data-plane calls themselves are idempotent on the server.
//
// An unplaced tenant (provisioned but never enrolled — no server_vms row) has
// no data anywhere; the allocation is just marked purged.
func (s *Service) PurgeAllocation(ctx context.Context, api AgentDataPurger, allocationID pgtype.UUID) error {
	alloc, err := s.q.GetAllocation(ctx, allocationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("purge: get allocation: %w", err)
	}
	if !alloc.RevokedAt.Valid {
		return ErrNotRevoked
	}
	if alloc.PurgedAt.Valid {
		return nil // already erased
	}
	if !alloc.AgentID.Valid || alloc.AgentID.String == "" {
		return ErrNotAgentAllocation
	}

	user, err := s.q.GetUser(ctx, alloc.UserID)
	if err != nil {
		return fmt.Errorf("purge: get user: %w", err)
	}

	// The disk lives in its per-agent tenant (legacy non-agent allocations fall back to
	// the user's tenant). A per-agent tenant holds exactly this agent, so purging it
	// always unregisters the whole tenant; a shared per-user tenant unregisters only on
	// the user's last allocation, else erases just this agent's subtree.
	tenant := user.TenantID
	perAgentTenant := alloc.TenantID.Valid && alloc.TenantID.String != ""
	if perAgentTenant {
		tenant = alloc.TenantID.String
	}

	vm, err := s.q.GetServerVMByTenant(ctx, tenant)
	if errors.Is(err, pgx.ErrNoRows) {
		// Never placed on a server: no bytes exist to erase.
		return s.markPurged(ctx, allocationID, "unplaced", 0, nil)
	}
	if err != nil {
		return fmt.Errorf("purge: get server vm: %w", err)
	}
	server, err := s.q.GetServerPoolByDataAddr(ctx, vm.DataAddr)
	if err != nil {
		return fmt.Errorf("purge: get server pool: %w", err)
	}

	// Fence the active mount session first so a straggling FUSE client can't
	// write into the subtree mid-erase. Best-effort: the pod driving that
	// session is already being torn down by the control-plane.
	if err := api.ClearActiveMountLease(ctx, server.OpsAddr, tenant, uuidString(alloc.ID)); err != nil {
		s.logger.Warn("purge_fence_failed",
			"allocation_id", uuidString(alloc.ID), "tenant_id", tenant, "error", err)
	}

	last := perAgentTenant
	if !perAgentTenant {
		remaining, err := s.q.CountActiveAllocationsForUser(ctx, alloc.UserID)
		if err != nil {
			return fmt.Errorf("purge: count active allocations: %w", err)
		}
		last = remaining == 0
	}

	if last {
		// Drop the whole tenant (its only agent, or the user's last shared allocation).
		if err := api.UnregisterTenant(ctx, server.OpsAddr, tenant); err != nil {
			return fmt.Errorf("purge: unregister tenant %s: %w", tenant, err)
		}
		return s.markPurged(ctx, allocationID, "tenant_unregistered", alloc.SizeBytes, func(cctx context.Context) {
			if n, derr := s.q.DeleteServerVM(cctx, tenant); derr != nil {
				s.logger.Error("purge_delete_server_vm_failed", "tenant_id", tenant, "error", derr)
			} else if n > 0 {
				s.logger.Info("purge_placement_dropped", "tenant_id", tenant)
			}
			if _, rerr := s.q.ReleaseCapacity(cctx, sqlcdb.ReleaseCapacityParams{
				FreeBytes: alloc.SizeBytes, ID: server.ID,
			}); rerr != nil {
				s.logger.Error("purge_release_capacity_failed",
					"server_id", server.ID, "bytes", alloc.SizeBytes, "error", rerr)
			}
		})
	}

	// Legacy shared tenant with other agents: erase just this agent's subtree.
	// No capacity release — the tenant-level reservation backs the survivors.
	if err := api.PurgeAgentData(ctx, server.OpsAddr, tenant, alloc.AgentID.String); err != nil {
		return fmt.Errorf("purge: agent data on %s: %w", server.OpsAddr, err)
	}
	return s.markPurged(ctx, allocationID, "agent_subtree", 0, nil)
}

// markPurged CAS-transitions purged_at and, when this caller wins the CAS,
// runs the release hook (placement drop + capacity release) on a fresh
// context so a cancelled parent cannot strand half the cleanup. Losing the
// CAS means a concurrent purge finished first — nothing left to do.
func (s *Service) markPurged(ctx context.Context, allocationID pgtype.UUID, mode string, releasedBytes int64, release func(context.Context)) error {
	row, err := s.q.MarkAllocationPurged(ctx, allocationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // concurrent purge won; it owns the release
	}
	if err != nil {
		return fmt.Errorf("purge: mark purged: %w", err)
	}
	if release != nil {
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		release(cctx)
	}
	s.logger.Info("allocation_purged",
		"allocation_id", uuidString(row.ID),
		"agent_id", row.AgentID.String,
		"mode", mode,
		"released_bytes", releasedBytes)
	return nil
}

// uuidString renders a pgtype.UUID for logs and URL paths.
func uuidString(u pgtype.UUID) string {
	if !u.Valid {
		return ""
	}
	v, err := u.Value()
	if err != nil {
		return ""
	}
	str, _ := v.(string)
	return str
}
