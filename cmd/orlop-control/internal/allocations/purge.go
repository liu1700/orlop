package allocations

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
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
//     the tenant dir), drop the server_vms placement, and release the owner's
//     one account-level reservation after its final placement disappears.
//
// Idempotent and concurrency-safe: the owner row lock serializes concurrent
// final-placement cleanup, and deleting the reservation is the release CAS.
// The data-plane calls and purged_at transition are themselves idempotent.
//
// An unplaced tenant (provisioned but never enrolled — no server_vms row) has
// no data anywhere; the allocation is just marked purged.
func (s *Service) PurgeAllocation(ctx context.Context, api AgentDataPurger, allocationID pgtype.UUID) error {
	allocID := toUUID(allocationID)
	alloc, err := s.store.GetAllocation(ctx, allocID)
	if errors.Is(err, storage.ErrNotFound) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("purge: get allocation: %w", err)
	}
	if alloc.RevokedAt == nil {
		return ErrNotRevoked
	}
	if alloc.PurgedAt != nil {
		return nil // already erased
	}
	if alloc.AgentID == "" {
		return ErrNotAgentAllocation
	}

	user, err := s.store.GetUser(ctx, alloc.UserID)
	if err != nil {
		return fmt.Errorf("purge: get user: %w", err)
	}

	// The disk lives in its per-agent tenant (legacy non-agent allocations fall back to
	// the user's tenant). A per-agent tenant holds exactly this agent, so purging it
	// always unregisters the whole tenant; a shared per-user tenant unregisters only on
	// the user's last allocation, else erases just this agent's subtree.
	tenant := user.TenantID
	perAgentTenant := alloc.TenantID != ""
	if perAgentTenant {
		tenant = alloc.TenantID
	}

	vm, err := s.store.GetServerVMByTenant(ctx, tenant)
	if errors.Is(err, storage.ErrNotFound) {
		// Never placed on a server: no bytes exist to erase.
		released, cleanupErr := s.releaseUnusedOwnerCapacity(ctx, alloc.UserID, "")
		if cleanupErr != nil {
			return cleanupErr
		}
		return s.markPurged(ctx, allocID, "unplaced", released)
	}
	if err != nil {
		return fmt.Errorf("purge: get server vm: %w", err)
	}
	server, err := s.store.GetServerPoolByDataAddr(ctx, vm.DataAddr)
	if err != nil {
		return fmt.Errorf("purge: get server pool: %w", err)
	}

	// Fence the active mount session first so a straggling FUSE client can't
	// write into the subtree mid-erase. Best-effort: the pod driving that
	// session is already being torn down by the control-plane.
	if err := api.ClearActiveMountLease(ctx, server.OpsAddr, tenant, alloc.ID.String()); err != nil {
		s.logger.Warn("purge_fence_failed",
			"allocation_id", alloc.ID.String(), "tenant_id", tenant, "error", err)
	}

	last := perAgentTenant
	if !perAgentTenant {
		remaining, err := s.store.CountActiveAllocationsForUser(ctx, alloc.UserID)
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
		released, cleanupErr := s.releaseUnusedOwnerCapacity(ctx, alloc.UserID, tenant)
		if cleanupErr != nil {
			return cleanupErr
		}
		return s.markPurged(ctx, allocID, "tenant_unregistered", released)
	}

	// Legacy shared tenant with other agents: erase just this agent's subtree.
	// No capacity release — the tenant-level reservation backs the survivors.
	if err := api.PurgeAgentData(ctx, server.OpsAddr, tenant, alloc.AgentID); err != nil {
		return fmt.Errorf("purge: agent data on %s: %w", server.OpsAddr, err)
	}
	return s.markPurged(ctx, allocID, "agent_subtree", 0)
}

// releaseUnusedOwnerCapacity drops the erased placement and, once the account
// has neither active allocations nor placements on a reserved server, releases
// its one durable account-level debit. The owner row lock serializes concurrent
// last-agent purges; doing this before purged_at means the sweeper retries the
// whole idempotent cleanup after a crash instead of silently stranding capacity.
func (s *Service) releaseUnusedOwnerCapacity(ctx context.Context, userID uuid.UUID, erasedTenant string) (int64, error) {
	tx, err := s.store.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("purge: begin owner cleanup: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.GetUserForUpdate(ctx, userID); err != nil {
		return 0, fmt.Errorf("purge: lock owner: %w", err)
	}
	if erasedTenant != "" {
		if _, err := tx.DeleteServerVM(ctx, erasedTenant); err != nil {
			return 0, fmt.Errorf("purge: delete placement: %w", err)
		}
	}
	active, err := tx.CountActiveAllocationsForUser(ctx, userID)
	if err != nil {
		return 0, fmt.Errorf("purge: count active allocations: %w", err)
	}
	reservations, err := tx.ListOwnerCapacityReservations(ctx, userID)
	if err != nil {
		return 0, fmt.Errorf("purge: list owner reservations: %w", err)
	}
	var released int64
	if active == 0 {
		for _, reservation := range reservations {
			placed, err := tx.CountPlacedAllocationsForUserOnServer(ctx, userID, reservation.DataAddr)
			if err != nil {
				return 0, fmt.Errorf("purge: count owner placements: %w", err)
			}
			if placed != 0 {
				continue
			}
			n, err := tx.DeleteOwnerCapacityReservation(ctx, userID, reservation.ServerID)
			if err != nil {
				return 0, fmt.Errorf("purge: delete owner reservation: %w", err)
			}
			if n > 0 {
				if err := tx.ReleaseCapacity(ctx, reservation.ServerID, reservation.SizeBytes); err != nil {
					return 0, fmt.Errorf("purge: release owner capacity: %w", err)
				}
				released += reservation.SizeBytes
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("purge: commit owner cleanup: %w", err)
	}
	return released, nil
}

// markPurged CAS-transitions purged_at. Losing the CAS means a concurrent
// purge completed first; the preceding cleanup is idempotent.
func (s *Service) markPurged(ctx context.Context, allocationID uuid.UUID, mode string, releasedBytes int64) error {
	row, err := s.store.MarkAllocationPurged(ctx, allocationID)
	if errors.Is(err, storage.ErrNotFound) {
		return nil // concurrent purge won; it owns the release
	}
	if err != nil {
		return fmt.Errorf("purge: mark purged: %w", err)
	}
	s.logger.Info("allocation_purged",
		"allocation_id", row.ID.String(),
		"agent_id", row.AgentID,
		"mode", mode,
		"released_bytes", releasedBytes)
	return nil
}
