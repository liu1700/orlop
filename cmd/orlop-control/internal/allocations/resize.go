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

// TenantResizer applies a new hard size cap to a tenant's storage on the
// orlop-server that hosts it. Satisfied by *serverapi.Client.ResizeTenant.
// Passed per-call (like ServerAdmin) to keep Resize testable without a live server.
type TenantResizer interface {
	ResizeTenant(ctx context.Context, opsAddr, tenantID string, sizeBytes int64) (projectID uint32, err error)
}

// Resize changes an allocation's hard size cap end-to-end, keeping the three
// places that track it consistent: the disk_allocations row (size_bytes), the
// hosting server's server_pool reservation (free_bytes), and the data-plane
// ext4 quota (via TenantResizer). It is the primitive the storage autoscaler and
// a cap upgrade both drive. Idempotent when newSizeBytes already matches.
//
// If the allocation's tenant has not been placed on a server yet (no server_vms
// row — e.g. provisioned but never enrolled), only the DB size is updated; the
// new cap takes effect when the tenant is first Reserve'd at enroll.
//
// Capacity safety: a grow first reserves the delta against the hosting server's
// free_bytes and fails with ErrNoCapacity if the server is full — we never widen
// a kernel quota past what the pool can back. A shrink releases the delta.
//
// Ordering & compensation (mirrors Reserve): the pool delta is applied first,
// then the data-plane call, then the DB size. A failure after a successful step
// compensates the earlier ones on a fresh context so a cancelled parent cannot
// strand capacity or leave the kernel quota wider than the recorded size.
func (s *Service) Resize(
	ctx context.Context,
	api TenantResizer,
	allocationID, userID pgtype.UUID,
	newSizeBytes int64,
) (Allocation, error) {
	if newSizeBytes <= 0 {
		return Allocation{}, fmt.Errorf("allocations: size_bytes must be positive, got %d", newSizeBytes)
	}

	alloc, err := s.q.GetAllocation(ctx, allocationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Allocation{}, ErrNotFound
	}
	if err != nil {
		return Allocation{}, fmt.Errorf("allocations: get allocation: %w", err)
	}
	if alloc.UserID != userID {
		return Allocation{}, ErrWrongUser
	}
	if alloc.RevokedAt.Valid {
		return Allocation{}, ErrRevoked
	}
	oldSize := alloc.SizeBytes
	if newSizeBytes == oldSize {
		return fromRow(alloc), nil // idempotent
	}

	// Resolve the tenant (the user's tenant is what Reserve placed) and, if the
	// tenant is placed, the server hosting it.
	user, err := s.q.GetUser(ctx, userID)
	if err != nil {
		return Allocation{}, fmt.Errorf("allocations: get user: %w", err)
	}
	// The disk lives in its per-agent tenant (falling back to the user's tenant for a
	// legacy non-agent allocation); that's where placement + the data-plane cap apply.
	tenant := user.TenantID
	if alloc.TenantID.Valid && alloc.TenantID.String != "" {
		tenant = alloc.TenantID.String
	}
	vm, err := s.q.GetServerVMByTenant(ctx, tenant)
	if errors.Is(err, pgx.ErrNoRows) {
		// Not placed yet: nothing to resize on the data plane and no reservation
		// to adjust. Record the size so the next enroll reserves the new amount.
		return s.updateSizeOnly(ctx, allocationID, userID, newSizeBytes, "unplaced")
	}
	if err != nil {
		return Allocation{}, fmt.Errorf("allocations: get server vm: %w", err)
	}
	server, err := s.q.GetServerPoolByDataAddr(ctx, vm.DataAddr)
	if err != nil {
		return Allocation{}, fmt.Errorf("allocations: get server pool: %w", err)
	}

	// --- Phase 1: adjust the hosting server's reservation by the delta ---
	// Growth uses ReserveCapacityForGrowth so a resident can still expand on a
	// server that has been marked 'draining' (no new placements past its
	// high-water mark, but in-place growth must keep working).
	delta := newSizeBytes - oldSize
	if delta > 0 {
		if _, err := s.q.ReserveCapacityForGrowth(ctx, sqlcdb.ReserveCapacityForGrowthParams{FreeBytes: delta, ID: server.ID}); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return Allocation{}, ErrNoCapacity
			}
			return Allocation{}, fmt.Errorf("allocations: reserve grow delta: %w", err)
		}
	} else if _, err := s.q.ReleaseCapacity(ctx, sqlcdb.ReleaseCapacityParams{FreeBytes: -delta, ID: server.ID}); err != nil {
		return Allocation{}, fmt.Errorf("allocations: release shrink delta: %w", err)
	}

	// --- Phase 2: apply the new cap on the data plane ---
	if _, err := api.ResizeTenant(ctx, server.OpsAddr, tenant, newSizeBytes); err != nil {
		s.compensatePoolDelta(ctx, server.ID, delta, "data_plane", err)
		return Allocation{}, fmt.Errorf("allocations: resize tenant on %s: %w", server.OpsAddr, err)
	}

	// --- Phase 3: record the new size in the DB ---
	row, err := s.q.UpdateAllocationSize(ctx, sqlcdb.UpdateAllocationSizeParams{
		ID: allocationID, UserID: userID, SizeBytes: newSizeBytes,
	})
	if err != nil {
		// Roll the data plane back to the old cap, then reverse the pool delta.
		rbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		if _, rbErr := api.ResizeTenant(rbCtx, server.OpsAddr, tenant, oldSize); rbErr != nil {
			s.logger.Error("allocations_resize_dataplane_rollback_failed",
				"allocation_id", allocationID, "tenant_id", tenant, "cause", err, "rollback_error", rbErr)
		}
		cancel()
		s.compensatePoolDelta(ctx, server.ID, delta, "update_size", err)
		return Allocation{}, fmt.Errorf("allocations: update size: %w", err)
	}

	s.logger.Info("allocation_resized",
		"allocation_id", allocationID, "tenant_id", user.TenantID, "server_id", server.ID,
		"old_size_bytes", oldSize, "new_size_bytes", newSizeBytes)
	return fromRow(row), nil
}

// updateSizeOnly records a new size_bytes without touching the pool or data
// plane — used when the tenant has no server placement yet.
func (s *Service) updateSizeOnly(ctx context.Context, allocationID, userID pgtype.UUID, newSizeBytes int64, reason string) (Allocation, error) {
	row, err := s.q.UpdateAllocationSize(ctx, sqlcdb.UpdateAllocationSizeParams{
		ID: allocationID, UserID: userID, SizeBytes: newSizeBytes,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Allocation{}, ErrNotFound
	}
	if err != nil {
		return Allocation{}, fmt.Errorf("allocations: update size (%s): %w", reason, err)
	}
	return fromRow(row), nil
}

// compensatePoolDelta reverses a Phase-1 reservation delta on a fresh context so
// a cancelled parent cannot strand capacity. A positive delta was a reservation
// (release it back); a negative delta was a release (re-reserve it).
func (s *Service) compensatePoolDelta(ctx context.Context, serverID pgtype.UUID, delta int64, reason string, cause error) {
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	var err error
	if delta > 0 {
		_, err = s.q.ReleaseCapacity(cctx, sqlcdb.ReleaseCapacityParams{FreeBytes: delta, ID: serverID})
	} else {
		// Re-reserving what a shrink released: allow draining so we don't fail to
		// restore capacity on a server past its high-water mark.
		_, err = s.q.ReserveCapacityForGrowth(cctx, sqlcdb.ReserveCapacityForGrowthParams{FreeBytes: -delta, ID: serverID})
	}
	if err != nil {
		s.logger.Error("allocations_resize_compensate_pool_failed",
			"server_id", serverID, "delta", delta, "reason", reason, "cause", cause, "compensate_error", err)
	}
}
