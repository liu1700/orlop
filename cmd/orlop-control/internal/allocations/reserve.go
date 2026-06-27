package allocations

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
)

// ErrNoCapacity is returned by Reserve when no server_pool row has
// free_bytes >= the requested sizeBytes.
var ErrNoCapacity = errors.New("allocations: no server has sufficient free capacity")

// Server pool status values. These match the CHECK constraint in the schema.
const (
	ServerStatusAvailable   = "available"
	ServerStatusDraining    = "draining"
	ServerStatusUnavailable = "unavailable"
)

// ServerAdmin is a minimal interface over the control-plane → orlop-server
// admin client. Passed per-call to keep tests cheap.
type ServerAdmin interface {
	RegisterTenant(ctx context.Context, opsAddr, tenantID, ownerTenantID, name string, sizeBytes int64) (projectID uint32, err error)
}

// Reserve places a tenant on a orlop-server VM and records the binding in
// server_vms. Idempotent — if a server_vms row already exists for tenantID,
// returns its data_addr without touching the pool or calling the admin API.
//
// Errors:
//   - ErrNoCapacity if no server_pool row has free_bytes >= sizeBytes.
//   - Wrapped error for admin-API or DB failures (compensating release
//     happens automatically before returning).
//
// ownerTenantID is the account tenant (u_<owner>) this tenant belongs to; the server
// nests the tenant dir under it and puts the shared account quota on the owner dir.
// sizeBytes is the ACCOUNT disk budget (the owner-dir cap), not a per-agent grant.
func (s *Service) Reserve(
	ctx context.Context,
	api ServerAdmin,
	tenantID, ownerTenantID, name string,
	sizeBytes int64,
) (dataAddr string, err error) {
	// --- Phase 0: idempotent check without a transaction ---
	existing, err := s.store.GetServerVMByTenant(ctx, tenantID)
	if err == nil {
		// Already placed — fast path, no tx needed.
		return existing.DataAddr, nil
	}
	if !errors.Is(err, storage.ErrNotFound) {
		return "", fmt.Errorf("allocations: get server vm: %w", err)
	}

	// --- Phase 1: capacity reservation inside a transaction ---
	tx, err := s.store.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("allocations: begin tx: %w", err)
	}

	chosen, err := tx.PickBestAvailableServer(ctx, sizeBytes)
	if errors.Is(err, storage.ErrNotFound) {
		_ = tx.Rollback(ctx)
		return "", ErrNoCapacity
	}
	if err != nil {
		_ = tx.Rollback(ctx)
		return "", fmt.Errorf("allocations: pick server: %w", err)
	}

	err = tx.ReserveCapacity(ctx, chosen.ID, sizeBytes)
	if errors.Is(err, storage.ErrNotFound) {
		// Lost a race with another reservation on this server.
		_ = tx.Rollback(ctx)
		return "", ErrNoCapacity
	}
	if err != nil {
		_ = tx.Rollback(ctx)
		return "", fmt.Errorf("allocations: reserve capacity: %w", err)
	}

	// Commit the capacity decrement before making the network call. Keeping
	// a long-lived tx open across an HTTP call would hold the row lock and
	// cause contention.
	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("allocations: commit reservation: %w", err)
	}

	compensate := func(reason string, compErr error) {
		// Compensating release — use a fresh context so a cancelled parent
		// (e.g. client disconnect) does not prevent capacity from being restored.
		compensateCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if rErr := s.store.ReleaseCapacity(compensateCtx, chosen.ID, sizeBytes); rErr != nil {
			s.logger.Error("allocations_reserve_compensate_failed",
				"tenant_id", tenantID,
				"server_id", chosen.ID,
				"reason", reason,
				"original_error", compErr,
				"release_error", rErr,
			)
		}
	}

	// --- Phase 2: register tenant on the chosen server (ops listener) ---
	_, err = api.RegisterTenant(ctx, chosen.OpsAddr, tenantID, ownerTenantID, name, sizeBytes)
	if err != nil {
		compensate("admin_api", err)
		return "", fmt.Errorf("allocations: register tenant on %s: %w", chosen.OpsAddr, err)
	}

	// --- Phase 3: record the server_vms binding (FUSE clients will use data_addr) ---
	err = s.store.CreateServerVM(ctx, storage.NewServerVM{
		TenantID: tenantID,
		DataAddr: chosen.DataAddr,
		Status:   "active",
	})
	if err != nil {
		// A concurrent Reserve won the race (unique violation on tenant_id).
		if errors.Is(err, storage.ErrAlreadyExists) {
			// Release our reservation and return the winner's data_addr.
			compensate("unique_violation", err)
			winner, getErr := s.store.GetServerVMByTenant(ctx, tenantID)
			if getErr != nil {
				return "", fmt.Errorf("allocations: get winner server vm: %w", getErr)
			}
			return winner.DataAddr, nil
		}
		compensate("create_server_vm", err)
		return "", fmt.Errorf("allocations: create server vm: %w", err)
	}

	return chosen.DataAddr, nil
}
