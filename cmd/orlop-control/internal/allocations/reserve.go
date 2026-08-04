package allocations

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

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
// server_vms. Pool capacity is debited once per owner/server; later agents for
// the owner reuse that reservation. Idempotent — if a server_vms row already
// exists for tenantID, returns its data_addr without touching the pool or API.
//
// Errors:
//   - ErrNoCapacity if no server_pool row has free_bytes >= sizeBytes.
//   - Wrapped error for admin-API or DB failures.
//
// ownerTenantID is the account tenant (u_<owner>) this tenant belongs to; the server
// nests the tenant dir under it and puts the shared account quota on the owner dir.
// sizeBytes is the ACCOUNT disk budget (the owner-dir cap), not a per-agent grant.
func (s *Service) Reserve(
	ctx context.Context,
	api ServerAdmin,
	ownerUserID uuid.UUID,
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

	// --- Phase 1: serialize this owner's first placement and reserve once. ---
	tx, err := s.store.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("allocations: begin tx: %w", err)
	}

	defer tx.Rollback(ctx) // no-op after Commit
	if _, err := tx.GetUserForUpdate(ctx, ownerUserID); err != nil {
		return "", fmt.Errorf("allocations: lock owner: %w", err)
	}
	reservations, err := tx.ListOwnerCapacityReservations(ctx, ownerUserID)
	if err != nil {
		return "", fmt.Errorf("allocations: list owner reservations: %w", err)
	}
	var chosen storage.ChosenServer
	if len(reservations) > 0 {
		// Keep an account's agents together. This matches the shared owner-dir
		// quota and avoids creating another reservation on another server.
		r := reservations[0]
		chosen = storage.ChosenServer{ID: r.ServerID, DataAddr: r.DataAddr, OpsAddr: r.OpsAddr}
	} else {
		chosen, err = tx.PickBestAvailableServer(ctx, sizeBytes)
		if errors.Is(err, storage.ErrNotFound) {
			return "", ErrNoCapacity
		}
		if err != nil {
			return "", fmt.Errorf("allocations: pick server: %w", err)
		}
		if err = tx.ReserveCapacity(ctx, chosen.ID, sizeBytes); errors.Is(err, storage.ErrNotFound) {
			return "", ErrNoCapacity
		} else if err != nil {
			return "", fmt.Errorf("allocations: reserve capacity: %w", err)
		}
		if err = tx.CreateOwnerCapacityReservation(ctx, ownerUserID, chosen.ID, sizeBytes); err != nil {
			return "", fmt.Errorf("allocations: record owner reservation: %w", err)
		}
	}

	// Commit the capacity decrement before making the network call. Keeping
	// a long-lived tx open across an HTTP call would hold the row lock and
	// cause contention.
	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("allocations: commit reservation: %w", err)
	}

	// --- Phase 2: register tenant on the chosen server (ops listener) ---
	_, err = api.RegisterTenant(ctx, chosen.OpsAddr, tenantID, ownerTenantID, name, sizeBytes)
	if err != nil {
		// Keep the owner reservation. The allocation still owns this budget and
		// a retry must reuse the same server instead of leaking another debit.
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
			winner, getErr := s.store.GetServerVMByTenant(ctx, tenantID)
			if getErr != nil {
				return "", fmt.Errorf("allocations: get winner server vm: %w", getErr)
			}
			return winner.DataAddr, nil
		}
		return "", fmt.Errorf("allocations: create server vm: %w", err)
	}

	return chosen.DataAddr, nil
}
