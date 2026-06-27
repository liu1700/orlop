package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage/postgres"
)

// tenantPlacementQuerier resolves where a tenant's data plane lives (server_vms →
// server_pools). *postgres.Store satisfies it; see [resolveTenantOpsAddr].
type tenantPlacementQuerier interface {
	GetServerVMByTenant(ctx context.Context, tenantID string) (storage.ServerVM, error)
	GetServerPoolByDataAddr(ctx context.Context, dataAddr string) (storage.Server, error)
}

// controlTenantUsageQuerier is the slice of the storage layer the per-user usage
// route needs. An interface so the unit tests inject a stub without a live DB.
type controlTenantUsageQuerier interface {
	GetUser(ctx context.Context, id uuid.UUID) (storage.User, error)
	ListAllocationsForUser(ctx context.Context, userID uuid.UUID) ([]storage.Allocation, error)
	tenantPlacementQuerier
}

// resolveTenantOpsAddr resolves a tenant's orlop-server ops address:
// server_vms → server_pools. placed is false (with a nil error) when the tenant
// has no server_vms row yet — it has never been mounted, so it has no usage. This
// is the same chain dashboard_handlers.go handleAllocationUsage and the serverapi
// adapters walk; a future cleanup could converge those onto this helper.
func resolveTenantOpsAddr(ctx context.Context, q tenantPlacementQuerier, tenantID string) (opsAddr string, placed bool, err error) {
	vm, err := q.GetServerVMByTenant(ctx, tenantID)
	if errors.Is(err, storage.ErrNotFound) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("resolve ops addr: server vm: %w", err)
	}
	pool, err := q.GetServerPoolByDataAddr(ctx, vm.DataAddr)
	if err != nil {
		return "", false, fmt.Errorf("resolve ops addr: server pool: %w", err)
	}
	return pool.OpsAddr, true, nil
}

// controlTenantUsageHandlers serves GET /v1/tenants/{owner}/usage — the
// control-plane→control-plane storage-metering surface. It reports an owner's
// aggregate disk usage (used_bytes across the owner's per-user tenant) so the
// control-plane's storage sweeper can bill each user once per day. The owner is
// the orlop user UUID the control-plane provisions disks under (entity owner_id),
// which the dg reuses as the dg user id (entity_handlers.go handleProvision), so
// GetUser(owner) → user.TenantID is the per-user tenant that holds the disks.
//
// Gated by RequireServiceToken in newRouter — never a user-facing surface, so it
// carries no per-allocation ownership check (the control-plane is trusted).
type controlTenantUsageHandlers struct {
	logger  *slog.Logger
	queries controlTenantUsageQuerier
	usage   tenantUsageClient // nil when no serverapi client (no SecretsDir): route 503s
}

func newControlTenantUsageHandlers(logger *slog.Logger, q controlTenantUsageQuerier, usage tenantUsageClient) *controlTenantUsageHandlers {
	return &controlTenantUsageHandlers{logger: logger, queries: q, usage: usage}
}

// mountControlTenantUsage registers the route on both the bare and /api-prefixed
// paths (the production edge strips /api before forwarding), gated by svc. Like
// /v1/entities this is a control-plane→control-plane surface, never user-facing.
func mountControlTenantUsage(r chi.Router, svc func(http.Handler) http.Handler, h *controlTenantUsageHandlers) {
	for _, prefix := range []string{"", "/api"} {
		r.With(svc).Get(prefix+"/v1/tenants/{owner}/usage", h.handleTenantUsage)
	}
}

type tenantUsageDTO struct {
	OwnerID   string `json:"owner_id"`
	UsedBytes int64  `json:"used_bytes"`
}

// handleTenantUsage resolves owner → per-user tenant → placed server → remote
// usage, mirroring dashboard_handlers.go handleAllocationUsage but keyed on the
// owner (not an allocation). Reports zero usage — never an error — when the owner
// has no dg user or has never been placed on a server (no mount yet), so the
// sweeper treats "not provisioned" as "nothing to bill".
func (h *controlTenantUsageHandlers) handleTenantUsage(w http.ResponseWriter, r *http.Request) {
	if h.usage == nil {
		writeOAuthError(w, http.StatusServiceUnavailable, "usage_unavailable", "")
		return
	}
	ownerID, err := parseUUIDParam(chi.URLParam(r, "owner"))
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "owner must be a uuid")
		return
	}
	zero := tenantUsageDTO{OwnerID: uuidString(ownerID), UsedBytes: 0}

	user, err := h.queries.GetUser(r.Context(), toUUID(ownerID))
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			// Owner has never provisioned a disk → no dg user → zero usage.
			writeJSON(w, http.StatusOK, zero)
			return
		}
		h.logger.Error("control_usage_get_user_failed", "error", err, "owner_id", uuidString(ownerID))
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}

	// Each of the owner's agents now has its OWN storage tenant; their used bytes sum
	// to the owner's total (docs/design/per-agent-tenant.md). A legacy non-agent
	// allocation with no per-agent tenant falls back to the owner's tenant.
	allocs, err := h.queries.ListAllocationsForUser(r.Context(), toUUID(ownerID))
	if err != nil {
		h.logger.Error("control_usage_list_allocations_failed", "error", err, "owner_id", uuidString(ownerID))
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	tenants := make(map[string]struct{}, len(allocs))
	for _, a := range allocs {
		t := user.TenantID
		if a.TenantID != "" {
			t = a.TenantID
		}
		tenants[t] = struct{}{}
	}

	var total int64
	for tenant := range tenants {
		opsAddr, placed, err := resolveTenantOpsAddr(r.Context(), h.queries, tenant)
		if err != nil {
			h.logger.Error("control_usage_resolve_ops_addr_failed", "error", err, "tenant_id", tenant)
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
			return
		}
		if !placed {
			continue // tenant never placed (no mount yet) → contributes no usage
		}
		tu, err := h.usage.GetTenantUsage(r.Context(), opsAddr, tenant)
		if err != nil {
			h.logger.Error("control_usage_remote_failed", "error", err, "ops_addr", opsAddr, "tenant_id", tenant)
			writeOAuthError(w, http.StatusBadGateway, "usage_failed", "")
			return
		}
		total += tu.UsedBytes
	}

	writeJSON(w, http.StatusOK, tenantUsageDTO{OwnerID: uuidString(ownerID), UsedBytes: total})
}

// ensure *postgres.Store satisfies controlTenantUsageQuerier at compile time.
var _ controlTenantUsageQuerier = (*postgres.Store)(nil)
