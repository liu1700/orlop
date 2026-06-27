package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/allocations"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/devauth"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/serverapi"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage/postgres"
)

// tenantUsageClient is the subset of *serverapi.Client this handler needs.
// Defined here so tests can inject a fake without standing up an mTLS server.
type tenantUsageClient interface {
	GetTenantUsage(ctx context.Context, opsAddr, tenantID string) (serverapi.TenantUsage, error)
}

// mountLeaseFencer drops orlop-server's active-session record for an
// allocation so the displaced agent's writes start failing immediately. nil
// implementations are tolerated (no fence call), which keeps the dashboard
// usable on dev setups without a serverapi client — at the cost of preserving
// the ~30 s data-correctness window from #175.
type mountLeaseFencer interface {
	FenceAllocation(ctx context.Context, tenantID, allocationID string) error
}

// dashboardStore is the slice of the storage layer the dashboard reads:
// user/quota lookups and the allocation→tenant→server placement chain the
// usage and fence paths walk. *postgres.Store satisfies it.
type dashboardStore interface {
	GetUser(ctx context.Context, id uuid.UUID) (storage.User, error)
	SumActiveAllocationBytes(ctx context.Context, userID uuid.UUID) (int64, error)
	GetAllocation(ctx context.Context, id uuid.UUID) (storage.Allocation, error)
	GetServerVMByTenant(ctx context.Context, tenantID string) (storage.ServerVM, error)
	GetServerPoolByDataAddr(ctx context.Context, dataAddr string) (storage.Server, error)
}

// dashboardHandlers serves the user-facing JSON the Next.js dashboard
// reads. All routes are gated on the admin-session cookie set by the
// device-flow login.
type dashboardHandlers struct {
	logger  *slog.Logger
	devAuth *devauth.Service
	store   dashboardStore
	alloc   *allocations.Service
	usage   tenantUsageClient // nil when the server admin client is not configured (no SecretsDir)
	fencer  mountLeaseFencer  // nil when no serverapi client; revoke skips the fence call
}

func newDashboardHandlers(logger *slog.Logger, svc *devauth.Service, store dashboardStore, alloc *allocations.Service, usage tenantUsageClient, fencer mountLeaseFencer) *dashboardHandlers {
	return &dashboardHandlers{logger: logger, devAuth: svc, store: store, alloc: alloc, usage: usage, fencer: fencer}
}

var _ dashboardStore = (*postgres.Store)(nil)

// mountDashboard registers routes on both bare and /api-prefixed paths.
// Direct callers (CLI, tests, healthchecks) hit the bare path; the Next.js
// web app's /api/[...path] proxy strips the /api/ prefix before forwarding,
// so the bare mount is the one the proxy actually reaches. The /api-
// prefixed mount lets a browser hit the control plane directly without
// going through the Next.js proxy (used by integration tests and the
// hosted-staging admin runbook).
func mountDashboard(r chi.Router, h *dashboardHandlers) {
	for _, prefix := range []string{"", "/api"} {
		r.Get(prefix+"/me", h.handleMe)
		r.Get(prefix+"/allocations", h.handleListAllocations)
		r.Get(prefix+"/allocations/{id}/usage", h.handleAllocationUsage)
		r.Post(prefix+"/allocations/{id}/revoke", h.handleRevokeAllocation)
	}
}

func (h *dashboardHandlers) handleMe(w http.ResponseWriter, r *http.Request) {
	ident, err := adminIdentity(r, h.devAuth)
	if err != nil {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "")
		return
	}
	user, err := h.store.GetUser(r.Context(), toUUID(ident.UserID))
	if err != nil {
		h.logger.Error("dashboard_me_get_user_failed", "error", err, "user_id", uuidString(ident.UserID))
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	used, err := h.store.SumActiveAllocationBytes(r.Context(), toUUID(ident.UserID))
	if err != nil {
		h.logger.Error("dashboard_me_sum_failed", "error", err, "user_id", uuidString(ident.UserID))
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user_id":     uuidString(ident.UserID),
		"tenant_id":   ident.TenantID,
		"purpose":     ident.Purpose,
		"email":       user.Email,
		"quota_bytes": user.QuotaBytes,
		"used_bytes":  used,
	})
}

const (
	mountStatusMounted = "mounted"
	mountStatusIdle    = "idle"
)

type allocationDTO struct {
	ID                  string `json:"id"`
	SizeBytes           int64  `json:"size_bytes"`
	CreatedAt           string `json:"created_at"`
	MountStatus         string `json:"mount_status"`
	MountedAgentID      string `json:"mounted_agent_id,omitempty"`
	MountLeaseExpiresAt string `json:"mount_lease_expires_at,omitempty"`
}

func (h *dashboardHandlers) handleListAllocations(w http.ResponseWriter, r *http.Request) {
	ident, err := adminIdentity(r, h.devAuth)
	if err != nil {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "")
		return
	}
	rows, err := h.alloc.ListForUser(r.Context(), ident.UserID)
	if err != nil {
		h.logger.Error("dashboard_list_allocations_failed", "error", err, "user_id", uuidString(ident.UserID))
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	out := make([]allocationDTO, 0, len(rows))
	now := time.Now().UTC()
	// Mounted = bound AND lease refreshed recently enough that the agent is
	// still alive. Without the horizon a freshly-dead client (lease acquired
	// but process crashed) would show Mounted until the full TTL elapses.
	// Horizon = now + TTL/2 (30 s with the current 60 s TTL), matching the
	// agent's refresh cadence.
	mountedHorizon := now.Add(allocations.LeaseTTL / 2)
	for _, a := range rows {
		dto := allocationDTO{
			ID:          uuidString(a.ID),
			SizeBytes:   a.SizeBytes,
			CreatedAt:   a.CreatedAt.UTC().Format(time.RFC3339),
			MountStatus: mountStatusIdle,
		}
		if a.BoundAgentID != nil && a.LeaseExpiresAt != nil && a.LeaseExpiresAt.After(mountedHorizon) {
			dto.MountStatus = mountStatusMounted
			dto.MountedAgentID = shortAgentID(*a.BoundAgentID)
			dto.MountLeaseExpiresAt = a.LeaseExpiresAt.UTC().Format(time.RFC3339)
		}
		out = append(out, dto)
	}
	writeJSON(w, http.StatusOK, map[string]any{"allocations": out})
}

func (h *dashboardHandlers) handleRevokeAllocation(w http.ResponseWriter, r *http.Request) {
	ident, err := adminIdentity(r, h.devAuth)
	if err != nil {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "")
		return
	}
	allocID, err := parseUUIDParam(chi.URLParam(r, "id"))
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "id must be a uuid")
		return
	}
	if err := h.alloc.Revoke(r.Context(), allocID, ident.UserID); err != nil {
		switch {
		case errors.Is(err, allocations.ErrNotFound), errors.Is(err, allocations.ErrWrongUser):
			// Same response for both: don't leak that another user owns it.
			writeOAuthError(w, http.StatusNotFound, "not_found", "")
		default:
			h.logger.Error("dashboard_revoke_failed", "error", err,
				"user_id", uuidString(ident.UserID),
				"allocation_id", uuidString(allocID))
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		}
		return
	}
	h.fenceAllocationBestEffort(r.Context(), allocID, "revoke")
	w.WriteHeader(http.StatusNoContent)
}

// fenceAllocationBestEffort tells orlop-server to drop the active session for
// allocID, so a displaced mount fails on its next write instead of after its
// next lease-refresh tick. Fence failures are logged but don't fail the
// caller's operation — the DB is already updated, so the lease is gone from
// orlop-control's POV; the worst case is the old #175 window reappearing for
// this one revoke until the client's refresh catches up.
func (h *dashboardHandlers) fenceAllocationBestEffort(ctx context.Context, allocID pgtype.UUID, reason string) {
	if h.fencer == nil {
		return
	}
	alloc, err := h.store.GetAllocation(ctx, toUUID(allocID))
	if err != nil {
		h.logger.Warn("fence_lookup_alloc_failed", "error", err, "allocation_id", uuidString(allocID), "reason", reason)
		return
	}
	user, err := h.store.GetUser(ctx, alloc.UserID)
	if err != nil {
		h.logger.Warn("fence_lookup_user_failed", "error", err, "allocation_id", uuidString(allocID), "reason", reason)
		return
	}
	if err := h.fencer.FenceAllocation(ctx, user.TenantID, uuidString(allocID)); err != nil {
		h.logger.Warn("fence_allocation_failed", "error", err, "tenant_id", user.TenantID, "allocation_id", uuidString(allocID), "reason", reason)
	}
}

func parseUUIDParam(s string) (pgtype.UUID, error) {
	var u pgtype.UUID
	if err := u.Scan(s); err != nil {
		return pgtype.UUID{}, err
	}
	if !u.Valid {
		return pgtype.UUID{}, errors.New("invalid uuid")
	}
	return u, nil
}

// shortAgentID returns the first 8 hex chars of a UUID — a stable
// human-friendly handle for the dashboard table column.
func shortAgentID(u pgtype.UUID) string {
	full := uuidString(u)
	if len(full) >= 8 {
		return full[:8]
	}
	return full
}

type allocationUsageDTO struct {
	AllocationID string `json:"allocation_id"`
	UsedBytes    int64  `json:"used_bytes"`
	SizeBytes    int64  `json:"size_bytes"`
}

func (h *dashboardHandlers) handleAllocationUsage(w http.ResponseWriter, r *http.Request) {
	// Both surfaces hit this: browser dashboard uses the cookie, CLI uses the
	// device-flow bearer token. Accept either.
	ident, err := adminOrBearerIdentity(r, h.devAuth)
	if err != nil {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "")
		return
	}
	if h.usage == nil {
		writeOAuthError(w, http.StatusServiceUnavailable, "usage_unavailable", "")
		return
	}
	allocID, err := parseUUIDParam(chi.URLParam(r, "id"))
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "id must be a uuid")
		return
	}

	// Ownership + revocation check via the same path the dashboard already trusts.
	alloc, err := h.alloc.GetForUser(r.Context(), allocID, ident.UserID)
	if err != nil {
		switch {
		case errors.Is(err, allocations.ErrNotFound), errors.Is(err, allocations.ErrWrongUser):
			writeOAuthError(w, http.StatusNotFound, "not_found", "")
		case errors.Is(err, allocations.ErrRevoked):
			writeOAuthError(w, http.StatusGone, "revoked", "")
		default:
			h.logger.Error("dashboard_usage_get_alloc_failed", "error", err,
				"user_id", uuidString(ident.UserID), "allocation_id", uuidString(allocID))
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		}
		return
	}

	user, err := h.store.GetUser(r.Context(), toUUID(ident.UserID))
	if err != nil {
		h.logger.Error("dashboard_usage_get_user_failed", "error", err, "user_id", uuidString(ident.UserID))
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}

	vm, err := h.store.GetServerVMByTenant(r.Context(), user.TenantID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			// Allocation exists but tenant has never been placed on a server
			// (i.e. no `orlop mount` since allocation was created). Surface
			// zero usage so the dashboard / CLI can render something sensible.
			writeJSON(w, http.StatusOK, allocationUsageDTO{
				AllocationID: uuidString(alloc.ID),
				UsedBytes:    0,
				SizeBytes:    alloc.SizeBytes,
			})
			return
		}
		h.logger.Error("dashboard_usage_get_server_vm_failed", "error", err, "tenant_id", user.TenantID)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	pool, err := h.store.GetServerPoolByDataAddr(r.Context(), vm.DataAddr)
	if err != nil {
		h.logger.Error("dashboard_usage_get_server_pool_failed", "error", err, "data_addr", vm.DataAddr)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}

	tu, err := h.usage.GetTenantUsage(r.Context(), pool.OpsAddr, user.TenantID)
	if err != nil {
		h.logger.Error("dashboard_usage_remote_failed", "error", err,
			"ops_addr", pool.OpsAddr, "tenant_id", user.TenantID)
		writeOAuthError(w, http.StatusBadGateway, "usage_failed", "")
		return
	}

	writeJSON(w, http.StatusOK, allocationUsageDTO{
		AllocationID: uuidString(alloc.ID),
		UsedBytes:    tu.UsedBytes,
		// DB is authoritative for the quota. The remote `tu.SizeBytes` is the
		// server-side echo; we keep it for log debugging only.
		SizeBytes: alloc.SizeBytes,
	})
}
