package main

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/allocations"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/db/sqlcdb"
)

const (
	purgeSweepDefaultLimit = 100
	purgeSweepMaxLimit     = 500
)

// purgePendingLister is the one query the sweep needs; an interface so the
// handler tests can stub it.
type purgePendingLister interface {
	ListPurgePendingAllocations(ctx context.Context, limit int32) ([]sqlcdb.ListPurgePendingAllocationsRow, error)
}

// purgeSweepHandlers serves POST /v1/admin/purge-sweep — the on-demand sweeper
// that erases backend data for revoked-but-unpurged allocations. It is the
// backstop for the inline purge on DELETE /v1/entities (which is best-effort):
// anything that path missed — a data-plane outage, a crash between revoke and
// purge, rows revoked before purge existed — queues up as
// revoked_at IS NOT NULL AND purged_at IS NULL and is drained here.
//
// Same static service-token gate as /v1/entities: this is an operator/control-
// plane surface, never user-facing.
type purgeSweepHandlers struct {
	logger  *slog.Logger
	queries purgePendingLister
	purge   allocationPurger
	api     allocations.AgentDataPurger
}

func newPurgeSweepHandlers(logger *slog.Logger, q purgePendingLister, purge allocationPurger, api allocations.AgentDataPurger) *purgeSweepHandlers {
	return &purgeSweepHandlers{logger: logger, queries: q, purge: purge, api: api}
}

func mountPurgeSweep(r chi.Router, svc func(http.Handler) http.Handler, h *purgeSweepHandlers) {
	for _, prefix := range []string{"", "/api"} {
		r.With(svc).Post(prefix+"/v1/admin/purge-sweep", h.handleSweep)
	}
}

type purgeSweepResponse struct {
	Pending int `json:"pending"`
	Purged  int `json:"purged"`
	Failed  int `json:"failed"`
}

// handleSweep drains up to `limit` pending purges (default 100, cap 500) and
// reports what it did. Failures are logged per-allocation and left pending —
// rerunning the sweep retries them. POST /v1/admin/purge-sweep?limit=N.
func (h *purgeSweepHandlers) handleSweep(w http.ResponseWriter, r *http.Request) {
	if h.api == nil {
		writeOAuthError(w, http.StatusServiceUnavailable, "server_error",
			"no data-plane admin client configured")
		return
	}

	limit := int64(purgeSweepDefaultLimit)
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.ParseInt(raw, 10, 32)
		if err != nil || n <= 0 {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "limit must be a positive integer")
			return
		}
		limit = min(n, purgeSweepMaxLimit)
	}

	rows, err := h.queries.ListPurgePendingAllocations(r.Context(), int32(limit))
	if err != nil {
		h.logger.Error("purge_sweep_list_failed", "error", err)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}

	resp := purgeSweepResponse{Pending: len(rows)}
	for _, row := range rows {
		if r.Context().Err() != nil {
			break
		}
		if err := h.purge.PurgeAllocation(r.Context(), h.api, row.AllocationID); err != nil {
			resp.Failed++
			h.logger.Error("purge_sweep_allocation_failed",
				"allocation_id", uuidString(row.AllocationID),
				"agent_id", row.AgentID.String,
				"error", err)
			continue
		}
		resp.Purged++
	}

	h.logger.Info("purge_sweep_complete",
		"pending", resp.Pending, "purged", resp.Purged, "failed", resp.Failed)
	writeJSON(w, http.StatusOK, resp)
}

// ensure the production types satisfy the handler interfaces.
var (
	_ purgePendingLister = (*sqlcdb.Queries)(nil)
	_ allocationPurger   = (*allocations.Service)(nil)
)
