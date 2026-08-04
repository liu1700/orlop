package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/allocations"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage/postgres"
)

const (
	purgeSweepDefaultLimit = 100
	purgeSweepMaxLimit     = 500
)

var errPurgeDataPlaneUnavailable = errors.New("no data-plane admin client configured")

// purgePendingLister is the one query the sweep needs; an interface so the
// handler tests can stub it.
type purgePendingLister interface {
	ListPurgePendingAllocations(ctx context.Context, limit int32) ([]storage.PurgePendingAllocation, error)
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
	mountBoth(func(prefix string) {
		r.With(svc).Post(prefix+"/v1/admin/purge-sweep", h.handleSweep)
	})
}

type purgeSweepResponse struct {
	Pending int `json:"pending"`
	Purged  int `json:"purged"`
	Failed  int `json:"failed"`
}

// Run performs one reconciliation immediately, then repeats on interval until
// shutdown. The immediate pass bounds recovery after a control-plane restart;
// the ticker is the level-triggered backstop for inline purge edges that were
// missed because of a crash or transient data-plane failure.
func (h *purgeSweepHandlers) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 || h.api == nil {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	h.runScheduledSweep(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.runScheduledSweep(ctx)
		}
	}
}

func (h *purgeSweepHandlers) runScheduledSweep(ctx context.Context) {
	if _, err := h.sweep(ctx, purgeSweepMaxLimit); err != nil && ctx.Err() == nil {
		h.logger.Warn("purge_sweep_reconcile_failed", "error", err)
	}
}

// handleSweep drains up to `limit` pending purges (default 100, cap 500) and
// reports what it did. Failures are logged per-allocation and left pending —
// rerunning the sweep retries them. POST /v1/admin/purge-sweep?limit=N.
func (h *purgeSweepHandlers) handleSweep(w http.ResponseWriter, r *http.Request) {
	if h.api == nil {
		writeOAuthError(w, http.StatusServiceUnavailable, "server_error",
			errPurgeDataPlaneUnavailable.Error())
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

	resp, err := h.sweep(r.Context(), int(limit))
	if err != nil {
		h.logger.Error("purge_sweep_list_failed", "error", err)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *purgeSweepHandlers) sweep(ctx context.Context, limit int) (purgeSweepResponse, error) {
	if h.api == nil {
		return purgeSweepResponse{}, errPurgeDataPlaneUnavailable
	}
	rows, err := h.queries.ListPurgePendingAllocations(ctx, int32(limit))
	if err != nil {
		return purgeSweepResponse{}, err
	}

	resp := purgeSweepResponse{Pending: len(rows)}
	for _, row := range rows {
		if ctx.Err() != nil {
			break
		}
		if err := h.purge.PurgeAllocation(ctx, h.api, fromUUID(row.AllocationID)); err != nil {
			resp.Failed++
			h.logger.Error("purge_sweep_allocation_failed",
				"allocation_id", row.AllocationID.String(),
				"agent_id", row.AgentID,
				"error", err)
			continue
		}
		resp.Purged++
	}

	h.logger.Info("purge_sweep_complete",
		"pending", resp.Pending, "purged", resp.Purged, "failed", resp.Failed)
	return resp, nil
}

// ensure the production types satisfy the handler interfaces.
var (
	_ purgePendingLister = (*postgres.Store)(nil)
	_ allocationPurger   = (*allocations.Service)(nil)
)
