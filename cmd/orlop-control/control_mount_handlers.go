package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/allocations"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/db/sqlcdb"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/devauth"
)

type mountLeaseHandlers struct {
	logger  *slog.Logger
	alloc   *allocations.Service
	q       *sqlcdb.Queries
	devAuth *devauth.Service
	fencer  mountLeaseFencer
}

func newMountLeaseHandlers(logger *slog.Logger, alloc *allocations.Service, q *sqlcdb.Queries, dev *devauth.Service, fencer mountLeaseFencer) *mountLeaseHandlers {
	return &mountLeaseHandlers{logger: logger, alloc: alloc, q: q, devAuth: dev, fencer: fencer}
}

func mountLeaseRoutes(r chi.Router, h *mountLeaseHandlers) {
	for _, prefix := range []string{"", "/api"} {
		r.Post(prefix+"/allocations/{id}/mount", h.handleAcquireMount)
		r.Post(prefix+"/allocations/{id}/mount/refresh", h.handleRefreshMount)
		r.Delete(prefix+"/allocations/{id}/mount", h.handleReleaseMount)
		r.Post(prefix+"/allocations/{id}/unmount", h.handleOwnerUnmount)
	}
}

type mountLeaseRequest struct {
	AgentFingerprint string `json:"agent_fingerprint"`
}

func (h *mountLeaseHandlers) handleAcquireMount(w http.ResponseWriter, r *http.Request) {
	allocID, agentID, ok := h.resolveMountRequest(w, r)
	if !ok {
		return
	}
	a, err := h.alloc.AcquireMountLease(r.Context(), allocID, agentID, allocations.LeaseTTL)
	if err != nil {
		h.writeLeaseError(w, r, "acquire", allocID, agentID, err)
		return
	}
	// Fence any stale server-side session before the mounter opens its new one. On a
	// fresh mount this is a no-op; on a same-agent takeover (a one-shot pod re-mounting,
	// or recovery from a leaked lease) it moves the previous session's hex into the
	// fenced set so orlop-server accepts THIS mount's new hex instead of rejecting
	// it with "session fenced". Without it, the DB-lease takeover would still be blocked
	// at the data plane. Best-effort, like the release path.
	h.fenceAllocation(r, allocID, "acquire")
	writeJSON(w, http.StatusOK, map[string]any{
		"lease_id":   uuidString(a.ID),
		"expires_at": a.LeaseExpiresAt.UTC().Format(time.RFC3339),
	})
}

func (h *mountLeaseHandlers) handleRefreshMount(w http.ResponseWriter, r *http.Request) {
	allocID, agentID, ok := h.resolveMountRequest(w, r)
	if !ok {
		return
	}
	a, err := h.alloc.RefreshMountLease(r.Context(), allocID, agentID, allocations.LeaseTTL)
	if err != nil {
		h.writeLeaseError(w, r, "refresh", allocID, agentID, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"expires_at": a.LeaseExpiresAt.UTC().Format(time.RFC3339),
	})
}

func (h *mountLeaseHandlers) handleReleaseMount(w http.ResponseWriter, r *http.Request) {
	allocID, agentID, ok := h.resolveMountRequest(w, r)
	if !ok {
		return
	}
	if err := h.alloc.ReleaseMountLease(r.Context(), allocID, agentID); err != nil {
		switch {
		case errors.Is(err, allocations.ErrNotFound):
			writeOAuthError(w, http.StatusNotFound, "not_found", "")
		case errors.Is(err, allocations.ErrWrongAgent):
			writeOAuthError(w, http.StatusConflict, "wrong_agent", "")
		default:
			h.logger.Error("mount_release_failed", "error", err, "allocation_id", uuidString(allocID), "agent_id", uuidString(agentID))
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		}
		return
	}
	// Tell orlop-server to drop its active-session record. Without this the
	// server keeps the previous lease_hex in mountLeases[alloc].active even
	// though the DB lease is gone, so the next mount's checkSessionFence
	// rejects the new hex with EACCES "session fenced" (see #181).
	h.fenceAllocation(r, allocID, "release")
	w.WriteHeader(http.StatusNoContent)
}

// fenceAllocation tells orlop-server to clear its active mount-lease record
// for an allocation. Best-effort: failures are logged but not propagated to
// the caller, matching the precedent in handleOwnerUnmount. reason is
// stamped on the warn log for triage.
func (h *mountLeaseHandlers) fenceAllocation(r *http.Request, allocID pgtype.UUID, reason string) {
	if h.fencer == nil {
		return
	}
	alloc, err := h.q.GetAllocation(r.Context(), allocID)
	if err != nil {
		return
	}
	user, err := h.q.GetUser(r.Context(), alloc.UserID)
	if err != nil {
		return
	}
	if ferr := h.fencer.FenceAllocation(r.Context(), user.TenantID, uuidString(allocID)); ferr != nil {
		h.logger.Warn("fence_allocation_failed",
			"error", ferr,
			"tenant_id", user.TenantID,
			"allocation_id", uuidString(allocID),
			"reason", reason)
	}
}

// resolveMountRequest authenticates the agent cert and returns the allocation id and the
// authenticated enrollment id (the mount lease's bound_agent_id, an FK into
// agent_enrollments). It ALSO checks that the cert's user owns the allocation and that the
// allocation is bound to an agent — that ownership check is what makes the unconditional
// lease takeover safe (AcquireMountLease): an allocation belongs to a single orlop agent,
// so any authorized enrollment mounting it IS that agent, and a one-shot pod re-mounting
// with a fresh cert each turn must be able to take over the prior pod's (possibly leaked)
// lease. Cross-tenant access is denied here; cross-agent access is enforced at the data
// plane by the agent-scoped cert.
func (h *mountLeaseHandlers) resolveMountRequest(w http.ResponseWriter, r *http.Request) (pgtype.UUID, pgtype.UUID, bool) {
	allocID, err := parseUUIDParam(chi.URLParam(r, "id"))
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "id must be a uuid")
		return pgtype.UUID{}, pgtype.UUID{}, false
	}
	fingerprint, err := agentFingerprintFromRequest(r)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return pgtype.UUID{}, pgtype.UUID{}, false
	}
	if fingerprint == "" {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "agent certificate or agent_fingerprint is required")
		return pgtype.UUID{}, pgtype.UUID{}, false
	}
	agent, err := h.q.GetActiveEnrollmentByFingerprint(r.Context(), fingerprint)
	if errors.Is(err, pgx.ErrNoRows) {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "")
		return pgtype.UUID{}, pgtype.UUID{}, false
	}
	if err != nil {
		h.logger.Error("mount_agent_lookup_failed", "error", err, "allocation_id", uuidString(allocID))
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return pgtype.UUID{}, pgtype.UUID{}, false
	}
	// Resolve the stable lease identity from the allocation's bound agent. Require the
	// authenticated cert's user to own the allocation, and the allocation to be bound to
	// an agent (only bound disks are mountable). A revoked allocation is NOT rejected
	// here — it flows to the lease op, which returns ErrRevoked (mapped to 410 Gone).
	alloc, err := h.q.GetAllocation(r.Context(), allocID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeOAuthError(w, http.StatusNotFound, "not_found", "")
		return pgtype.UUID{}, pgtype.UUID{}, false
	}
	if err != nil {
		h.logger.Error("mount_allocation_lookup_failed", "error", err, "allocation_id", uuidString(allocID))
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return pgtype.UUID{}, pgtype.UUID{}, false
	}
	if alloc.UserID != agent.UserID || !alloc.AgentID.Valid {
		writeOAuthError(w, http.StatusForbidden, "access_denied", "")
		return pgtype.UUID{}, pgtype.UUID{}, false
	}
	// bound_agent_id is an FK into agent_enrollments, so the lease binds to the
	// authenticated enrollment; the takeover (below) is what bridges across the
	// per-turn enrollment churn.
	return allocID, agent.ID, true
}

func agentFingerprintFromRequest(r *http.Request) (string, error) {
	var body mountLeaseRequest
	if r.Body != nil {
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&body); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, http.ErrBodyNotAllowed) {
			return "", fmt.Errorf("invalid json body")
		}
	}
	bodyFP := strings.TrimSpace(body.AgentFingerprint)
	certFP := ""
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		certFP = strings.ToUpper(r.TLS.PeerCertificates[0].SerialNumber.Text(16))
	}
	if bodyFP != "" && certFP != "" && !strings.EqualFold(bodyFP, certFP) {
		return "", fmt.Errorf("agent_fingerprint does not match client certificate")
	}
	if certFP != "" {
		return certFP, nil
	}
	return bodyFP, nil
}

func (h *mountLeaseHandlers) handleOwnerUnmount(w http.ResponseWriter, r *http.Request) {
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
	if err := h.alloc.ForceReleaseMountLease(r.Context(), allocID, ident.UserID); err != nil {
		switch {
		case errors.Is(err, allocations.ErrNotFound), errors.Is(err, allocations.ErrWrongUser):
			writeOAuthError(w, http.StatusNotFound, "not_found", "")
		case errors.Is(err, allocations.ErrRevoked):
			writeOAuthError(w, http.StatusGone, "revoked", "")
		default:
			h.logger.Error("allocation_force_unmount_failed",
				"error", err,
				"user_id", uuidString(ident.UserID),
				"allocation_id", uuidString(allocID))
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		}
		return
	}
	// Fence the displaced session on orlop-server so its next manifest write
	// fails immediately instead of after the client's lease-refresh tick.
	// Best-effort: failures only widen the residual #175 window for this op.
	h.fenceAllocation(r, allocID, "force_unmount")
	w.WriteHeader(http.StatusNoContent)
}

func (h *mountLeaseHandlers) writeLeaseError(w http.ResponseWriter, r *http.Request, op string, allocID, agentID pgtype.UUID, err error) {
	switch {
	case errors.Is(err, allocations.ErrAlreadyMounted), errors.Is(err, allocations.ErrWrongAgent):
		writeOAuthError(w, http.StatusConflict, "already_mounted", "")
	case errors.Is(err, allocations.ErrRevoked):
		writeOAuthError(w, http.StatusGone, "revoked", "")
	case errors.Is(err, allocations.ErrLeaseLost):
		writeOAuthError(w, http.StatusGone, "lease_lost", "")
	case errors.Is(err, allocations.ErrNotFound):
		writeOAuthError(w, http.StatusNotFound, "not_found", "")
	default:
		h.logger.Error("mount_lease_failed", "op", op, "method", r.Method, "error", err, "allocation_id", uuidString(allocID), "agent_id", uuidString(agentID))
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
	}
}
