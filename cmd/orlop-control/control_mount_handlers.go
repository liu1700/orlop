package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/allocations"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/devauth"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage/postgres"
)

// mountLeaseStore is the slice of the storage layer the mount-lease routes
// read: the agent cert→enrollment lookup plus the allocation/user pair the
// ownership check and fence path need. *postgres.Store satisfies it.
type mountLeaseStore interface {
	GetActiveEnrollmentByFingerprint(ctx context.Context, fingerprint string) (storage.AgentEnrollment, error)
	GetAllocation(ctx context.Context, id uuid.UUID) (storage.Allocation, error)
	GetUser(ctx context.Context, id uuid.UUID) (storage.User, error)
}

type mountLeaseHandlers struct {
	logger  *slog.Logger
	alloc   *allocations.Service
	store   mountLeaseStore
	devAuth *devauth.Service
	fencer  mountLeaseFencer
}

func newMountLeaseHandlers(logger *slog.Logger, alloc *allocations.Service, store mountLeaseStore, dev *devauth.Service, fencer mountLeaseFencer) *mountLeaseHandlers {
	return &mountLeaseHandlers{logger: logger, alloc: alloc, store: store, devAuth: dev, fencer: fencer}
}

var _ mountLeaseStore = (*postgres.Store)(nil)

func mountLeaseRoutes(r chi.Router, h *mountLeaseHandlers) {
	mountBoth(func(prefix string) {
		r.Post(prefix+"/allocations/{id}/mount", h.handleAcquireMount)
		r.Post(prefix+"/allocations/{id}/mount/refresh", h.handleRefreshMount)
		r.Delete(prefix+"/allocations/{id}/mount", h.handleReleaseMount)
		r.Post(prefix+"/allocations/{id}/unmount", h.handleOwnerUnmount)
	})
}

type mountLeaseRequest struct {
	AgentFingerprint string `json:"agent_fingerprint"`
	// Force opts in to taking over a lease that is still live for a different
	// enrollment (issue #93): the caller asserts the incumbent's host is gone
	// (crash recovery, dashboard take-over). Without it such an acquire is
	// refused with 409 lease_live. Ignored by refresh/release.
	Force bool `json:"force"`
}

func (h *mountLeaseHandlers) handleAcquireMount(w http.ResponseWriter, r *http.Request) {
	allocID, agentID, force, ok := h.resolveMountRequest(w, r)
	if !ok {
		return
	}
	a, err := h.alloc.AcquireMountLease(r.Context(), allocID, agentID, allocations.LeaseTTL, force)
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
	fenceAllocationBestEffort(r.Context(), h.logger, h.store, h.fencer, allocID, "acquire")
	writeJSON(w, http.StatusOK, map[string]any{
		"lease_id":   uuidString(a.ID),
		"expires_at": a.LeaseExpiresAt.UTC().Format(time.RFC3339),
	})
}

func (h *mountLeaseHandlers) handleRefreshMount(w http.ResponseWriter, r *http.Request) {
	allocID, agentID, _, ok := h.resolveMountRequest(w, r)
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
	allocID, agentID, _, ok := h.resolveMountRequest(w, r)
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
	fenceAllocationBestEffort(r.Context(), h.logger, h.store, h.fencer, allocID, "release")
	w.WriteHeader(http.StatusNoContent)
}

// resolveMountRequest authenticates the agent cert and returns the allocation id, the
// authenticated enrollment id (the mount lease's bound_agent_id, an FK into
// agent_enrollments), and the request's force flag. It ALSO checks that the cert's user
// owns the allocation and that the allocation is bound to an agent — that ownership check
// is what makes a lease takeover safe (AcquireMountLease): an allocation belongs to a
// single orlop agent, so any authorized enrollment mounting it IS that agent, and a
// one-shot pod re-mounting with a fresh cert each turn takes over the prior pod's lease
// once it is released or expired (or, with force, even while live — issue #93).
// Cross-tenant access is denied here; cross-agent access is enforced at the data plane by
// the agent-scoped cert.
func (h *mountLeaseHandlers) resolveMountRequest(w http.ResponseWriter, r *http.Request) (pgtype.UUID, pgtype.UUID, bool, bool) {
	allocID, err := parseUUIDParam(chi.URLParam(r, "id"))
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "id must be a uuid")
		return pgtype.UUID{}, pgtype.UUID{}, false, false
	}
	fingerprint, force, err := agentFingerprintFromRequest(r)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return pgtype.UUID{}, pgtype.UUID{}, false, false
	}
	if fingerprint == "" {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "agent certificate or agent_fingerprint is required")
		return pgtype.UUID{}, pgtype.UUID{}, false, false
	}
	agent, err := h.store.GetActiveEnrollmentByFingerprint(r.Context(), fingerprint)
	if errors.Is(err, storage.ErrNotFound) {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "")
		return pgtype.UUID{}, pgtype.UUID{}, false, false
	}
	if err != nil {
		h.logger.Error("mount_agent_lookup_failed", "error", err, "allocation_id", uuidString(allocID))
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return pgtype.UUID{}, pgtype.UUID{}, false, false
	}
	// Resolve the stable lease identity from the allocation's bound agent. Require the
	// authenticated cert's user to own the allocation, and the allocation to be bound to
	// an agent (only bound disks are mountable). A revoked allocation is NOT rejected
	// here — it flows to the lease op, which returns ErrRevoked (mapped to 410 Gone).
	alloc, err := h.store.GetAllocation(r.Context(), toUUID(allocID))
	if errors.Is(err, storage.ErrNotFound) {
		writeOAuthError(w, http.StatusNotFound, "not_found", "")
		return pgtype.UUID{}, pgtype.UUID{}, false, false
	}
	if err != nil {
		h.logger.Error("mount_allocation_lookup_failed", "error", err, "allocation_id", uuidString(allocID))
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return pgtype.UUID{}, pgtype.UUID{}, false, false
	}
	if alloc.UserID != agent.UserID || alloc.AgentID == "" {
		writeOAuthError(w, http.StatusForbidden, "access_denied", "")
		return pgtype.UUID{}, pgtype.UUID{}, false, false
	}
	// bound_agent_id is an FK into agent_enrollments, so the lease binds to the
	// authenticated enrollment; the takeover (below) is what bridges across the
	// per-turn enrollment churn.
	return allocID, fromUUID(agent.ID), force, true
}

func agentFingerprintFromRequest(r *http.Request) (string, bool, error) {
	var body mountLeaseRequest
	if r.Body != nil {
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&body); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, http.ErrBodyNotAllowed) {
			return "", false, fmt.Errorf("invalid json body")
		}
	}
	bodyFP := strings.TrimSpace(body.AgentFingerprint)
	certFP := ""
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		certFP = strings.ToUpper(r.TLS.PeerCertificates[0].SerialNumber.Text(16))
	}
	if bodyFP != "" && certFP != "" && !strings.EqualFold(bodyFP, certFP) {
		return "", false, fmt.Errorf("agent_fingerprint does not match client certificate")
	}
	if certFP != "" {
		return certFP, body.Force, nil
	}
	return bodyFP, body.Force, nil
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
		writeAllocOwnershipError(w, err, h.logger, "allocation_force_unmount_failed",
			"user_id", uuidString(ident.UserID),
			"allocation_id", uuidString(allocID))
		return
	}
	// Fence the displaced session on orlop-server so its next manifest write
	// fails immediately instead of after the client's lease-refresh tick.
	// Best-effort: failures only widen the residual #175 window for this op.
	fenceAllocationBestEffort(r.Context(), h.logger, h.store, h.fencer, allocID, "force_unmount")
	w.WriteHeader(http.StatusNoContent)
}

func (h *mountLeaseHandlers) writeLeaseError(w http.ResponseWriter, r *http.Request, op string, allocID, agentID pgtype.UUID, err error) {
	var live *allocations.LeaseLiveError
	switch {
	case errors.As(err, &live):
		// A refused takeover of a live lease (issue #93). Distinct from
		// already_mounted and carrying the incumbent's binding details, so the
		// caller can judge whether the incumbent is really gone before
		// retrying with {"force": true}.
		h.logger.Warn("mount_lease_takeover_refused",
			"allocation_id", uuidString(allocID),
			"agent_id", uuidString(agentID),
			"incumbent_lease_expires_at", live.LeaseExpiresAt.UTC().Format(time.RFC3339))
		body := map[string]any{
			"error":            "lease_live",
			"lease_expires_at": live.LeaseExpiresAt.UTC().Format(time.RFC3339),
		}
		if live.BoundAt != nil {
			body["bound_at"] = live.BoundAt.UTC().Format(time.RFC3339)
		}
		writeJSON(w, http.StatusConflict, body)
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
