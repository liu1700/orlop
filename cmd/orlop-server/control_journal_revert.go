package main

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// controlJournalRevertRequest is the body of POST /control/tenants/{id}/journal/revert.
//
// Singular path/seq: per Phase 3a spec §3.1, every revert is one (path, point).
// Orlop-control is the only caller and constructs the body from the
// browser-side click.
//
// AgentID is required and recorded on the inverse journal row. orlop-control
// passes either the authenticated user's tenant-scoped agent id
// ("user:<uuid>") or a synthetic label like "anonymous:<short-sid>" for the
// anonymous sandbox surface — the data plane will not invent attribution.
type controlJournalRevertRequest struct {
	AllocationID string `json:"allocation_id"`
	// SessionID + Seq together pin the exact row the user clicked. Seq is
	// per-session, so a take-over can leave two rows in the same allocation
	// sharing a seq; without SessionID the revert can spuriously target the
	// wrong row.
	SessionID string `json:"session_id,omitempty"`
	Path      string `json:"path"`
	Seq       uint64 `json:"seq"`
	Force     bool   `json:"force,omitempty"`
	AgentID   string `json:"agent_id"`
}

// controlJournalRevertResponse mirrors the wire shape of the public
// /api/v1/journal/revert endpoint orlop-control fronts (spec §3.1).
type controlJournalRevertResponse struct {
	Ok       bool                  `json:"ok"`
	Conflict *controlRevertConflict `json:"conflict,omitempty"`
}

type controlRevertConflict struct {
	Reason string `json:"reason"`
}

// tenantJournalRevert handles POST /control/tenants/{id}/journal/revert.
// Protected by controlPlaneOnlyMiddleware — orlop-control is the only caller;
// allocation ownership and request-side auth happen there.
//
// Behavior:
//   - Delegates to journal.RevertPaths with a 1-element slice. The seq pin
//     (spec §10.2: "the row you clicked must still be the latest") lives
//     inside RevertPaths now; force=true bypasses it per spec §10.1.
//   - Always 200; the body's `ok` bit and `conflict` field distinguish
//     success from per-path conflict. Real I/O failures still return 5xx.
func (s *serverState) tenantJournalRevert(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if !tenantIDRe.MatchString(id) {
		writeJSONError(w, http.StatusBadRequest, "invalid_tenant_id",
			"tenant_id must match ^[A-Za-z0-9_][A-Za-z0-9_-]{0,62}$")
		return
	}
	ts, ok := s.tenant(id)
	if !ok {
		writeJSONError(w, http.StatusNotFound, "tenant_not_found", "")
		return
	}

	var req controlJournalRevertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}
	if req.AllocationID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing_allocation_id", "")
		return
	}
	if req.Path == "" {
		writeJSONError(w, http.StatusBadRequest, "missing_path", "")
		return
	}
	if req.AgentID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing_agent_id",
			"agent_id is required so the inverse row is attributable")
		return
	}

	revertSessionID := s.writerSessionForRevert(req.AllocationID)

	reverted, conflicts, err := ts.journal.RevertPaths(
		req.AllocationID, []string{req.Path},
		[]string{req.SessionID}, []uint64{req.Seq},
		ts.manifests,
		revertSessionID, req.AgentID, req.Force,
	)
	if err != nil {
		s.logger.Error("tenant_journal_revert_failed",
			"error", err, "tenant_id", id, "allocation_id", req.AllocationID, "path", req.Path)
		writeJSONError(w, http.StatusInternalServerError, "revert_failed", "")
		return
	}
	if len(conflicts) > 0 {
		writeJSON(w, http.StatusOK, controlJournalRevertResponse{
			Ok:       false,
			Conflict: &controlRevertConflict{Reason: conflicts[0].Reason},
		})
		return
	}
	if len(reverted) == 0 {
		// RevertPaths returned neither a conflict nor a reverted path —
		// shouldn't happen with a non-empty input, but fail loud rather
		// than silently lie via ok:true.
		writeJSON(w, http.StatusOK, controlJournalRevertResponse{
			Ok:       false,
			Conflict: &controlRevertConflict{Reason: ReasonRevertBlocked},
		})
		return
	}
	writeJSON(w, http.StatusOK, controlJournalRevertResponse{Ok: true})
}
