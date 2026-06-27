package main

import (
	"encoding/json"
	"net/http"
	"time"
)

// certRevocationItem is one entry in a deny-list push (issue #5).
type certRevocationItem struct {
	Serial    string    `json:"serial"`     // uppercase hex
	ExpiresAt time.Time `json:"expires_at"` // cert NotAfter; the prune horizon
}

type pushCertRevocationsRequest struct {
	Revocations []certRevocationItem `json:"revocations"`
}

// pushCertRevocations handles PUT /control/cert-revocations: orlop-control
// pushes the active serial deny-list. Semantics are MERGE (add) — a revoked
// cert is never un-revoked, it only ages out at its own expiry — so repeated
// pushes are idempotent and a restarted server is repopulated by the next
// reconcile. Gated to the control-plane identity by controlPlaneOnlyMiddleware.
func (s *serverState) pushCertRevocations(w http.ResponseWriter, r *http.Request) {
	if s.certRevocations == nil {
		writeJSONError(w, http.StatusNotImplemented, "revocation_disabled", "cert revocation registry is not configured")
		return
	}
	var req pushCertRevocationsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, errCodeInvalidRequest, "request body must be valid JSON")
		return
	}
	for _, rev := range req.Revocations {
		s.certRevocations.Add(rev.Serial, rev.ExpiresAt)
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": s.certRevocations.Count()})
}
