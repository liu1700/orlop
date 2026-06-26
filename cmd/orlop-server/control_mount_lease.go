package main

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

// clearActiveMountLease handles
// DELETE /control/tenants/{id}/allocations/{alloc}/mount-lease.
//
// orlop-control calls this on Revoke or owner-driven Force-Unmount (the
// Take-over path also goes through this endpoint via Force-Unmount). It moves
// the currently-active session into the per-allocation fenced set so the
// displaced client's next manifest_put / _delete / _rename is rejected
// immediately (issue #175). Idempotent.
//
// A matching PUT is intentionally absent: orlop-server installs the active
// session lazily on the first sessioned write that arrives — that write
// carries the lease_id from orlop-server's own lease_grant, which orlop-control
// does not see and therefore cannot push.
func (s *serverState) clearActiveMountLease(w http.ResponseWriter, r *http.Request) {
	tenantID := chi.URLParam(r, "id")
	if !tenantIDRe.MatchString(tenantID) {
		writeJSONError(w, http.StatusBadRequest, "invalid_tenant_id", "")
		return
	}
	if _, ok := s.tenant(tenantID); !ok {
		writeJSONError(w, http.StatusNotFound, "tenant_not_found", "")
		return
	}
	allocationID := chi.URLParam(r, "alloc")
	if allocationID == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_allocation_id", "")
		return
	}
	s.mountLeases.Clear(allocationID)
	w.WriteHeader(http.StatusNoContent)
}

// writerSessionForRevert returns the session_id tag a revert's inverse
// write should journal under for the given allocation. Prefers the active
// mount lease so the sidebar groups the inverse alongside the user's other
// writes; falls back to sessionRevertPrefix+allocationID when no client is
// mounted (the row still surfaces — the query path does not filter by
// session prefix).
func (s *serverState) writerSessionForRevert(allocationID string) string {
	if leaseHex := s.mountLeases.Get(allocationID); leaseHex != "" {
		return sessionMountPrefix + leaseHex
	}
	return sessionRevertPrefix + allocationID
}
