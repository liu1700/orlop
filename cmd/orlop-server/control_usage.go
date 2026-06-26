package main

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/liu1700/orlop/cmd/orlop-server/internal/usage"
)

type tenantUsageResponse struct {
	TenantID  string `json:"tenant_id"`
	UsedBytes int64  `json:"used_bytes"`
	SizeBytes int64  `json:"size_bytes"`
}

// tenantUsage returns on-disk usage for a tenant. Control-plane only.
//
// Used bytes are computed by walking the tenant's storeRoot. SizeBytes is
// the registered quota (from quota.Manager.Lookup). When the tenant has no
// registered quota record (static tenant), size_bytes is reported as 0.
func (s *serverState) tenantUsage(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if !tenantIDRe.MatchString(id) {
		writeJSONError(w, http.StatusBadRequest, "invalid_tenant_id", "tenant_id must match ^[A-Za-z0-9_][A-Za-z0-9_-]{0,62}$")
		return
	}
	ts, ok := s.tenant(id)
	if !ok {
		writeJSONError(w, http.StatusNotFound, "tenant_not_found", "")
		return
	}
	used, err := usage.DirSize(ts.storeRoot)
	if err != nil {
		s.logger.Error("tenant_usage_walk_failed", "error", err, "tenant_id", id)
		writeJSONError(w, http.StatusInternalServerError, "usage_failed", err.Error())
		return
	}
	var size int64
	if _, sz, ok := s.quota.Lookup(id); ok {
		size = sz
	}
	writeJSON(w, http.StatusOK, tenantUsageResponse{
		TenantID:  id,
		UsedBytes: used,
		SizeBytes: size,
	})
}
