package main

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
)

type tenantUsageResponse struct {
	TenantID  string `json:"tenant_id"`
	UsedBytes int64  `json:"used_bytes"`
	SizeBytes int64  `json:"size_bytes"`
}

// tenantUsage returns on-disk usage for a tenant. Control-plane only.
//
// Used bytes are the sum of the tenant's stored chunk sizes, read from the local
// metadata SQLite (TenantDB.UsedBytes) — an indexed scalar aggregate on the fast
// MetadataRoot disk, NOT an O(files) filepath.WalkDir over the networked JuiceFS
// chunk store. The walk could consume the caller's whole 10s budget under a
// concurrent mount/quota burst that starves the filesystem and time the request
// out to a 502 (PLO-292); the metadata sum stays bounded regardless of file
// count or filesystem contention, and equals the walk byte for byte (chunks are
// stored raw). SizeBytes is the registered quota (quota.Manager.Lookup); 0 when
// the tenant has no quota record (static tenant).
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

	started := time.Now()
	used, chunkCount, err := ts.db.UsedBytes(r.Context())
	s.metrics.observeDuration("usage", started)
	if err != nil {
		s.logger.Error("tenant_usage_failed",
			"tenant_id", id,
			"duration_ms", time.Since(started).Milliseconds(),
			"error", err)
		writeJSONError(w, http.StatusInternalServerError, "usage_failed", err.Error())
		return
	}
	// Seam telemetry (PLO-292): duration + a bounded work indicator (chunk_count)
	// + tenant identity, carrying no paths or user content, so a future slow-usage
	// investigation reads server-side start/end evidence instead of only the
	// caller's timeout.
	s.logger.Info("tenant_usage",
		"tenant_id", id,
		"used_bytes", used,
		"chunk_count", chunkCount,
		"duration_ms", time.Since(started).Milliseconds())

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
