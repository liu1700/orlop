package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
)

type auditResp struct {
	Events     []map[string]any `json:"events"`
	NextCursor *string          `json:"next_cursor"`
}

func (s *serverState) getAudit(w http.ResponseWriter, r *http.Request) {
	limitStr := r.URL.Query().Get("limit")

	limit := 100
	if limitStr != "" {
		parsed, err := strconv.Atoi(limitStr)
		if err != nil || parsed < 0 {
			writeJSONError(w, http.StatusBadRequest, "invalid_request", "invalid limit")
			return
		}
		limit = parsed
	}
	if limit > 1000 {
		limit = 1000
	}

	events, err := s.audit.ReadEvents()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}

	// Scope the audit trail to the caller (audit P1-4). The JSONL is a single,
	// process-wide log across every tenant, so returning it whole let any agent
	// cert read every OTHER tenant's records (file paths, cert subjects encoding
	// user/tenant ids, op types, sizes). Filter to the caller's tenant — and, when
	// the cert is agent-scoped, to its own agent — before returning. A control-plane
	// cert (trusted ops) still sees the full log.
	if !s.callerIsControlPlane(r) {
		ident := identityFromRequest(r)
		scoped := ident.ScopedAgentID
		if scoped == "" && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			scoped = certScopedAgentID(r.TLS.PeerCertificates[0], s.trustDomain)
		}
		events = filterAuditForCaller(events, ident.TenantID, scoped)
	}

	if len(events) > limit {
		events = events[len(events)-limit:]
	}
	size := uint64(len(events))
	s.recordAudit(r, "http_get_audit", "/audit", &size, true)
	writeJSON(w, http.StatusOK, auditResp{Events: events})
}

// callerIsControlPlane reports whether the request's verified client cert carries
// the control-plane SAN (trusted ops), which may read the full cross-tenant audit.
func (s *serverState) callerIsControlPlane(r *http.Request) bool {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return false
	}
	return isControlPlaneCert(r.TLS.PeerCertificates[0], s.trustDomain)
}

// filterAuditForCaller keeps only records belonging to tenantID (and, when
// agentID is non-empty, that agent). Records missing the tenant attribution are
// dropped — an agent cert must never see un-attributed / server-level entries.
// Order is preserved; the result uses a fresh backing array.
func filterAuditForCaller(events []map[string]any, tenantID, agentID string) []map[string]any {
	out := make([]map[string]any, 0, len(events))
	for _, e := range events {
		if auditString(e["tenant_id"]) != tenantID {
			continue
		}
		if agentID != "" && auditString(e["agent_id"]) != agentID {
			continue
		}
		out = append(out, e)
	}
	return out
}

func auditString(v any) string {
	s, _ := v.(string)
	return s
}

func (s *serverState) recordAudit(r *http.Request, event, path string, size *uint64, allowed bool) {
	ident := identityFromRequest(r)
	rec := AuditRecord{
		Event:       event,
		Path:        path,
		Size:        size,
		AgentID:     ident.AgentID,
		TenantID:    ident.TenantID,
		CertSerial:  ident.CertSerial,
		CertSubject: ident.CertSubject,
		UID:         uintPtr(s.uid),
		GID:         uintPtr(s.gid),
		Command:     "orlop-server",
		Allowed:     allowed,
	}
	s.audit.Record(rec)
}

func (s *serverState) recordAuthFailure(r *http.Request, ident Identity) {
	path := r.URL.Path
	if r.URL.RawQuery != "" {
		path += "?" + r.URL.RawQuery
	}
	rec := AuditRecord{
		Event:       "http_auth",
		Path:        path,
		AgentID:     ident.AgentID,
		TenantID:    ident.TenantID,
		CertSerial:  ident.CertSerial,
		CertSubject: ident.CertSubject,
		UID:         uintPtr(s.uid),
		GID:         uintPtr(s.gid),
		Command:     "orlop-server",
		Allowed:     false,
	}
	s.audit.Record(rec)
}

func identityFromRequest(r *http.Request) Identity {
	if id, ok := IdentityFromContext(r.Context()); ok {
		return id
	}
	return Identity{}
}

func uintPtr(v uint32) *uint32 { return &v }

// encodeJSON writes v with a trailing newline to w. Failures are silent — the
// HTTP status has already been written.
func encodeJSON(w io.Writer, v any) {
	enc := json.NewEncoder(w)
	_ = enc.Encode(v)
}
