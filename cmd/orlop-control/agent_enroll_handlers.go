package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"golang.org/x/time/rate"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/allocations"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/ca"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/db"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/db/sqlcdb"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/devauth"
)

const (
	agentCertTTL       = time.Hour
	enrollRetryAfter   = "60"
	serverStatusActive = "active"
)

type agentEnrollHandlers struct {
	logger      *slog.Logger
	q           db.Store
	devAuth     *devauth.Service
	ca          *ca.CA
	limit       *agentEnrollLimiter
	allocations *allocations.Service
	serverAPI   allocations.ServerAdmin
}

func newAgentEnrollHandlers(
	logger *slog.Logger,
	q db.Store,
	devAuth *devauth.Service,
	agentCA *ca.CA,
	limit *agentEnrollLimiter,
	allocSvc *allocations.Service,
	serverAPI allocations.ServerAdmin,
) *agentEnrollHandlers {
	if limit == nil {
		limit = newAgentEnrollLimiter(60, time.Hour)
	}
	return &agentEnrollHandlers{
		logger:      logger,
		q:           q,
		devAuth:     devAuth,
		ca:          agentCA,
		limit:       limit,
		allocations: allocSvc,
		serverAPI:   serverAPI,
	}
}

type agentEnrollLimiter struct {
	mu      sync.Mutex
	limit   rate.Limit
	burst   int
	buckets map[string]*rate.Limiter
}

func newAgentEnrollLimiter(n int, window time.Duration) *agentEnrollLimiter {
	return &agentEnrollLimiter{
		limit:   rate.Every(window / time.Duration(n)),
		burst:   n,
		buckets: map[string]*rate.Limiter{},
	}
}

func (l *agentEnrollLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		b = rate.NewLimiter(l.limit, l.burst)
		l.buckets[key] = b
	}
	return b.Allow()
}

func mountAgentEnroll(r chi.Router, bearer func(http.Handler) http.Handler, h *agentEnrollHandlers) {
	r.With(bearer).Post("/agent/enroll", h.handleEnroll)
}

func (h *agentEnrollHandlers) handleEnroll(w http.ResponseWriter, r *http.Request) {
	ident, ok := IdentityFromRequest(r)
	if !ok {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "")
		return
	}
	if !h.limit.Allow(r.Header.Get("Authorization")) {
		writeOAuthError(w, http.StatusTooManyRequests, "rate_limited", "")
		return
	}

	tenant, err := h.q.GetTenant(r.Context(), ident.TenantID)
	if errors.Is(err, db.ErrNotFound) {
		writeOAuthError(w, http.StatusForbidden, "access_denied", "tenant_not_found")
		return
	}
	if err != nil {
		h.logger.Error("agent_enroll_tenant_lookup_failed", "error", err, "tenant_id", ident.TenantID)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	if tenant.SuspendedAt.Valid {
		writeOAuthError(w, http.StatusForbidden, "access_denied", "tenant_suspended")
		return
	}

	userID := uuidString(ident.UserID)

	// Pull allocation up so we have size_bytes available for placement.
	var allocation *sqlcdb.DiskAllocation
	if ident.AllocationID.Valid {
		alloc, err := h.q.GetAllocation(r.Context(), ident.AllocationID)
		if err != nil {
			h.logger.Error("agent_enroll_allocation_lookup_failed", "error", err, "tenant_id", ident.TenantID, "user_id", userID, "allocation_id", uuidString(ident.AllocationID))
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
			return
		}
		if alloc.UserID != ident.UserID || alloc.RevokedAt.Valid {
			h.logger.Error("agent_enroll_allocation_invalid", "tenant_id", ident.TenantID, "user_id", userID, "allocation_id", uuidString(ident.AllocationID))
			desc := "allocation_not_found"
			if alloc.RevokedAt.Valid {
				desc = "allocation_revoked"
			}
			writeOAuthError(w, http.StatusForbidden, "access_denied", desc)
			return
		}
		allocation = &alloc
	}

	// Resolve (or place) the server assigned to this tenant.
	var serverAddr string
	{
		vm, vmErr := h.q.GetServerVMByTenant(r.Context(), ident.TenantID)
		if vmErr == nil {
			if vm.Status != serverStatusActive {
				writeRetryableEnrollError(w, "server_vm_unavailable")
				return
			}
			serverAddr = vm.DataAddr
		} else if !errors.Is(vmErr, db.ErrNotFound) {
			h.logger.Error("agent_enroll_server_vm_lookup_failed", "error", vmErr, "tenant_id", ident.TenantID)
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
			return
		} else if allocation == nil {
			// No existing placement and no allocation — cannot place, keep prior 503 behaviour.
			writeRetryableEnrollError(w, "server_vm_unavailable")
			return
		} else {
			// The tenant nests under its account's owner tenant (u_<owner>), and the
			// shared account quota — allocation.SizeBytes carries the account budget —
			// is applied to the owner dir, capping all the account's agents together.
			ownerTenant := tenantIDForOwner(uuidString(allocation.UserID))
			placed, placementErr := h.allocations.Reserve(r.Context(), h.serverAPI, ident.TenantID, ownerTenant, tenant.Name, allocation.SizeBytes)
			if errors.Is(placementErr, allocations.ErrNoCapacity) {
				h.logger.Info("agent_enroll_no_capacity", "tenant_id", ident.TenantID)
				writeRetryableEnrollError(w, "server_vm_unavailable")
				return
			}
			if placementErr != nil {
				h.logger.Error("agent_enroll_placement_failed", "error", placementErr, "tenant_id", ident.TenantID)
				writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
				return
			}
			serverAddr = placed
		}
	}
	// Lazy-bootstrap the tenant intermediate if a per-user tenant lands here
	// for the first time. Static-config tenants get their intermediates from
	// the deploy bootstrap; dynamic per-user tenants minted by hostedTenantID
	// don't, so MintAgentCert would otherwise fail with "unknown tenant".
	if !h.ca.HasTenant(ident.TenantID) {
		if err := h.ca.BootstrapTenant(r.Context(), ident.TenantID); err != nil {
			// Operator allowlist gate (issue #8): an unrecognized tenant id is a
			// client-side authorization failure, not a transient server fault —
			// reject with 403 rather than the retryable 503 used for real CA
			// outages, so a disallowed tenant cannot self-onboard by retrying.
			if errors.Is(err, ca.ErrTenantNotAllowed) {
				h.logger.Warn("agent_enroll_tenant_not_allowed", "tenant_id", ident.TenantID)
				writeOAuthError(w, http.StatusForbidden, "access_denied", "tenant_not_allowed")
				return
			}
			h.logger.Error("agent_ca_bootstrap_failed", "error", err, "tenant_id", ident.TenantID)
			writeRetryableEnrollError(w, "tenant_ca_unavailable")
			return
		}
		h.logger.Info("agent_ca_bootstrapped", "tenant_id", ident.TenantID)
	}
	// Single isolation policy (the agent-isolation and cert-bootstrap design):
	// every cert is bound to a specific agent via a SPIFFE /agent/<id> SAN. An
	// enroll without a provisioned agent disk gets NO cert — the tenant-wide
	// fallback is removed. orlop always provisions an agent-keyed allocation
	// (control-plane → /v1/entities) for registered AND anonymous users alike, so
	// this never trips in normal operation; it is the hard guarantee behind the
	// single policy.
	if allocation == nil || !allocation.AgentID.Valid || allocation.AgentID.String == "" {
		h.logger.Info("agent_enroll_no_agent_scope", "tenant_id", ident.TenantID, "user_id", userID)
		writeOAuthError(w, http.StatusForbidden, "access_denied", "agent_scope_required")
		return
	}
	agentID := allocation.AgentID.String
	certPEM, keyPEM, chainPEM, serial, err := h.ca.MintAgentCert(ident.TenantID, userID, agentID, agentCertTTL)
	if err != nil {
		h.logger.Error("agent_cert_mint_failed", "error", err, "tenant_id", ident.TenantID, "user_id", userID)
		writeRetryableEnrollError(w, "tenant_ca_unavailable")
		return
	}
	leaf, err := ca.DecodeCertPEM(certPEM)
	if err != nil {
		h.logger.Error("agent_cert_parse_failed", "error", err, "tenant_id", ident.TenantID, "user_id", userID)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	// Single-use per-pod enroll tokens (issue #6): spend the token now that the
	// cert is minted. This is the serialization point — it runs only after every
	// retryable placement/bootstrap/mint step above has succeeded, so a transient
	// 503 earlier leaves the token live for the sidecar's retry, while a replay
	// or the loser of a concurrent race finds it already consumed and is rejected
	// without a second cert leaving the building. Device-session enrolls (the CLI
	// path) are multi-use and skip this entirely.
	if ident.Purpose == devauth.PurposeAgentEnroll {
		consumed, err := h.devAuth.ConsumeAgentEnrollToken(r.Context(), r.Header.Get("Authorization"))
		if err != nil {
			h.logger.Error("agent_enroll_token_consume_failed", "error", err, "tenant_id", ident.TenantID, "user_id", userID)
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
			return
		}
		if !consumed {
			h.logger.Warn("agent_enroll_token_replay", "tenant_id", ident.TenantID, "user_id", userID)
			writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "token_consumed")
			return
		}
	}
	if _, err := h.q.CreateAgentEnrollment(r.Context(), sqlcdb.CreateAgentEnrollmentParams{
		UserID:       ident.UserID,
		CertSerial:   serial,
		CertNotAfter: pgtype.Timestamptz{Time: leaf.NotAfter, Valid: true},
	}); err != nil {
		h.logger.Error("agent_enrollment_record_failed", "error", err, "tenant_id", ident.TenantID, "user_id", userID)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	resp := map[string]any{
		"client_cert_pem": string(certPEM),
		"client_key_pem":  string(keyPEM),
		"ca_chain_pem":    string(chainPEM),
		"server_addr":     serverAddr,
		"expires_at":      leaf.NotAfter.UTC().Format(time.RFC3339),
	}
	if allocation != nil {
		resp["allocation_id"] = uuidString(allocation.ID)
		resp["size_bytes"] = allocation.SizeBytes
	}
	writeJSON(w, http.StatusOK, resp)
}

func writeRetryableEnrollError(w http.ResponseWriter, code string) {
	w.Header().Set("Retry-After", enrollRetryAfter)
	writeOAuthError(w, http.StatusServiceUnavailable, code, "")
}

func uuidString(u pgtype.UUID) string {
	if !u.Valid {
		return ""
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", u.Bytes[0:4], u.Bytes[4:6], u.Bytes[6:8], u.Bytes[8:10], u.Bytes[10:16])
}
