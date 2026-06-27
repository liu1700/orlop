package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"regexp"

	"github.com/go-chi/chi/v5"
	"github.com/liu1700/orlop/cmd/orlop-server/internal/quota"
)

// Accepts the IDs orlop-control mints (e.g. "user_eP4M9vrfF4Q2qVDtN1349g")
// while still rejecting path-traversal / special-char input. First char is
// alnum-or-underscore; remaining chars add hyphen.
var tenantIDRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_-]{0,62}$`)

const (
	errCodeRegistrationDisabled = "registration_disabled"
	errCodeInvalidRequest       = "invalid_request"
	errCodeSizeMismatch         = "size_mismatch"
	errCodeFSQuotaUnavailable   = "fs_quota_unavailable"
)

type registerTenantRequest struct {
	TenantID string `json:"tenant_id"`
	// OwnerTenantID is the account tenant (u_<owner>) this tenant belongs to. The
	// tenant's dir nests UNDER it (/jfs/tenants/u_<owner>/<tenant_id>) and the JuiceFS
	// quota lives on the owner dir, so all of an account's agents share one hard cap.
	// Empty ⇒ the tenant IS its own account (its dir is /jfs/tenants/<tenant_id> and
	// the quota is on itself) — the user/OAuth tenant and back-compat callers.
	OwnerTenantID string `json:"owner_tenant_id"`
	Name          string `json:"name"`
	// SizeBytes is the ACCOUNT disk budget (included + purchased), applied to the owner
	// dir — NOT a per-agent cap. Re-asserted on every placement under the account.
	SizeBytes int64 `json:"size_bytes"`
}

type registerTenantResponse struct {
	TenantID  string `json:"tenant_id"`
	ProjectID uint32 `json:"project_id"`
	SizeBytes int64  `json:"size_bytes"`
}

func (s *serverState) registerTenant(w http.ResponseWriter, r *http.Request) {
	if s.adminCfg.TenantsRoot == "" {
		writeJSONError(w, http.StatusNotImplemented, errCodeRegistrationDisabled, "dynamic tenant registration is not configured")
		return
	}

	var req registerTenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, errCodeInvalidRequest, "request body must be valid JSON")
		return
	}

	if !tenantIDRe.MatchString(req.TenantID) {
		writeJSONError(w, http.StatusBadRequest, "invalid_tenant_id", "tenant_id must match ^[A-Za-z0-9_][A-Za-z0-9_-]{0,62}$")
		return
	}
	// Default the owner to the tenant itself (a tenant that is its own account).
	ownerTenant := req.OwnerTenantID
	if ownerTenant == "" {
		ownerTenant = req.TenantID
	}
	if !tenantIDRe.MatchString(ownerTenant) {
		writeJSONError(w, http.StatusBadRequest, "invalid_owner_tenant_id", "owner_tenant_id must match the tenant_id pattern")
		return
	}
	if req.Name == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_name", "name must not be empty")
		return
	}
	if req.SizeBytes <= 0 {
		writeJSONError(w, http.StatusBadRequest, "invalid_size", "size_bytes must be > 0")
		return
	}

	// Hold the write lock across the entire handler — existence check through the
	// tenants-map insert and appendRegisteredTenant — to prevent concurrent
	// same-tenant registrations from opening duplicate handles or racing the JSON file.
	s.mu.Lock()
	defer s.mu.Unlock()

	// The account quota lives on the owner dir; the tenant nests under it (unless it IS
	// the account, in which case dir == owner dir).
	ownerDir := filepath.Join(s.adminCfg.TenantsRoot, ownerTenant)
	tenantDir := ownerDir
	if req.TenantID != ownerTenant {
		tenantDir = filepath.Join(ownerDir, req.TenantID)
	}
	storeRoot := filepath.Join(tenantDir, "store")

	// Metadata (routes.db + leases.db) lives under MetadataRoot, mirroring the
	// tenant layout — so the latency-critical SQLite can sit on a fast local disk
	// while the chunk store under storeRoot stays on TenantsRoot (JuiceFS).
	// MetadataRoot defaults to TenantsRoot (single-disk), so this is the old path
	// when unsplit. Default at the use site too: a directly-built adminConfig (tests)
	// may leave it empty, and filepath.Join("", x) would yield a relative path.
	metaRoot := s.adminCfg.MetadataRoot
	if metaRoot == "" {
		metaRoot = s.adminCfg.TenantsRoot
	}
	metaTenantDir := filepath.Join(metaRoot, ownerTenant)
	if req.TenantID != ownerTenant {
		metaTenantDir = filepath.Join(metaTenantDir, req.TenantID)
	}

	// ensureAccountQuota (re)asserts the JuiceFS hard cap on the owner dir to the account
	// budget — idempotent, and resizes in place if the budget changed. The dir must exist
	// first, so callers MkdirAll before invoking it.
	//
	// When async application is enabled it hands the (re)assertion to the background
	// applier and returns immediately so the agent disk mount is not blocked by a slow
	// first `juicefs quota set` (see accountQuotaApplier). The returned projID is the
	// last-applied one if any (0 until the first apply lands); callers — and ultimately
	// orlop-control — only use it for the response body, never for placement.
	ensureAccountQuota := func() (uint32, bool) {
		if s.quotaApply != nil {
			s.quotaApply.Enqueue(ownerTenant, ownerDir, req.SizeBytes)
			projID, _, _ := s.quota.Lookup(ownerTenant)
			return projID, true
		}
		projID, err := s.quota.EnsureQuota(r.Context(), ownerTenant, ownerDir, req.SizeBytes)
		if err == nil {
			return projID, true
		}
		var notQuota quota.ErrNotProjectQuotaFS
		if errors.As(err, &notQuota) {
			s.logger.Error("account quota unavailable", "owner_tenant", ownerTenant, "stderr", notQuota.Stderr)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			encodeJSON(w, map[string]any{
				"error": map[string]any{"code": errCodeFSQuotaUnavailable, "message": notQuota.Stderr},
			})
			return 0, false
		}
		writeJSONError(w, http.StatusInternalServerError, "quota_failed", err.Error())
		return 0, false
	}

	if existing, ok := s.tenants[req.TenantID]; ok {
		// Idempotent placement: the tenant is already live. Re-assert the account quota
		// (the budget may have grown since) and return.
		projID, okQ := ensureAccountQuota()
		if !okQ {
			return
		}
		writeJSON(w, http.StatusOK, registerTenantResponse{
			TenantID:  existing.id,
			ProjectID: projID,
			SizeBytes: req.SizeBytes,
		})
		return
	}

	if err := os.MkdirAll(storeRoot, 0o750); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "mkdir_failed", err.Error())
		return
	}
	if err := os.MkdirAll(metaTenantDir, 0o750); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "mkdir_failed", err.Error())
		return
	}

	projID, okQ := ensureAccountQuota()
	if !okQ {
		return
	}

	routesDB := filepath.Join(metaTenantDir, "routes.db")
	ts, err := openTenantState(req.TenantID, req.Name, storeRoot, routesDB, s.adminCfg.LeaseCfg, s.conns, s.audit, s.metrics)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "open_tenant_failed", err.Error())
		return
	}
	// Assign directly — we already hold s.mu.Lock().
	s.tenants[ts.id] = ts

	rt := registeredTenant{
		ID:        req.TenantID,
		Name:      req.Name,
		SizeBytes: req.SizeBytes,
		ProjectID: projID,
		StoreRoot: storeRoot,
		RoutesDB:  routesDB,
	}
	if err := appendRegisteredTenant(s.adminCfg.RegisteredTenantsPath, rt); err != nil {
		s.logger.Error("persist registered tenant failed", "tenant_id", req.TenantID, "error", err)
		// Non-fatal: tenant is live in memory; next restart will need quota reload from quota_state.json.
	}

	writeJSON(w, http.StatusOK, registerTenantResponse{
		TenantID:  req.TenantID,
		ProjectID: projID,
		SizeBytes: req.SizeBytes,
	})
}

type resizeTenantRequest struct {
	SizeBytes int64 `json:"size_bytes"`
}

// resizeTenant changes an existing tenant's hard size cap in place
// (PATCH /control/tenants/{id}). It is the data-plane half of elastic storage:
// orlop-control's storage autoscaler calls it to grow a tenant toward its
// promised ceiling, and a cap upgrade raises an anon trial's cap the
// same way. Idempotent: re-applying the current size returns 200 unchanged.
//
// Only the kernel quota (quota_state.json) is updated — registered_tenants.json
// holds a now-stale size, but that field is never consulted on reload
// (openTenantState ignores it), so it is intentionally left untouched.
func (s *serverState) resizeTenant(w http.ResponseWriter, r *http.Request) {
	if s.adminCfg.TenantsRoot == "" {
		writeJSONError(w, http.StatusNotImplemented, errCodeRegistrationDisabled, "dynamic tenant registration is not configured")
		return
	}

	tenantID := chi.URLParam(r, "id")
	if !tenantIDRe.MatchString(tenantID) {
		writeJSONError(w, http.StatusBadRequest, "invalid_tenant_id", "tenant_id must match ^[A-Za-z0-9_][A-Za-z0-9_-]{0,62}$")
		return
	}

	var req resizeTenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, errCodeInvalidRequest, "request body must be valid JSON")
		return
	}
	if req.SizeBytes <= 0 {
		writeJSONError(w, http.StatusBadRequest, "invalid_size", "size_bytes must be > 0")
		return
	}

	// Hold the write lock across the existence check + Resize to serialize with
	// a concurrent register/unregister of the same tenant. Mirrors registerTenant.
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.tenants[tenantID]; !ok {
		writeJSONError(w, http.StatusNotFound, "not_found", "tenant is not registered")
		return
	}

	projID, err := s.quota.Resize(r.Context(), tenantID, req.SizeBytes)
	if err != nil {
		if errors.Is(err, quota.ErrTenantNotFound) {
			writeJSONError(w, http.StatusNotFound, "not_found", "tenant has no quota record")
			return
		}
		var notQuota quota.ErrNotProjectQuotaFS
		if errors.As(err, &notQuota) {
			s.logger.Error("quota resize unavailable", "tenant_id", tenantID, "stderr", notQuota.Stderr)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			encodeJSON(w, map[string]any{
				"error": map[string]any{
					"code":    errCodeFSQuotaUnavailable,
					"message": notQuota.Stderr,
				},
			})
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "quota_failed", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, registerTenantResponse{
		TenantID:  tenantID,
		ProjectID: projID,
		SizeBytes: req.SizeBytes,
	})
}

// unregisterTenant tears down a dynamically-registered tenant. Used by
// orlop-control's anonymous-session sweeper to drop a per-session tenant
// after the 5-min sandbox + 5h adoption window has elapsed. Idempotent: a
// second call returns 404 with code "not_found" but is otherwise safe.
//
// Cleanup order (best-effort; any one step's failure logs but does not
// abort the others — we'd rather leave one orphan than leak the whole
// tenant):
//  1. Remove from in-memory map so new connections can't bind to it
//  2. Close the routes.db handle
//  3. Delete the tenant's on-disk directory (storeRoot + routes.db)
//  4. Drop the entry from registered_tenants.json
//
// Quota records in quota_state.json are intentionally NOT released — the
// project ID is monotonically allocated and the directory is gone so the
// quota slot is effectively dead. A later compaction pass can reclaim
// project IDs if the slot count becomes a problem.
func (s *serverState) unregisterTenant(w http.ResponseWriter, r *http.Request) {
	if s.adminCfg.TenantsRoot == "" {
		writeJSONError(w, http.StatusNotImplemented, errCodeRegistrationDisabled, "dynamic tenant registration is not configured")
		return
	}

	tenantID := chi.URLParam(r, "id")
	if !tenantIDRe.MatchString(tenantID) {
		writeJSONError(w, http.StatusBadRequest, "invalid_tenant_id", "tenant_id must match ^[A-Za-z0-9_][A-Za-z0-9_-]{0,62}$")
		return
	}

	// Hold s.mu across the registered_tenants.json write so a concurrent
	// registerTenant of the same ID can't race with our remove and either
	// resurrect a deleted entry or drop a live one. Mirrors the lock
	// scope in registerTenant.
	s.mu.Lock()
	defer s.mu.Unlock()

	ts, ok := s.tenants[tenantID]
	if !ok {
		writeJSONError(w, http.StatusNotFound, "not_found", "tenant is not registered")
		return
	}
	delete(s.tenants, tenantID)

	if err := ts.db.Close(); err != nil {
		s.logger.Error("unregister tenant db close failed", "tenant_id", tenantID, "error", err)
	}
	// The tenant dir may be nested under its account (u_<owner>/<tenant_id>), so derive
	// it from the registered store root rather than recomputing the (flat) path.
	tenantDir := filepath.Dir(ts.storeRoot)
	if err := os.RemoveAll(tenantDir); err != nil {
		s.logger.Error("unregister tenant rmdir failed", "tenant_id", tenantID, "error", err)
	}
	// routes.db + leases.db live in a separate metadata dir (metadata_root split);
	// remove it too so the SQLite files don't orphan on the NVMe disk. When the
	// metadata dir IS the tenant dir (single-disk), this is a harmless no-op.
	if metaDir := filepath.Dir(ts.routesDB); metaDir != tenantDir {
		if err := os.RemoveAll(metaDir); err != nil {
			s.logger.Error("unregister tenant metadata rmdir failed", "tenant_id", tenantID, "error", err)
		}
	}
	if err := removeRegisteredTenant(s.adminCfg.RegisteredTenantsPath, tenantID); err != nil {
		s.logger.Error("unregister tenant persist failed", "tenant_id", tenantID, "error", err)
	}

	w.WriteHeader(http.StatusNoContent)
}

// setAccountQuota sets (or resizes) the JuiceFS hard cap on an account's owner tenant dir
// — the shared disk budget (plan included + purchased) that all the account's agents draw
// from. PATCH /control/accounts/{owner}/quota {"size_bytes": <budget>}. Idempotent, and
// resizes in place when the budget changes (the buy/upgrade path). It creates the owner
// dir if no agent has been placed under the account yet, so a user can buy disk before
// (or without) running an agent.
func (s *serverState) setAccountQuota(w http.ResponseWriter, r *http.Request) {
	if s.adminCfg.TenantsRoot == "" {
		writeJSONError(w, http.StatusNotImplemented, errCodeRegistrationDisabled, "dynamic tenant registration is not configured")
		return
	}
	owner := chi.URLParam(r, "owner")
	if !tenantIDRe.MatchString(owner) {
		writeJSONError(w, http.StatusBadRequest, "invalid_owner_tenant_id", "owner must match the tenant_id pattern")
		return
	}
	var req resizeTenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, errCodeInvalidRequest, "request body must be valid JSON")
		return
	}
	if req.SizeBytes <= 0 {
		writeJSONError(w, http.StatusBadRequest, "invalid_size", "size_bytes must be > 0")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	ownerDir := filepath.Join(s.adminCfg.TenantsRoot, owner)
	if err := os.MkdirAll(ownerDir, 0o750); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "mkdir_failed", err.Error())
		return
	}
	// Async path: hand the (re)assertion to the background applier so a slow first
	// `juicefs quota set` doesn't block the buy/upgrade response. The apply is
	// idempotent and retried until it sticks; the live resize the caller wanted lands
	// shortly after the 200. (orlop-control already treats a resize failure here
	// as non-fatal, so eventual application only strengthens the guarantee.)
	if s.quotaApply != nil {
		s.quotaApply.Enqueue(owner, ownerDir, req.SizeBytes)
		projID, _, _ := s.quota.Lookup(owner)
		writeJSON(w, http.StatusOK, registerTenantResponse{TenantID: owner, ProjectID: projID, SizeBytes: req.SizeBytes})
		return
	}
	projID, err := s.quota.EnsureQuota(r.Context(), owner, ownerDir, req.SizeBytes)
	if err != nil {
		var notQuota quota.ErrNotProjectQuotaFS
		if errors.As(err, &notQuota) {
			s.logger.Error("account quota unavailable", "owner_tenant", owner, "stderr", notQuota.Stderr)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			encodeJSON(w, map[string]any{
				"error": map[string]any{"code": errCodeFSQuotaUnavailable, "message": notQuota.Stderr},
			})
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "quota_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, registerTenantResponse{TenantID: owner, ProjectID: projID, SizeBytes: req.SizeBytes})
}
