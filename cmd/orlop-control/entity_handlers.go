package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/allocations"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage/postgres"
)

// agentDiskInitialGrantBytes is the initial elastic grant for a freshly-
// provisioned agent disk when the caller specifies no quota_bytes. It is
// deliberately well below the promised ceiling (users.quota_bytes, 10 GiB in
// migration 0001): the storage autoscaler grows the grant toward that ceiling as
// real usage climbs, so we don't reserve 10 GiB of pool capacity per user up
// front. See docs/design/elastic-storage-allocation.md.
const agentDiskInitialGrantBytes = 1 * 1024 * 1024 * 1024 // 1 GiB

// agentVirtualPath is the stable mount path for an agent's disk. It must match
// the control-plane's mount-path scheme so every pod for the same
// agent lands on the same files.
func agentVirtualPath(agentID string) string {
	return "/mnt/orlop/agents/" + agentID
}

// entityQuerier is the slice of the storage layer the entity handlers need:
// the provisioning write surface plus the allocation/user reads the quota and
// account-budget paths walk. Declaring it as an interface lets the unit tests
// inject a stub without a live database; *postgres.Store satisfies it.
type entityQuerier interface {
	storage.ProvisioningStore
	GetUser(ctx context.Context, id uuid.UUID) (storage.User, error)
	// Quota lifecycle (anon-trial funnel): revoke an agent's disk when a trial
	// expires (DELETE). A cap upgrade (PATCH) routes through the
	// resize primitive (allocationResizer), not a direct size write here.
	RevokeAllocation(ctx context.Context, allocID, userID uuid.UUID) error
	// Account-budget path (the buy/upgrade): list a user's allocations to re-stamp
	// the new account budget on each, and resolve where they're placed (the
	// embedded tenantPlacementQuerier, consumed via resolveTenantOpsAddr) to
	// resize the live shared owner quota.
	ListAllocationsForUser(ctx context.Context, userID uuid.UUID) ([]storage.Allocation, error)
	UpdateAllocationSize(ctx context.Context, allocID, userID uuid.UUID, sizeBytes int64) (storage.Allocation, error)
	tenantPlacementQuerier
}

// accountQuotaSetter resizes the live JuiceFS quota on an account's owner tenant dir on
// a orlop-server. *serverapi.Client satisfies it.
type accountQuotaSetter interface {
	SetAccountQuota(ctx context.Context, opsAddr, ownerTenantID string, sizeBytes int64) (uint32, error)
}

// enrollTokenMinter mints a short-lived, agent-scoped enroll token bound to an
// allocation. It is satisfied by devauth.Service.IssueAgentEnrollToken; the
// indirection keeps the handler testable without a live devauth.Service.
type enrollTokenMinter func(ctx context.Context, userID pgtype.UUID, tenantID string, allocationID pgtype.UUID) (token string, expiresAt time.Time, err error)

// entityHandlers serves the service-to-service /v1/entities provisioning API
// the orlop control-plane calls when an agent first needs a disk. This is
// metadata-only (Phase 1 of docs/design/agent-storage-bridge.md): it ensures
// the owner's per-user tenant + user and upserts the agent's disk allocation.
// CA bootstrap and server placement remain at enroll/mount time. It also serves
// POST /v1/agents/{id}/enroll-token (Phase 4): a per-pod, agent-scoped enroll
// token the control-plane injects into the mounter sidecar.
type entityHandlers struct {
	logger     *slog.Logger
	queries    entityQuerier
	mintEnroll enrollTokenMinter
	resize     allocationResizer
	serverAPI  allocations.TenantResizer
	// purge erases a revoked allocation's backend data inline on DELETE (the
	// revoke itself is metadata-only). Nil when no data-plane admin client is
	// configured — the on-demand purge sweep then remains the only eraser.
	purge    allocationPurger
	purgeAPI allocations.AgentDataPurger
	// initialGrantBytes is the elastic disk size granted at provision when the
	// caller passes no quota_bytes (ORLOP_INITIAL_GRANT_BYTES; defaults to
	// agentDiskInitialGrantBytes).
	initialGrantBytes int64
}

// allocationResizer applies an end-to-end quota resize (DB size_bytes +
// server_pool reservation + data-plane ext4 quota). Satisfied by
// *allocations.Service; an interface so the handler tests can stub it.
type allocationResizer interface {
	Resize(ctx context.Context, api allocations.TenantResizer, allocationID, userID pgtype.UUID, newSizeBytes int64) (allocations.Allocation, error)
}

// allocationPurger erases a revoked allocation's backend data (per-agent
// subtree or whole-tenant unregister). Satisfied by *allocations.Service; an
// interface so the handler tests can stub it.
type allocationPurger interface {
	PurgeAllocation(ctx context.Context, api allocations.AgentDataPurger, allocationID pgtype.UUID) error
}

func newEntityHandlers(logger *slog.Logger, q entityQuerier, mintEnroll enrollTokenMinter, resize allocationResizer, serverAPI allocations.TenantResizer, purge allocationPurger, purgeAPI allocations.AgentDataPurger, initialGrantBytes int64) *entityHandlers {
	if initialGrantBytes <= 0 {
		initialGrantBytes = agentDiskInitialGrantBytes
	}
	return &entityHandlers{logger: logger, queries: q, mintEnroll: mintEnroll, resize: resize, serverAPI: serverAPI, purge: purge, purgeAPI: purgeAPI, initialGrantBytes: initialGrantBytes}
}

// mountEntities registers the provisioning routes on both the bare `/v1/...`
// path and the `/api`-prefixed path (the production edge strips `/api` before
// forwarding; the prefixed mount lets a same-origin caller hit the control
// plane directly). Both are gated by the svc middleware — these are
// control-plane→control-plane calls, never a user-facing surface, so they do
// NOT go through the user RequireBearer path.
func mountEntities(r chi.Router, svc func(http.Handler) http.Handler, h *entityHandlers) {
	for _, prefix := range []string{"", "/api"} {
		r.With(svc).Post(prefix+"/v1/entities", h.handleProvision)
		r.With(svc).Get(prefix+"/v1/entities/{type}/{id}", h.handleResolve)
		r.With(svc).Patch(prefix+"/v1/entities/{type}/{id}", h.handleSetQuota)
		r.With(svc).Delete(prefix+"/v1/entities/{type}/{id}", h.handleDelete)
		r.With(svc).Post(prefix+"/v1/agents/{id}/enroll-token", h.handleEnrollToken)
		r.With(svc).Post(prefix+"/v1/entities/{type}/{id}/reassign", h.handleReassign)
		r.With(svc).Post(prefix+"/v1/entities/account/{owner}/budget", h.handleSetAccountBudget)
	}
}

// Dynamic tenant-id prefixes. These tenants are derived server-side from an
// authenticated user/agent id (never from an external claim), which is why the
// CA bootstrap allowlist may trust them by prefix (issue #8).
const (
	tenantPrefixUser  = "u_" // per-owner (user) tenant
	tenantPrefixAgent = "a_" // per-agent storage tenant
)

// tenantIDForOwner derives the deterministic dg-tenant id from a orlop owner
// (user) UUID. Idempotent ensure keys on this id.
func tenantIDForOwner(ownerID string) string { return tenantPrefixUser + ownerID }

// tenantForAgent derives the per-agent storage tenant id from a orlop agent id.
// Each agent's disk lives in its own tenant so it can be re-homed to a different
// billing owner without moving data (docs/design/per-agent-tenant.md).
func tenantForAgent(agentID string) string { return tenantPrefixAgent + agentID }

// syntheticUserEmail is the email stored on the reused dg user row. The dg user
// id is the orlop user UUID; the email column is NOT NULL UNIQUE so we mint a
// deterministic synthetic address per owner.
func syntheticUserEmail(ownerID string) string {
	return ownerID + "@agents.orlop.internal"
}

type provisionEntityRequest struct {
	EntityType string `json:"entity_type"`
	EntityID   string `json:"entity_id"`
	OwnerID    string `json:"owner_id"`
	// GrantBytes is the INITIAL disk grant (disk_allocations.size_bytes) — NOT the
	// ceiling (users.quota_bytes, which the autoscaler grows toward). 0 ⇒
	// agentDiskInitialGrantBytes. The anon-trial funnel passes 128 MiB; a
	// registered agent passes ~1 GiB and grows elastically.
	GrantBytes int64 `json:"grant_bytes"`
	// QuotaBytes is the legacy name for GrantBytes (it always set size_bytes, the
	// grant, despite the misleading name). Accepted for back-compat with older
	// callers; GrantBytes wins when both are set. See elastic-storage-allocation.md.
	QuotaBytes int64 `json:"quota_bytes"`
}

// grant returns the requested initial grant, preferring the new grant_bytes field
// over the legacy quota_bytes alias.
func (req provisionEntityRequest) grant() int64 {
	if req.GrantBytes > 0 {
		return req.GrantBytes
	}
	return req.QuotaBytes
}

type entityResponse struct {
	Handle      string `json:"handle"`
	VirtualPath string `json:"virtual_path"`
}

func (h *entityHandlers) handleProvision(w http.ResponseWriter, r *http.Request) {
	var req provisionEntityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "malformed body")
		return
	}
	if req.EntityType != EntityTypeAgent {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request",
			`entity_type must be "agent"`)
		return
	}
	if req.EntityID == "" || req.OwnerID == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request",
			"entity_id and owner_id are required")
		return
	}

	owner, err := uuid.Parse(req.OwnerID)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "owner_id must be a uuid")
		return
	}

	tenantID := tenantIDForOwner(req.OwnerID)

	// D2: ensure the customer's per-user tenant (no CA bootstrap, no server_vm).
	if err := h.queries.EnsureTenant(r.Context(), tenantID, tenantID); err != nil {
		h.logger.Error("entity_ensure_tenant_failed", "error", err, "tenant_id", tenantID)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}

	// D3: ensure the dg user, reusing the orlop user UUID as the dg user id. Its
	// tenant_id is a per-user placeholder that satisfies the FK and anchors the
	// non-agent (OAuth) disk path; the agent's disk lives in its own tenant (D3b).
	if err := h.queries.EnsureUserWithID(r.Context(), storage.NewUser{
		ID:       owner,
		TenantID: tenantID,
		Email:    syntheticUserEmail(req.OwnerID),
	}); err != nil {
		h.logger.Error("entity_ensure_user_failed", "error", err, "owner_id", req.OwnerID)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}

	// D3b: ensure the agent's OWN storage tenant. Keying the disk on a per-agent
	// tenant (not the owner's) is what lets a re-parent be a user_id flip with no
	// data move (docs/design/per-agent-tenant.md).
	agentTenant := tenantForAgent(req.EntityID)
	if err := h.queries.EnsureTenant(r.Context(), agentTenant, agentTenant); err != nil {
		h.logger.Error("entity_ensure_agent_tenant_failed", "error", err, "tenant_id", agentTenant)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}

	// D4: idempotently upsert the agent's disk allocation, keyed on agent_id, in its
	// own tenant, with the requested per-agent hard cap (0 ⇒ the default). Re-
	// provisioning is a no-op that returns the existing row, so the cap is set at first
	// provision and changed thereafter via PATCH (handleSetQuota), never silently here.
	size := req.grant()
	if size <= 0 {
		size = h.initialGrantBytes
	}
	row, err := h.queries.UpsertAgentAllocation(r.Context(), storage.NewAgentAllocation{
		UserID:    owner,
		AgentID:   req.EntityID,
		TenantID:  agentTenant,
		SizeBytes: size,
	})
	if err != nil {
		h.logger.Error("entity_upsert_allocation_failed", "error", err, "agent_id", req.EntityID)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}

	h.logger.Info("entity_provisioned",
		"agent_id", req.EntityID,
		"owner_id", req.OwnerID,
		"tenant_id", tenantID,
		"handle", row.ID.String())

	writeJSON(w, http.StatusOK, entityResponse{
		Handle:      row.ID.String(),
		VirtualPath: agentVirtualPath(req.EntityID),
	})
}

func (h *entityHandlers) handleResolve(w http.ResponseWriter, r *http.Request) {
	if chi.URLParam(r, "type") != EntityTypeAgent {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request",
			`type must be "agent"`)
		return
	}
	agentID := chi.URLParam(r, "id")
	if agentID == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "id is required")
		return
	}

	row, err := h.queries.GetAllocationByAgent(r.Context(), agentID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeOAuthError(w, http.StatusNotFound, "not_found", "")
			return
		}
		h.logger.Error("entity_resolve_failed", "error", err, "agent_id", agentID)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}

	writeJSON(w, http.StatusOK, entityResponse{
		Handle:      row.ID.String(),
		VirtualPath: agentVirtualPath(agentID),
	})
}

// handleSetQuota raises (or lowers) an agent's disk hard cap in place, preserving
// the allocation id (the control-plane's stored disk handle). A cap
// upgrade flips an anon agent's 128 MiB disk to the registered size.
// PATCH /v1/entities/{type}/{id}.
func (h *entityHandlers) handleSetQuota(w http.ResponseWriter, r *http.Request) {
	if chi.URLParam(r, "type") != EntityTypeAgent {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", `type must be "agent"`)
		return
	}
	agentID := chi.URLParam(r, "id")
	if agentID == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "id is required")
		return
	}
	// grant_bytes is the new name (it resizes size_bytes, the grant); quota_bytes is
	// the legacy alias, accepted for back-compat. grant_bytes wins when both are set.
	var body struct {
		GrantBytes int64 `json:"grant_bytes"`
		QuotaBytes int64 `json:"quota_bytes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "malformed body")
		return
	}
	newGrant := body.GrantBytes
	if newGrant <= 0 {
		newGrant = body.QuotaBytes
	}
	if newGrant <= 0 {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "grant_bytes must be > 0")
		return
	}
	alloc, err := h.queries.GetAllocationByAgent(r.Context(), agentID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeOAuthError(w, http.StatusNotFound, "not_found", "")
			return
		}
		h.logger.Error("entity_set_quota_lookup_failed", "error", err, "agent_id", agentID)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	// Route through the end-to-end resize primitive so the new cap propagates to
	// the data-plane ext4 quota and the server_pool reservation — not just the DB
	// row. (Before this, the cap upgrade was a cosmetic DB-only change.)
	resized, err := h.resize.Resize(r.Context(), h.serverAPI, fromUUID(alloc.ID), fromUUID(alloc.UserID), newGrant)
	if err != nil {
		switch {
		case errors.Is(err, allocations.ErrNotFound):
			writeOAuthError(w, http.StatusNotFound, "not_found", "")
		case errors.Is(err, allocations.ErrNoCapacity):
			writeOAuthError(w, http.StatusConflict, "insufficient_capacity",
				"no server capacity to grow the disk")
		default:
			h.logger.Error("entity_set_quota_failed", "error", err, "agent_id", agentID)
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		}
		return
	}
	writeJSON(w, http.StatusOK, entityResponse{
		Handle:      uuidString(resized.ID),
		VirtualPath: agentVirtualPath(agentID),
	})
}

// handleDelete revokes an agent's disk allocation and erases its backend data.
// Called by the orlop control-plane on agent delete and by the 7-day retention
// sweeper when an anonymous trial expires. Idempotent: an unknown agent (or an
// already-revoked one) is a no-op 204. DELETE /v1/entities/{type}/{id}.
//
// The revoke (DB soft-delete) is the source of truth and always 204s once it
// lands. The data erase that follows is inline but best-effort: a failure is
// logged and the allocation stays revoked-unpurged, where the on-demand purge
// sweep (POST /v1/admin/purge-sweep) retries it.
func (h *entityHandlers) handleDelete(w http.ResponseWriter, r *http.Request) {
	if chi.URLParam(r, "type") != EntityTypeAgent {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", `type must be "agent"`)
		return
	}
	agentID := chi.URLParam(r, "id")
	if agentID == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "id is required")
		return
	}
	alloc, err := h.queries.GetAllocationByAgent(r.Context(), agentID)
	if errors.Is(err, storage.ErrNotFound) {
		w.WriteHeader(http.StatusNoContent) // idempotent: nothing to revoke
		return
	}
	if err != nil {
		h.logger.Error("entity_delete_lookup_failed", "error", err, "agent_id", agentID)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	if err := h.queries.RevokeAllocation(r.Context(), alloc.ID, alloc.UserID); err != nil && !errors.Is(err, storage.ErrNotFound) {
		h.logger.Error("entity_delete_revoke_failed", "error", err, "agent_id", agentID)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}

	if h.purge != nil && h.purgeAPI != nil {
		purgeCtx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		if err := h.purge.PurgeAllocation(purgeCtx, h.purgeAPI, fromUUID(alloc.ID)); err != nil {
			// Revoke already landed; the sweeper retries the erase.
			h.logger.Error("entity_delete_purge_failed", "error", err, "agent_id", agentID,
				"allocation_id", alloc.ID.String())
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

// enrollTokenResponse is the body of POST /v1/agents/{id}/enroll-token.
type enrollTokenResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
}

// handleEnrollToken mints a per-pod, agent-scoped enroll token (Phase 4 of
// docs/design/agent-storage-bridge.md). The orlop control-plane calls it at pod
// launch and injects the returned token as the mounter sidecar's
// ORLOP_ENROLL_TOKEN env (replacing a static Secret). Flow: agent_id (URL) →
// GetAllocationByAgent → allocation.user_id → GetUser → tenant_id →
// IssueAgentEnrollToken(user, tenant, allocation.ID). The token carries the
// allocation_id so /agent/enroll mints the cert with the per-agent SAN.
func (h *entityHandlers) handleEnrollToken(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "id")
	if agentID == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "id is required")
		return
	}

	alloc, err := h.queries.GetAllocationByAgent(r.Context(), agentID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeOAuthError(w, http.StatusNotFound, "not_found", "")
			return
		}
		h.logger.Error("enroll_token_allocation_lookup_failed", "error", err, "agent_id", agentID)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}

	// The allocation owner's user row carries the tenant the enroll token (and
	// the cert it is traded for) must be scoped to.
	user, err := h.queries.GetUser(r.Context(), alloc.UserID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			// An allocation always has a user; a missing one is an internal
			// inconsistency, not a client error.
			h.logger.Error("enroll_token_user_missing", "agent_id", agentID, "user_id", alloc.UserID.String())
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
			return
		}
		h.logger.Error("enroll_token_user_lookup_failed", "error", err, "agent_id", agentID)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}

	// Scope the token (and the cert it's traded for) to the AGENT's own tenant, so a
	// re-parented agent's pod still mounts the agent's disk regardless of who now owns
	// it. Fall back to the user's tenant for a legacy allocation with no per-agent one.
	tenant := user.TenantID
	if alloc.TenantID != "" {
		tenant = alloc.TenantID
	}
	token, expiresAt, err := h.mintEnroll(r.Context(), fromUUID(alloc.UserID), tenant, fromUUID(alloc.ID))
	if err != nil {
		h.logger.Error("enroll_token_mint_failed", "error", err, "agent_id", agentID)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}

	h.logger.Info("enroll_token_minted",
		"agent_id", agentID,
		"user_id", alloc.UserID.String(),
		"tenant_id", tenant,
		"allocation_id", alloc.ID.String())

	writeJSON(w, http.StatusOK, enrollTokenResponse{
		Token:     token,
		ExpiresAt: expiresAt.UTC().Format(time.RFC3339),
	})
}

type reassignEntityRequest struct {
	OwnerID string `json:"owner_id"`
}

// handleReassign re-homes an agent's disk to a new billing owner WITHOUT moving data
// (docs/design/per-agent-tenant.md): the disk stays in its per-agent tenant; only the
// allocation's user_id (the billing owner) changes. The control-plane calls this to
// merge an anon trial's agent into an existing account on login. Idempotent, and with
// no quota gate — a merge is allowed even if it pushes the new owner over their ceiling.
// POST /v1/entities/{type}/{id}/reassign  {"owner_id":"<new orlop user uuid>"}.
func (h *entityHandlers) handleReassign(w http.ResponseWriter, r *http.Request) {
	if chi.URLParam(r, "type") != EntityTypeAgent {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", `type must be "agent"`)
		return
	}
	agentID := chi.URLParam(r, "id")
	if agentID == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "id is required")
		return
	}
	var req reassignEntityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "malformed body")
		return
	}
	newOwner, err := uuid.Parse(req.OwnerID)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "owner_id must be a uuid")
		return
	}

	// Ensure the new owner's dg user (+ its placeholder tenant) exists so the
	// allocation's user_id FK resolves after the flip.
	newTenant := tenantIDForOwner(req.OwnerID)
	if err := h.queries.EnsureTenant(r.Context(), newTenant, newTenant); err != nil {
		h.logger.Error("entity_reassign_ensure_tenant_failed", "error", err, "tenant_id", newTenant)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	if err := h.queries.EnsureUserWithID(r.Context(), storage.NewUser{
		ID: newOwner, TenantID: newTenant, Email: syntheticUserEmail(req.OwnerID),
	}); err != nil {
		h.logger.Error("entity_reassign_ensure_user_failed", "error", err, "owner_id", req.OwnerID)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}

	if err := h.queries.ReassignAgentAllocation(r.Context(), agentID, newOwner); err != nil {
		h.logger.Error("entity_reassign_failed", "error", err, "agent_id", agentID, "owner_id", req.OwnerID)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}

	h.logger.Info("entity_reassigned", "agent_id", agentID, "new_owner_id", req.OwnerID)
	w.WriteHeader(http.StatusNoContent)
}

type setAccountBudgetRequest struct {
	DiskBytes int64 `json:"disk_bytes"`
}

// handleSetAccountBudget sets an account's shared disk budget (plan included + purchased)
// — the buy/upgrade path. POST /v1/entities/account/{owner}/budget {"disk_bytes": N}.
// It (1) re-stamps the budget on each of the user's allocations so future placements
// carry it, and (2) resizes the LIVE shared quota on the owner dir of every server the
// account's agents are placed on, so a buy takes effect immediately (e.g. on a warm pod).
// The live resize is best-effort: a failure is logged but doesn't fail the call, since the
// next cold enroll re-asserts the budget from the updated allocation size.
func (h *entityHandlers) handleSetAccountBudget(w http.ResponseWriter, r *http.Request) {
	owner := chi.URLParam(r, "owner")
	ownerUUID, err := uuid.Parse(owner)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "owner must be a uuid")
		return
	}
	var req setAccountBudgetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "malformed body")
		return
	}
	if req.DiskBytes <= 0 {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "disk_bytes must be > 0")
		return
	}

	ownerTenant := tenantIDForOwner(owner)

	allocs, err := h.queries.ListAllocationsForUser(r.Context(), ownerUUID)
	if err != nil {
		h.logger.Error("account_budget_list_allocations_failed", "error", err, "owner_id", owner)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}

	// (1) Re-stamp the budget on every allocation so future placements carry it.
	for _, a := range allocs {
		if _, err := h.queries.UpdateAllocationSize(r.Context(), a.ID, a.UserID, req.DiskBytes); err != nil {
			h.logger.Error("account_budget_update_alloc_failed", "error", err, "allocation_id", a.ID.String())
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
			return
		}
	}

	// (2) Resize the live owner quota on each distinct server holding the account.
	if setter, ok := h.serverAPI.(accountQuotaSetter); ok {
		servers := map[string]struct{}{}
		for _, a := range allocs {
			tenant := ownerTenant
			if a.TenantID != "" {
				tenant = a.TenantID
			}
			// Resolve the tenant's ops addr (server_vms → server_pools), skipping any
			// tenant not yet placed or whose lookup errors — a best-effort live resize.
			opsAddr, placed, rErr := resolveTenantOpsAddr(r.Context(), h.queries, tenant)
			if rErr != nil || !placed {
				continue
			}
			servers[opsAddr] = struct{}{}
		}
		for opsAddr := range servers {
			if _, err := setter.SetAccountQuota(r.Context(), opsAddr, ownerTenant, req.DiskBytes); err != nil {
				h.logger.Error("account_budget_live_resize_failed", "error", err, "ops_addr", opsAddr, "owner_tenant", ownerTenant)
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"owner_id": owner, "disk_bytes": req.DiskBytes})
}

// EntityTypeAgent is the only entity namespace /v1/entities provisions today:
// a orlop agent maps 1:1 onto a per-agent disk allocation.
const EntityTypeAgent = "agent"

// RequireServiceToken returns middleware that authenticates control-plane→
// control-plane calls via a static bearer token. It constant-time-compares the
// Authorization header to expected and rejects on mismatch. It fails closed:
// when expected is empty (token unconfigured) every request is rejected, so an
// unconfigured deployment never exposes the provisioning API unauthenticated.
//
// This is deliberately NOT the user RequireBearer path: /v1/entities is a
// service surface, not a user surface.
func RequireServiceToken(expected string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if expected == "" {
				writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "")
				return
			}
			got := bearerToken(r.Header.Get("Authorization"))
			if subtle.ConstantTimeCompare([]byte(got), []byte(expected)) != 1 {
				writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ensure *postgres.Store satisfies entityQuerier at compile time.
var _ entityQuerier = (*postgres.Store)(nil)
