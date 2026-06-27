package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/allocations"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/devauth"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/tokens"
)

type devAuthHandlers struct {
	svc          *devauth.Service
	allocations  *allocations.Service
	logger       *slog.Logger
	cookieDomain string
	createCode   *devauth.RateLimiter
	pollLimit    *devauth.RateLimiter
	approveLim   *devauth.RateLimiter
}

func newDevAuthHandlers(logger *slog.Logger, svc *devauth.Service, allocationSvc *allocations.Service, cookieDomain string) *devAuthHandlers {
	return &devAuthHandlers{
		svc:          svc,
		allocations:  allocationSvc,
		logger:       logger,
		cookieDomain: cookieDomain,
		createCode:   devauth.NewRateLimiter(10, time.Minute),
		pollLimit:    devauth.NewRateLimiter(60, time.Minute),
		approveLim:   devauth.NewRateLimiter(30, time.Minute),
	}
}

// mountDeviceFlow registers the device-flow routes. Public
// (createCode, poll, devicePage, approve) — auth is enforced inside
// each handler as appropriate.
func mountDeviceFlow(r chi.Router, h *devAuthHandlers) {
	r.Post("/auth/logout", h.handleLogout)
	r.Post("/auth/device/code", h.handleCreateCode)
	r.Post("/auth/device/token", h.handleTokenPoll)
	r.Post("/auth/token/refresh", h.handleTokenRefresh)
	r.Get("/device", h.handleDevicePage)
	r.Get("/device/lookup", h.handleDeviceLookup)
	r.Post("/device/approve", h.handleApprove)
}

// apiTokenTouchInterval is the minimum gap between writes of api_tokens.last_used_at.
// Reduces write amplification for high-frequency agents while keeping the timestamp
// fresh enough to be useful in the dashboard's "last used" column.
const apiTokenTouchInterval = 60 * time.Second

// RequireBearer returns middleware that resolves Identity from the
// Authorization header and stores it in the request context. Used by
// downstream endpoints (POST /agent/run, future control-plane APIs).
//
// Two token shapes are accepted; both go through bearerToken() so they
// recognise the same header forms (case-insensitive "Bearer", trailing
// whitespace tolerated):
//   - "orlop_<base32>": long-lived API token issued via /v1/tokens.
//     Looked up by SHA-256 hash; rejected if the row is missing,
//     revoked, or belongs to a suspended user or suspended tenant.
//   - everything else: short-lived device-flow access token, validated
//     by devauth.Service (existing OAuth path, unchanged).
func RequireBearer(svc *devauth.Service, store storage.APITokenStore) func(http.Handler) http.Handler {
	return requireBearer(store, svc.AuthenticateBearer)
}

// RequireEnrollBearer is RequireBearer for the /agent/enroll route. It is
// identical except the OAuth-style path additionally accepts a per-pod
// agent-scoped enroll token (devauth.PurposeAgentEnroll, minted by
// IssueAgentEnrollToken). The widened purpose set is confined to this
// middleware so /agent/run and other RequireBearer surfaces stay device-only.
func RequireEnrollBearer(svc *devauth.Service, store storage.APITokenStore) func(http.Handler) http.Handler {
	return requireBearer(store, svc.AuthenticateEnrollBearer)
}

// requireBearer is the shared body for RequireBearer / RequireEnrollBearer.
// authenticate validates the OAuth-style (non-"orlop_") token and resolves an
// Identity; the API-token ("orlop_") shape is handled identically for both.
func requireBearer(store storage.APITokenStore, authenticate func(context.Context, string) (devauth.Identity, error)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := bearerToken(r.Header.Get("Authorization"))
			if strings.HasPrefix(raw, tokens.Prefix) {
				auth, err := store.GetAPITokenByHash(r.Context(), tokens.Hash(raw))
				if err != nil || auth.Revoked {
					writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "")
					return
				}
				// Optional expiry (set when ORLOP_API_TOKEN_TTL is configured at
				// mint time). nil = never expires (the historical behavior).
				if auth.ExpiresAt != nil && time.Now().After(*auth.ExpiresAt) {
					writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "expired")
					return
				}
				if auth.TenantSuspended {
					writeOAuthError(w, http.StatusForbidden, "access_denied", "tenant_suspended")
					return
				}
				if auth.UserSuspended {
					writeOAuthError(w, http.StatusForbidden, "access_denied", "user_suspended")
					return
				}
				// Debounced last-used update — only write once per 60s per token,
				// so a busy agent doesn't issue a write per request. Synchronous
				// (the UPDATE is a single indexed-PK touch and ~1ms; goroutine
				// would add lifetime-management complexity for no measurable win).
				if auth.LastUsedAt == nil || time.Since(*auth.LastUsedAt) > apiTokenTouchInterval {
					_ = store.TouchAPITokenLastUsed(r.Context(), auth.ID)
				}
				ident := devauth.Identity{
					UserID:   fromUUID(auth.UserID),
					TenantID: auth.TenantID,
					Purpose:  devauth.PurposeAPIToken,
				}
				ctx := context.WithValue(r.Context(), identityCtxKey{}, ident)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// OAuth-style bearer (existing path).
			ident, err := authenticate(r.Context(), r.Header.Get("Authorization"))
			if err != nil {
				// Distinguish suspension causes so callers can show a
				// precise message — matches the contract added by #160
				// for the enroll handler, which expects this middleware
				// to pass through the same descriptions.
				if errors.Is(err, devauth.ErrTenantSuspended) {
					writeOAuthError(w, http.StatusForbidden, "access_denied", "tenant_suspended")
					return
				}
				if errors.Is(err, devauth.ErrUserSuspended) {
					writeOAuthError(w, http.StatusForbidden, "access_denied", "user_suspended")
					return
				}
				writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "")
				return
			}
			ctx := context.WithValue(r.Context(), identityCtxKey{}, ident)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

type identityCtxKey struct{}

// IdentityFromRequest is exported for downstream handlers (#31 enroll).
func IdentityFromRequest(r *http.Request) (devauth.Identity, bool) {
	id, ok := r.Context().Value(identityCtxKey{}).(devauth.Identity)
	return id, ok
}

// --- handlers ---

func (h *devAuthHandlers) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, h.adminCookie(r, "", -1))
	w.WriteHeader(http.StatusNoContent)
}

func (h *devAuthHandlers) handleCreateCode(w http.ResponseWriter, r *http.Request) {
	if !h.createCode.Allow(clientIP(r)) {
		writeOAuthError(w, http.StatusTooManyRequests, "slow_down", "rate limit exceeded")
		return
	}
	deviceCode, userCode, expiresAt, err := h.svc.CreateDeviceCode(r.Context())
	if err != nil {
		h.logger.Error("device_code_create_failed", "error", err)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	resp := map[string]any{
		"device_code":      deviceCode,
		"user_code":        userCode,
		"verification_uri": verificationURI(r),
		"expires_in":       int(time.Until(expiresAt).Round(time.Second).Seconds()),
		"interval":         int(devauth.PollInterval.Seconds()),
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *devAuthHandlers) handleTokenPoll(w http.ResponseWriter, r *http.Request) {
	if !h.pollLimit.Allow(clientIP(r)) {
		writeOAuthError(w, http.StatusTooManyRequests, "slow_down", "")
		return
	}
	deviceCode, err := readDeviceCodeParam(r)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	res, err := h.svc.Poll(r.Context(), deviceCode)
	if err != nil {
		h.logger.Error("device_token_poll_failed", "error", err)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	switch res.Status {
	case "ready":
		resp := map[string]any{
			"access_token":       res.AccessToken,
			"access_expires_at":  res.AccessExpiresAt,
			"refresh_token":      res.RefreshToken,
			"refresh_expires_at": res.RefreshExpiresAt,
			"control_plane_url":  controlPlaneURL(r),
			"user_id":            uuidString(res.UserID),
			"token_type":         "Bearer",
			"expires_in":         res.ExpiresIn,
		}
		if res.AllocationID.Valid {
			resp["allocation_id"] = uuidString(res.AllocationID)
		}
		writeJSON(w, http.StatusOK, resp)
	case "authorization_pending", "slow_down":
		writeOAuthError(w, http.StatusBadRequest, res.Status, "")
	case "access_denied":
		writeOAuthError(w, http.StatusBadRequest, "access_denied", "")
	case "expired_token":
		writeOAuthError(w, http.StatusBadRequest, "expired_token", "")
	default:
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
	}
}

func (h *devAuthHandlers) handleTokenRefresh(w http.ResponseWriter, r *http.Request) {
	res, err := h.svc.Refresh(r.Context(), bearerToken(r.Header.Get("Authorization")))
	if err != nil {
		switch {
		case errors.Is(err, devauth.ErrUserSuspended), errors.Is(err, devauth.ErrTenantSuspended):
			writeOAuthError(w, http.StatusForbidden, "access_denied", "")
		case errors.Is(err, devauth.ErrBearerMissing),
			errors.Is(err, devauth.ErrTokenUnknown),
			errors.Is(err, devauth.ErrTokenRevoked),
			errors.Is(err, devauth.ErrTokenExpired):
			writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "")
		default:
			h.logger.Error("refresh_token_failed", "error", err)
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		}
		return
	}
	resp := map[string]any{
		"access_token":       res.AccessToken,
		"access_expires_at":  res.AccessExpiresAt,
		"refresh_token":      res.RefreshToken,
		"refresh_expires_at": res.RefreshExpiresAt,
		"control_plane_url":  controlPlaneURL(r),
		"user_id":            uuidString(res.UserID),
		"token_type":         "Bearer",
		"expires_in":         res.ExpiresIn,
	}
	if res.AllocationID.Valid {
		resp["allocation_id"] = uuidString(res.AllocationID)
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleDevicePage renders the approval form. Two flows:
//   - ?session=TOK present: validate, set HttpOnly cookie, redirect to /device.
//     This is the runbook flow — the operator pastes the URL printed by
//     `orlop-control user seed` into a browser.
//   - cookie present: render form.
//   - neither: 401 with a one-line reminder pointing at the runbook.
func (h *devAuthHandlers) handleDevicePage(w http.ResponseWriter, r *http.Request) {
	if tok := r.URL.Query().Get("session"); tok != "" {
		if _, err := h.svc.AuthenticateAdminSession(r.Context(), tok); err != nil {
			writeAdminAuthRequired(w)
			return
		}
		h.setAdminCookie(w, r, tok, int(devauth.AdminSessionTTL.Seconds()))
		http.Redirect(w, r, "/device", http.StatusFound)
		return
	}
	if _, err := adminIdentity(r, h.svc); err != nil {
		writeAdminAuthRequired(w)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = devicePageTpl.Execute(w, nil)
}

func (h *devAuthHandlers) handleApprove(w http.ResponseWriter, r *http.Request) {
	if !h.approveLim.Allow(clientIP(r)) {
		writeOAuthError(w, http.StatusTooManyRequests, "slow_down", "")
		return
	}
	ident, err := adminIdentity(r, h.svc)
	if err != nil {
		writeAdminAuthRequired(w)
		return
	}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		h.handleJSONApprove(w, r, ident)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	userCode := r.PostFormValue("user_code")
	action := r.PostFormValue("action")
	if userCode == "" || (action != "approve" && action != "deny") {
		http.Error(w, "user_code and action=approve|deny required", http.StatusBadRequest)
		return
	}
	var resolveErr error
	if action == "approve" {
		resolveErr = h.svc.ApproveByUserCode(r.Context(), userCode, ident)
	} else {
		resolveErr = h.svc.DenyByUserCode(r.Context(), userCode, ident)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	switch {
	case resolveErr == nil:
		_ = approveResultTpl.Execute(w, map[string]string{"Outcome": action + "d", "Detail": "The CLI session will pick up this decision on its next poll."})
	case errors.Is(resolveErr, devauth.ErrUserCodeUnknown):
		w.WriteHeader(http.StatusNotFound)
		_ = approveResultTpl.Execute(w, map[string]string{"Outcome": "rejected", "Detail": "Unknown user_code. Re-check the value displayed by the CLI."})
	case errors.Is(resolveErr, devauth.ErrUserCodeExpired):
		w.WriteHeader(http.StatusGone)
		_ = approveResultTpl.Execute(w, map[string]string{"Outcome": "rejected", "Detail": "The user_code has expired. Re-run `orlop login` and try again."})
	case errors.Is(resolveErr, devauth.ErrUserCodeAlreadyResolved):
		w.WriteHeader(http.StatusConflict)
		_ = approveResultTpl.Execute(w, map[string]string{"Outcome": "rejected", "Detail": "This user_code was already approved or denied."})
	default:
		h.logger.Error("device_approval_failed", "error", resolveErr)
		w.WriteHeader(http.StatusInternalServerError)
		_ = approveResultTpl.Execute(w, map[string]string{"Outcome": "error", "Detail": "Internal error. Check server logs."})
	}
}

func (h *devAuthHandlers) handleDeviceLookup(w http.ResponseWriter, r *http.Request) {
	ident, err := adminIdentity(r, h.svc)
	if err != nil {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "")
		return
	}
	userCode := r.URL.Query().Get("user_code")
	if userCode == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "user_code required")
		return
	}
	res, err := h.svc.LookupDeviceApproval(r.Context(), userCode, ident)
	if err != nil {
		writeDeviceApprovalError(w, h.logger, "device_lookup_failed", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user_code":       res.UserCode,
		"expires_at":      res.ExpiresAt,
		"quota_bytes":     res.QuotaBytes,
		"used_bytes":      res.UsedBytes,
		"remaining_bytes": res.RemainingBytes,
	})
}

func (h *devAuthHandlers) handleJSONApprove(w http.ResponseWriter, r *http.Request, ident devauth.Identity) {
	if h.allocations == nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	var body struct {
		UserCode     string `json:"user_code"`
		SizeBytes    int64  `json:"size_bytes,omitempty"`
		AllocationID string `json:"allocation_id,omitempty"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "")
		return
	}
	if body.UserCode == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "user_code required")
		return
	}
	hasNew := body.SizeBytes > 0
	hasReuse := body.AllocationID != ""
	if hasNew == hasReuse {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request",
			"exactly one of size_bytes or allocation_id is required")
		return
	}

	var allocation allocations.Allocation
	if hasReuse {
		allocID, err := parseUUIDParam(body.AllocationID)
		if err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "allocation_id must be a uuid")
			return
		}
		a, err := h.allocations.GetForUser(r.Context(), allocID, ident.UserID)
		switch {
		case errors.Is(err, allocations.ErrNotFound), errors.Is(err, allocations.ErrWrongUser):
			writeOAuthError(w, http.StatusNotFound, "not_found", "")
			return
		case errors.Is(err, allocations.ErrRevoked):
			writeOAuthError(w, http.StatusGone, "revoked", "")
			return
		case err != nil:
			h.logger.Error("device_allocation_lookup_failed", "error", err, "allocation_id", body.AllocationID)
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
			return
		}
		allocation = a
		h.logger.Info("device_allocation_reused", "user_id", uuidString(ident.UserID), "allocation_id", body.AllocationID)
	} else {
		a, err := h.allocations.Allocate(r.Context(), ident.UserID, body.SizeBytes)
		if err != nil {
			if errors.Is(err, allocations.ErrQuotaExceeded) {
				writeOAuthError(w, http.StatusUnprocessableEntity, "quota_exceeded", "")
				return
			}
			h.logger.Error("device_allocation_failed", "error", err)
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
			return
		}
		allocation = a
	}

	if err := h.svc.ApproveByUserCodeWithAllocation(r.Context(), body.UserCode, ident, allocation.ID); err != nil {
		if !hasReuse {
			if revokeErr := h.allocations.Revoke(r.Context(), allocation.ID, ident.UserID); revokeErr != nil {
				h.logger.Error("device_allocation_revoke_after_approval_failure_failed",
					"error", revokeErr, "allocation_id", uuidString(allocation.ID))
			}
		}
		writeDeviceApprovalError(w, h.logger, "device_approval_failed", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":        "approved",
		"allocation_id": uuidString(allocation.ID),
		"size_bytes":    allocation.SizeBytes,
	})
}

func writeDeviceApprovalError(w http.ResponseWriter, logger *slog.Logger, logEvent string, err error) {
	switch {
	case errors.Is(err, devauth.ErrUserCodeUnknown):
		writeOAuthError(w, http.StatusNotFound, "unknown_user_code", "")
	case errors.Is(err, devauth.ErrUserCodeExpired):
		writeOAuthError(w, http.StatusGone, "expired_user_code", "")
	case errors.Is(err, devauth.ErrUserCodeAlreadyResolved):
		writeOAuthError(w, http.StatusConflict, "already_resolved", "")
	default:
		logger.Error(logEvent, "error", err)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
	}
}

// --- helpers ---

func adminIdentity(r *http.Request, svc *devauth.Service) (devauth.Identity, error) {
	c, err := r.Cookie(devauth.AdminSessionCookie)
	if err != nil {
		return devauth.Identity{}, err
	}
	return svc.AuthenticateAdminSession(r.Context(), c.Value)
}

// adminOrBearerIdentity accepts either the dashboard cookie (browser callers)
// or a device-flow bearer token (CLI callers). Used by endpoints both surfaces
// hit — currently /api/allocations/{id}/usage.
func adminOrBearerIdentity(r *http.Request, svc *devauth.Service) (devauth.Identity, error) {
	if c, err := r.Cookie(devauth.AdminSessionCookie); err == nil {
		return svc.AuthenticateAdminSession(r.Context(), c.Value)
	}
	return svc.AuthenticateBearer(r.Context(), r.Header.Get("Authorization"))
}

func (h *devAuthHandlers) setAdminCookie(w http.ResponseWriter, r *http.Request, value string, maxAge int) {
	http.SetCookie(w, h.adminCookie(r, value, maxAge))
}

func (h *devAuthHandlers) adminCookie(r *http.Request, value string, maxAge int) *http.Cookie {
	c := &http.Cookie{
		Name:     devauth.AdminSessionCookie,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	}
	if h.cookieDomain != "" {
		c.Domain = h.cookieDomain
	}
	return c
}

func readDeviceCodeParam(r *http.Request) (string, error) {
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "application/json") {
		var body struct {
			DeviceCode string `json:"device_code"`
			GrantType  string `json:"grant_type"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			return "", fmt.Errorf("invalid json body: %w", err)
		}
		if body.DeviceCode == "" {
			return "", errors.New("device_code required")
		}
		return body.DeviceCode, nil
	}
	if err := r.ParseForm(); err != nil {
		return "", fmt.Errorf("parse form: %w", err)
	}
	dc := r.PostFormValue("device_code")
	if dc == "" {
		return "", errors.New("device_code required")
	}
	return dc, nil
}

func bearerToken(header string) string {
	const prefix = "Bearer "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(header[len(prefix):])
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeOAuthError(w http.ResponseWriter, status int, code, desc string) {
	body := map[string]any{"error": code}
	if desc != "" {
		body["error_description"] = desc
	}
	writeJSON(w, status, body)
}

func writeAdminAuthRequired(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`<!doctype html><meta charset="utf-8"><title>orlop-control</title>
<p>Admin session required. See <code>docs/control-plane-runbook.md</code> for how to seed one with <code>orlop-control user seed</code>.</p>
`))
}

// clientIP returns a rate-limit key derived from the connecting peer.
// chi's RealIP middleware rewrites r.RemoteAddr to the X-Forwarded-For
// chain head when running behind a trusted proxy, so this is sufficient.
func clientIP(r *http.Request) string {
	addr := r.RemoteAddr
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		return addr[:i]
	}
	return addr
}

func isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); strings.EqualFold(proto, "https") {
		return true
	}
	return false
}

// verificationURI returns the URL the device-code flow tells the user to
// open in their browser. Prefers ORLOP_DASHBOARD_URL (the Vercel-hosted
// dashboard at example.com/device) when set; falls back to the control plane's
// own /device template for self-hosted / pre-DNS deploys.
func verificationURI(r *http.Request) string {
	if dash := strings.TrimRight(os.Getenv("ORLOP_DASHBOARD_URL"), "/"); dash != "" {
		return dash + "/device"
	}
	return controlPlaneURL(r) + "/device"
}

func controlPlaneURL(r *http.Request) string {
	scheme := "http"
	if isHTTPS(r) {
		scheme = "https"
	}
	host := r.Host
	if host == "" {
		host = "localhost"
	}
	return scheme + "://" + host
}

var devicePageTpl = template.Must(template.New("device").Parse(`<!doctype html>
<meta charset="utf-8">
<title>Approve device</title>
<style>body{font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem}
input,button{font-size:1rem;padding:.5rem}label{display:block;margin:1rem 0 .25rem}
form{display:flex;flex-direction:column;gap:.5rem}.row{display:flex;gap:.5rem}</style>
<h1>Approve a device</h1>
<p>Enter the code displayed by the CLI (e.g. <code>ORL-K7Q9</code>).</p>
<form method="post" action="/device/approve">
  <label for="user_code">User code</label>
  <input id="user_code" name="user_code" autocomplete="off" autofocus required>
  <div class="row">
    <button type="submit" name="action" value="approve">Approve</button>
    <button type="submit" name="action" value="deny">Deny</button>
  </div>
</form>
`))

var approveResultTpl = template.Must(template.New("approveresult").Parse(`<!doctype html>
<meta charset="utf-8">
<title>{{.Outcome}}</title>
<style>body{font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem}</style>
<h1>{{.Outcome}}</h1>
<p>{{.Detail}}</p>
<p><a href="/device">Back</a></p>
`))
