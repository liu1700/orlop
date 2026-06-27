package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/devauth"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/tokens"
)

type devAuthHandlers struct {
	svc          *devauth.Service
	logger       *slog.Logger
	cookieDomain string
}

func newDevAuthHandlers(logger *slog.Logger, svc *devauth.Service, cookieDomain string) *devAuthHandlers {
	return &devAuthHandlers{
		svc:          svc,
		logger:       logger,
		cookieDomain: cookieDomain,
	}
}

// mountAdminSession registers the admin-session cookie bootstrap routes.
//   - GET /admin/session?token=TOK turns a seed admin_session token (printed by
//     `orlop-control user seed`) into the orlop_admin_session cookie.
//   - POST /auth/logout clears the cookie.
func mountAdminSession(r chi.Router, h *devAuthHandlers) {
	r.Post("/auth/logout", h.handleLogout)
	r.Get("/admin/session", h.handleAdminSession)
}

// apiTokenTouchInterval is the minimum gap between writes of api_tokens.last_used_at.
// Reduces write amplification for high-frequency agents while keeping the timestamp
// fresh enough to be useful in the dashboard's "last used" column.
const apiTokenTouchInterval = 60 * time.Second

// RequireEnrollBearer returns middleware for the /agent/enroll route. It
// resolves Identity from the Authorization header and stores it in the request
// context.
//
// Two token shapes are accepted; both go through bearerToken() so they
// recognise the same header forms (case-insensitive "Bearer", trailing
// whitespace tolerated):
//   - "orlop_<base32>": long-lived API token issued via /v1/tokens.
//     Looked up by SHA-256 hash; rejected if the row is missing,
//     revoked, or belongs to a suspended user or suspended tenant.
//   - everything else: a per-pod agent-scoped enroll token
//     (devauth.PurposeAgentEnroll, minted by IssueAgentEnrollToken),
//     validated by devauth.Service.
func RequireEnrollBearer(svc *devauth.Service, store storage.APITokenStore) func(http.Handler) http.Handler {
	return requireBearer(store, svc.AuthenticateEnrollBearer)
}

// requireBearer is the shared body for the bearer middleware. authenticate
// validates the OAuth-style (non-"orlop_") token and resolves an Identity; the
// API-token ("orlop_") shape is handled here.
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

// handleAdminSession turns a seed admin_session token into the
// orlop_admin_session cookie. This is the runbook bootstrap: the operator pastes
// the URL printed by `orlop-control user seed` (GET /admin/session?token=TOK)
// into a browser; we validate the token, set the HttpOnly cookie, and redirect
// to the dashboard root.
func (h *devAuthHandlers) handleAdminSession(w http.ResponseWriter, r *http.Request) {
	tok := r.URL.Query().Get("token")
	if tok == "" {
		writeAdminAuthRequired(w)
		return
	}
	if _, err := h.svc.AuthenticateAdminSession(r.Context(), tok); err != nil {
		writeAdminAuthRequired(w)
		return
	}
	h.setAdminCookie(w, r, tok, int(devauth.AdminSessionTTL.Seconds()))
	http.Redirect(w, r, "/", http.StatusFound)
}

// --- helpers ---

func adminIdentity(r *http.Request, svc *devauth.Service) (devauth.Identity, error) {
	c, err := r.Cookie(devauth.AdminSessionCookie)
	if err != nil {
		return devauth.Identity{}, err
	}
	return svc.AuthenticateAdminSession(r.Context(), c.Value)
}

// adminOrBearerIdentity resolves the dashboard cookie. It is named for the
// historical CLI-bearer fallback that is now retired; the device-flow bearer
// path is gone, so only the admin-session cookie is accepted.
func adminOrBearerIdentity(r *http.Request, svc *devauth.Service) (devauth.Identity, error) {
	return adminIdentity(r, svc)
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

func isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); strings.EqualFold(proto, "https") {
		return true
	}
	return false
}
