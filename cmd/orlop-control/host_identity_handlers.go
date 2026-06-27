package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/identity"
)

// Mode B (docs/design-identity.md §3): orlop-control verifies a host-issued,
// audience-pinned signed JWT and maps an allowlisted claim onto the tenant
// subject. This is the pluggable replacement for the deleted self-service
// login: the host owns the human; orlop verifies an assertion. The verifier is
// injected (identity.Verifier), so a deployment can drop in its own.

type hostIdentityCtxKey struct{}

// HostIdentityFromRequest returns the verified host identity placed in the
// request context by RequireHostIdentity.
func HostIdentityFromRequest(r *http.Request) (identity.Identity, bool) {
	id, ok := r.Context().Value(hostIdentityCtxKey{}).(identity.Identity)
	return id, ok
}

// RequireHostIdentity verifies the request's host assertion with v and stores
// the resolved identity in context. It fails closed: anything the verifier
// rejects is a 401, and a well-signed token whose tenant is not on the operator
// allowlist is a 403 (so a misconfigured-but-valid IdP cannot self-onboard).
func RequireHostIdentity(v identity.Verifier, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			info := identity.AuthInfo{
				Bearer: bearerToken(r.Header.Get("Authorization")),
				TLS:    r.TLS,
			}
			id, err := v.Verify(r.Context(), info)
			if err != nil {
				switch {
				case errors.Is(err, identity.ErrTenantNotAllowed):
					writeOAuthError(w, http.StatusForbidden, "access_denied", "tenant_not_allowed")
				case errors.Is(err, identity.ErrNoCredential):
					writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "")
				default:
					// Don't leak which check failed to the client; log for the operator.
					logger.Info("host_identity_rejected", "error", err)
					writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "")
				}
				return
			}
			ctx := context.WithValue(r.Context(), hostIdentityCtxKey{}, id)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// mountHostIdentity registers the Mode B introspection endpoint behind the
// host-identity middleware. GET /v1/whoami echoes the verified tenant subject —
// a concrete, dependency-free exercise of the seam end to end.
func mountHostIdentity(r chi.Router, mw func(http.Handler) http.Handler) {
	for _, prefix := range []string{"", "/api"} {
		r.With(mw).Get(prefix+"/v1/whoami", handleWhoami)
	}
}

func handleWhoami(w http.ResponseWriter, r *http.Request) {
	id, ok := HostIdentityFromRequest(r)
	if !ok {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant_id": id.TenantID,
		"subject":   id.Subject,
	})
}
