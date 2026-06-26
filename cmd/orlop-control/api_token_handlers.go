package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/db/sqlcdb"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/devauth"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/tokens"
)

const apiTokenNameMaxLen = 50

// apiTokenHandlers serves the API-token routes for issuing, listing, and
// revoking long-lived API tokens. Authenticates the caller as either the
// dashboard admin-session cookie (browser) or a device-flow Bearer token
// (CLI), via adminOrBearerIdentity().
//
// Public path is /api/v1/tokens; the production Caddy is configured with
// `handle_path /api/*` which strips the `/api` prefix before forwarding,
// so the routes registered here must use the bare `/v1/...` form.
type apiTokenHandlers struct {
	logger  *slog.Logger
	devAuth *devauth.Service
	queries *sqlcdb.Queries
	// ttl, when > 0, sets an expiry on newly minted tokens. 0 = never expires
	// (the historical default). Configured via ORLOP_API_TOKEN_TTL.
	ttl time.Duration
}

func newAPITokenHandlers(logger *slog.Logger, svc *devauth.Service, q *sqlcdb.Queries, ttl time.Duration) *apiTokenHandlers {
	return &apiTokenHandlers{logger: logger, devAuth: svc, queries: q, ttl: ttl}
}

// mountAPITokens registers token routes at the post-Caddy-strip path
// `/v1/tokens`. The public-facing URL is `/api/v1/tokens`; Caddy's
// `handle_path /api/*` strips the prefix before forwarding.
func mountAPITokens(r chi.Router, h *apiTokenHandlers) {
	r.Post("/v1/tokens", h.handleCreate)
	r.Get("/v1/tokens", h.handleList)
	r.Delete("/v1/tokens/{id}", h.handleRevoke)
}

type createTokenRequest struct {
	Name string `json:"name"`
}

type createTokenResponse struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Prefix    string    `json:"prefix"`
	CreatedAt time.Time `json:"created_at"`
	Token     string    `json:"token"` // raw token — shown once, never returned again
}

func (h *apiTokenHandlers) handleCreate(w http.ResponseWriter, r *http.Request) {
	ident, err := adminOrBearerIdentity(r, h.devAuth)
	if err != nil {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "")
		return
	}

	var req createTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "malformed body")
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" || len(name) > apiTokenNameMaxLen {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request",
			"name must be 1..50 chars")
		return
	}

	tok, err := tokens.Generate()
	if err != nil {
		h.logger.Error("api_token_generate_failed", "error", err)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}

	var expiresAt pgtype.Timestamptz
	if h.ttl > 0 {
		expiresAt = pgtype.Timestamptz{Time: time.Now().Add(h.ttl), Valid: true}
	}
	row, err := h.queries.CreateAPIToken(r.Context(), sqlcdb.CreateAPITokenParams{
		UserID:    ident.UserID,
		Name:      name,
		TokenHash: tok.Hash,
		Prefix:    tok.Prefix,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		h.logger.Error("api_token_create_failed", "error", err, "user_id", uuidString(ident.UserID))
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}

	h.logger.Info("api_token_created",
		"user_id", uuidString(ident.UserID),
		"token_id", uuidString(row.ID),
		"prefix", row.Prefix,
		"name", row.Name)

	writeJSON(w, http.StatusCreated, createTokenResponse{
		ID:        uuidString(row.ID),
		Name:      row.Name,
		Prefix:    row.Prefix,
		CreatedAt: row.CreatedAt.Time,
		Token:     tok.Raw,
	})
}

// listTokenItem is the per-row shape returned by handleList. It omits
// the raw token, the stored hash, and revoked_at — the list is the
// caller's view of their active tokens, not a credential surface.
type listTokenItem struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

func (h *apiTokenHandlers) handleList(w http.ResponseWriter, r *http.Request) {
	ident, err := adminOrBearerIdentity(r, h.devAuth)
	if err != nil {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "")
		return
	}
	rows, err := h.queries.ListAPITokensByUser(r.Context(), ident.UserID)
	if err != nil {
		h.logger.Error("api_token_list_failed", "error", err, "user_id", uuidString(ident.UserID))
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	out := make([]listTokenItem, 0, len(rows))
	for _, row := range rows {
		item := listTokenItem{
			ID:        uuidString(row.ID),
			Name:      row.Name,
			Prefix:    row.Prefix,
			CreatedAt: row.CreatedAt.Time,
		}
		if row.LastUsedAt.Valid {
			t := row.LastUsedAt.Time
			item.LastUsedAt = &t
		}
		out = append(out, item)
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *apiTokenHandlers) handleRevoke(w http.ResponseWriter, r *http.Request) {
	ident, err := adminOrBearerIdentity(r, h.devAuth)
	if err != nil {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "")
		return
	}

	var id pgtype.UUID
	if err := id.Scan(chi.URLParam(r, "id")); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "id must be a uuid")
		return
	}

	// Confirm the token exists AND belongs to the authenticated user.
	// Returns 404 (not 403) when the row is missing or belongs to a different
	// user, to avoid leaking which token IDs exist.
	row, err := h.queries.GetAPITokenByID(r.Context(), id)
	if err != nil || row.UserID != ident.UserID {
		writeOAuthError(w, http.StatusNotFound, "not_found", "")
		return
	}

	if err := h.queries.RevokeAPIToken(r.Context(), sqlcdb.RevokeAPITokenParams{
		ID: id, UserID: ident.UserID,
	}); err != nil {
		h.logger.Error("api_token_revoke_failed", "error", err, "id", uuidString(id), "user_id", uuidString(ident.UserID))
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}

	h.logger.Info("api_token_revoked",
		"user_id", uuidString(ident.UserID),
		"token_id", uuidString(id),
		"prefix", row.Prefix,
		"name", row.Name)

	w.WriteHeader(http.StatusNoContent)
}
