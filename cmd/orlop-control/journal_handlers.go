package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/allocations"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/db"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/devauth"
)

// journalQuerier is the subset of the orlop-server journal API this handler
// needs. Defined as an interface so tests can inject a fake without standing
// up an mTLS server.
//
// QueryJournal returns entries (newest-first), the opaque next-page cursor
// ("" if no more pages), and an error. Pass "" as cursor for the first page.
// allocationID may be empty to return the merged feed across all of the
// caller's tenant's allocations. limit is already clamped by the caller.
//
// QueryJournalAfterSeq is the reconnect/backfill counterpart: ascending-seq
// rows with seq > afterSeq. allocationID is required.
//
// StreamJournal opens an SSE pipe to orlop-server. The returned channel
// delivers JournalEntryJSON until ctx is cancelled or the underlying body
// closes; the close-on-exit contract is the WS handler's signal to
// terminate.
//
// RevertPath issues a single (path, seq) revert. Ok=true on success;
// Ok=false carries a machine-readable conflict reason (see spec §3.4).
type journalQuerier interface {
	QueryJournal(ctx context.Context, tenantID, allocationID string, limit uint32, cursor string) ([]journalEntryJSON, string, error)
	QueryJournalAfterSeq(ctx context.Context, tenantID, allocationID string, limit uint32, afterSeq uint64) ([]journalEntryJSON, error)
	StreamJournal(ctx context.Context, tenantID, allocationID string, afterSeq uint64) (<-chan journalEntryJSON, error)
	RevertPath(ctx context.Context, tenantID, allocationID, sessionID, path string, seq uint64, force bool, agentID string) (revertResult, error)
}

// revertResult is the per-call outcome of RevertPath. Mirrors the wire shape
// of POST /api/v1/journal/revert (spec §3.1).
type revertResult struct {
	Ok       bool
	Conflict *revertConflict
}

// Conflict reason tokens — wire-stable, mirror the orlop-server side.
// Used as both response strings (when this layer synthesises a conflict)
// and input strings (when forwarding the server's response unchanged).
const (
	reasonNoJournalRow     = "no_journal_row"
	reasonConcurrentWriter = "concurrent_writer"
	reasonRevertBlocked    = "revert_blocked"
)

type revertConflict struct {
	Reason string
}

// journalEntryJSON is the per-row shape returned to the caller.
type journalEntryJSON struct {
	SessionID     string  `json:"session_id"`
	AllocationID  string  `json:"allocation_id"`
	Seq           uint64  `json:"seq"`
	TsUnixMs      int64   `json:"ts_unix_ms"`
	Path          string  `json:"path"`
	Op            string  `json:"op"`
	AgentID       string  `json:"agent_id"`
	BeforeVersion *uint64 `json:"before_version,omitempty"`
	AfterVersion  *uint64 `json:"after_version,omitempty"`
	RenameFrom    string  `json:"rename_from,omitempty"`
	SizeBefore    *uint64 `json:"size_before,omitempty"`
	SizeAfter     *uint64 `json:"size_after,omitempty"`
}

// journalResponseJSON is the envelope returned by GET /api/v1/journal.
type journalResponseJSON struct {
	Entries    []journalEntryJSON `json:"entries"`
	NextCursor string             `json:"next_cursor,omitempty"`
}

// journalHandlers serves GET /v1/journal (public path) / /api/v1/journal
// (Caddy-stripped path). Both cookie and bearer-token auth are accepted.
type journalHandlers struct {
	devAuth *devauth.Service
	alloc   *allocations.Service
	queries db.Store
	querier journalQuerier
}

func newJournalHandlers(svc *devauth.Service, alloc *allocations.Service, queries db.Store, q journalQuerier) *journalHandlers {
	return &journalHandlers{devAuth: svc, alloc: alloc, queries: queries, querier: q}
}

// mountJournal registers routes on both bare and /api-prefixed paths,
// matching the convention used by mountDashboard and mountAPITokens.
func mountJournal(r chi.Router, h *journalHandlers) {
	for _, prefix := range []string{"", "/api"} {
		r.Get(prefix+"/v1/journal", h.handleJournal)
		r.Post(prefix+"/v1/journal/revert", h.handleJournalRevert)
		r.Get(prefix+"/v1/journal/stream", h.handleJournalStream)
	}
}

func (h *journalHandlers) handleJournal(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	ident, err := adminOrBearerIdentity(r, h.devAuth)
	if err != nil {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "")
		return
	}

	allocationID := q.Get("allocation_id")

	limit, _ := strconv.ParseUint(q.Get("limit"), 10, 32)
	if limit == 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}

	cursor := q.Get("cursor")
	afterSeqRaw := q.Get("after_seq")

	// Ownership check: if the caller supplied a specific allocation_id,
	// verify they own it before forwarding to the querier. This prevents
	// cross-tenant journal reads.
	if allocationID != "" {
		allocUUID, err := parseUUIDParam(allocationID)
		if err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "allocation_id must be a uuid")
			return
		}
		if _, err := h.alloc.GetForUser(r.Context(), allocUUID, ident.UserID); err != nil {
			writeAllocOwnershipError(w, err)
			return
		}
	}

	// after_seq mode: ascending-seq backfill for the WS reconnect path
	// (spec §4.4). Requires allocation_id; ignores the keyset cursor.
	if afterSeqRaw != "" {
		if allocationID == "" {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "after_seq requires allocation_id")
			return
		}
		afterSeq, _ := strconv.ParseUint(afterSeqRaw, 10, 64)
		entries, err := h.querier.QueryJournalAfterSeq(r.Context(), ident.TenantID, allocationID, uint32(limit), afterSeq)
		if err != nil {
			writeOAuthError(w, http.StatusBadGateway, "journal_query_failed", "")
			return
		}
		if entries == nil {
			entries = []journalEntryJSON{}
		}
		writeJSON(w, http.StatusOK, journalResponseJSON{Entries: entries})
		return
	}

	entries, nextCursor, err := h.querier.QueryJournal(r.Context(), ident.TenantID, allocationID, uint32(limit), cursor)
	if err != nil {
		writeOAuthError(w, http.StatusBadGateway, "journal_query_failed", "")
		return
	}

	out := journalResponseJSON{
		Entries:    entries,
		NextCursor: nextCursor,
	}
	if out.Entries == nil {
		out.Entries = []journalEntryJSON{}
	}
	writeJSON(w, http.StatusOK, out)
}

// journalRevertRequest is the request body for POST /api/v1/journal/revert
// (spec §3.1). Singular path/seq; force defaults to false. SessionID pins
// the row the user clicked across the per-session seq numbering — two
// distinct rows in the same allocation can share a seq when a mount
// take-over starts a new session whose seqs restart from 1; without
// SessionID the revert can spuriously target the wrong row.
type journalRevertRequest struct {
	AllocationID string `json:"allocation_id"`
	SessionID    string `json:"session_id,omitempty"`
	Path         string `json:"path"`
	Seq          uint64 `json:"seq"`
	Force        bool   `json:"force,omitempty"`
}

// journalRevertResponseJSON mirrors the wire shape per spec §3.1: 200 always,
// `ok` distinguishes success/conflict, `conflict.reason` is the
// machine-readable enum the web layer maps to user-facing text (§3.4).
type journalRevertResponseJSON struct {
	Ok       bool                       `json:"ok"`
	Conflict *journalRevertConflictJSON `json:"conflict,omitempty"`
}

type journalRevertConflictJSON struct {
	Reason string `json:"reason"`
}

// handleJournalRevert serves POST /v1/journal/revert (and /api/v1/journal/revert
// via Caddy strip), authed by cookie/bearer; allocation ownership is verified.
//
// On success the response is 200 {ok:true}. Per-path conflicts (concurrent
// writer, no journal row, server-side block) return 200 with ok:false and a
// reason token. Auth/validation failures use 4xx with the writeOAuthError
// shape, identical to handleJournal.
func (h *journalHandlers) handleJournalRevert(w http.ResponseWriter, r *http.Request) {
	var body journalRevertRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid json body")
		return
	}
	if body.AllocationID == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "allocation_id required")
		return
	}
	if body.Path == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "path required")
		return
	}
	if body.Seq == 0 {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "seq required")
		return
	}

	ident, err := adminOrBearerIdentity(r, h.devAuth)
	if err != nil {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "")
		return
	}

	allocUUID, err := parseUUIDParam(body.AllocationID)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "allocation_id must be a uuid")
		return
	}
	if _, err := h.alloc.GetForUser(r.Context(), allocUUID, ident.UserID); err != nil {
		writeAllocOwnershipError(w, err)
		return
	}

	// Attribute the inverse row to the authenticated user. The agent_id
	// column is a free-form string in the journal; "user:<uuid>" makes it
	// sortable alongside other writes.
	agentID := "user:" + uuidString(ident.UserID)
	res, err := h.querier.RevertPath(r.Context(), ident.TenantID, body.AllocationID, body.SessionID, body.Path, body.Seq, body.Force, agentID)
	if err != nil {
		writeOAuthError(w, http.StatusBadGateway, "revert_failed", "")
		return
	}
	writeJSON(w, http.StatusOK, revertResultJSON(res))
}

func revertResultJSON(r revertResult) journalRevertResponseJSON {
	out := journalRevertResponseJSON{Ok: r.Ok}
	if r.Conflict != nil {
		out.Conflict = &journalRevertConflictJSON{Reason: r.Conflict.Reason}
	}
	return out
}

// writeAllocOwnershipError maps an allocations.Service lookup error into the
// canonical OAuth-shaped response. Collapses the three "user can't see this
// allocation" paths to 404 (don't leak that another user owns it) and
// 410 Gone for revoked-but-known allocations. Used by every journal
// handler that calls alloc.GetForUser.
func writeAllocOwnershipError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, allocations.ErrNotFound), errors.Is(err, allocations.ErrWrongUser):
		writeOAuthError(w, http.StatusNotFound, "not_found", "")
	case errors.Is(err, allocations.ErrRevoked):
		writeOAuthError(w, http.StatusGone, "revoked", "")
	default:
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
	}
}
