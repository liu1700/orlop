package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/websocket"
)

// journalWSKeepalive is how often the WS handler emits a ping frame when
// no journal entries flow. Browsers and intermediate proxies tend to GC
// idle WS connections after ~60s; 30s keeps the path warm with margin.
// A var so tests can shorten it.
var journalWSKeepalive = 30 * time.Second

// WS event tags — wire-stable strings the TS client switches on.
// wsEventReverted is reserved for a future server-side "this row was
// reverted by someone else" push (spec §4.5); not emitted today but
// pinned here so a typo can't sneak in when it ships.
const (
	wsEventAppended = "appended"
	wsEventReverted = "reverted"
	wsEventPing     = "ping"
)

// journalWSUpgrader controls the WS upgrade for /api/v1/journal/stream.
// CheckOrigin returns true because Caddy is the public-facing edge in
// production and applies CORS there; running an additional origin gate
// here would duplicate that policy and break local dev (file:// origins
// produce empty Origin headers).
var journalWSUpgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

// journalWSFrame is the JSON shape sent over the WS (text frames).
type journalWSFrame struct {
	Event string            `json:"event"`
	Entry *journalEntryJSON `json:"entry,omitempty"`
}

// handleJournalStream upgrades GET /v1/journal/stream to a WebSocket and
// pushes live journal entries from orlop-server's SSE pipe.
//
// Auth mirrors handleJournal: cookie or bearer + allocation ownership.
//
// Wire protocol (text frames, server→client only):
//
//	{"event":"appended","entry":{...}}
//	{"event":"ping"}
//
// The client never sends after the upgrade; readPumpDiscard runs only so
// a closed/aborted client causes ReadMessage to error and triggers shutdown.
func (h *journalHandlers) handleJournalStream(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	allocationID := q.Get("allocation_id")
	if allocationID == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "allocation_id required")
		return
	}
	afterSeq, _ := strconv.ParseUint(q.Get("after_seq"), 10, 64)

	ident, err := adminOrBearerIdentity(r, h.devAuth)
	if err != nil {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "")
		return
	}
	allocUUID, err := parseUUIDParam(allocationID)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "allocation_id must be a uuid")
		return
	}
	if _, err := h.alloc.GetForUser(r.Context(), allocUUID, ident.UserID); err != nil {
		writeAllocOwnershipError(w, err)
		return
	}
	tenantID := ident.TenantID

	// Open the upstream SSE pipe BEFORE upgrading: if the server is
	// unreachable the client sees a clean HTTP error instead of an
	// immediate WS close after a successful 101.
	streamCtx, cancel := context.WithCancel(r.Context())
	defer cancel()

	upstream, err := h.querier.StreamJournal(streamCtx, tenantID, allocationID, afterSeq)
	if err != nil {
		writeOAuthError(w, http.StatusBadGateway, "stream_open_failed", "")
		return
	}

	conn, err := journalWSUpgrader.Upgrade(w, r, nil)
	if err != nil {
		// Upgrade wrote its own HTTP error already.
		return
	}
	defer conn.Close()

	// Client-side reader pump: we don't expect any frames from the browser
	// after the upgrade. ReadMessage blocks until the connection errors;
	// that error is the signal to tear down the stream.
	clientClosed := make(chan struct{})
	go func() {
		defer close(clientClosed)
		for {
			if _, _, err := conn.NextReader(); err != nil {
				return
			}
		}
	}()

	ticker := time.NewTicker(journalWSKeepalive)
	defer ticker.Stop()

	for {
		select {
		case entry, ok := <-upstream:
			if !ok {
				// Upstream closed (server-side EOF, error, ctx cancel).
				return
			}
			if err := writeWSFrame(conn, journalWSFrame{Event: wsEventAppended, Entry: &entry}); err != nil {
				return
			}
		case <-ticker.C:
			if err := writeWSFrame(conn, journalWSFrame{Event: wsEventPing}); err != nil {
				return
			}
		case <-clientClosed:
			return
		case <-r.Context().Done():
			return
		}
	}
}

func writeWSFrame(conn *websocket.Conn, frame journalWSFrame) error {
	buf, err := json.Marshal(frame)
	if err != nil {
		return err
	}
	// Bound the write to avoid stalling the whole goroutine on a stuck peer.
	_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return conn.WriteMessage(websocket.TextMessage, buf)
}
