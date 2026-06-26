package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
)

// streamKeepaliveInterval is how often the SSE handler writes a comment frame
// when no journal entries are flowing. Idle mTLS connections crossing NATs
// and load balancers benefit from periodic bytes; 30s matches the spec.
// A var (not const) so tests can shorten it.
var streamKeepaliveInterval = 30 * time.Second

// controlJournalResponse is the JSON body returned by GET /control/tenants/{id}/journal.
type controlJournalResponse struct {
	Entries    []controlJournalEntry `json:"entries"`
	NextCursor string                `json:"next_cursor,omitempty"`
}

type controlJournalEntry struct {
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

// tenantJournalQuery handles GET /control/tenants/{id}/journal.
// It is protected by controlPlaneOnlyMiddleware.
//
// Query params:
//   - allocation_id (optional): filter to a single allocation; empty returns merged feed
//   - limit          (optional): default 50, capped at 200
//   - cursor         (optional): opaque keyset pagination cursor (next_cursor from a prior page)
func (s *serverState) tenantJournalQuery(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if !tenantIDRe.MatchString(id) {
		writeJSONError(w, http.StatusBadRequest, "invalid_tenant_id",
			"tenant_id must match ^[A-Za-z0-9_][A-Za-z0-9_-]{0,62}$")
		return
	}
	ts, ok := s.tenant(id)
	if !ok {
		writeJSONError(w, http.StatusNotFound, "tenant_not_found", "")
		return
	}

	q := r.URL.Query()
	allocationID := q.Get("allocation_id")

	rawLimit, _ := strconv.ParseUint(q.Get("limit"), 10, 32)
	limit := uint32(rawLimit)

	cursor := q.Get("cursor")

	// after_seq is the browser's reconnect/backfill cursor (spec §4.4).
	// When set, returns ascending-seq rows with seq > after_seq for the given
	// allocation and ignores the keyset cursor. Requires allocation_id (the
	// QueryAfterSeq helper rejects empty allocations because backfill is a
	// per-allocation operation).
	afterSeqRaw := q.Get("after_seq")
	if afterSeqRaw != "" {
		if allocationID == "" {
			writeJSONError(w, http.StatusBadRequest, "missing_allocation_id",
				"allocation_id is required when after_seq is set")
			return
		}
		afterSeq, _ := strconv.ParseUint(afterSeqRaw, 10, 64)
		// QueryAfterSeq honors the limit now; default to 200 to match the
		// merged-feed cap. Pagination of after_seq is left for a future
		// iteration if a >200-row gap proves common.
		if limit == 0 {
			limit = 200
		}
		if limit > 200 {
			limit = 200
		}
		rows, err := ts.journal.QueryAfterSeq(allocationID, afterSeq, int(limit))
		if err != nil {
			s.logger.Error("tenant_journal_query_after_seq_failed",
				"error", err, "tenant_id", id, "allocation_id", allocationID)
			writeJSONError(w, http.StatusInternalServerError, "journal_failed", "")
			return
		}
		entries := make([]controlJournalEntry, 0, len(rows))
		for _, row := range rows {
			entries = append(entries, controlJournalEntry{
				SessionID:     row.SessionID,
				AllocationID:  row.AllocationID,
				Seq:           row.Seq,
				TsUnixMs:      row.TsUnixMs,
				Path:          row.Path,
				Op:            row.Op,
				AgentID:       row.AgentID,
				BeforeVersion: row.BeforeVersion,
				AfterVersion:  row.AfterVersion,
				RenameFrom:    row.RenameFrom,
				SizeBefore:    row.SizeBefore,
				SizeAfter:     row.SizeAfter,
			})
		}
		writeJSON(w, http.StatusOK, controlJournalResponse{Entries: entries})
		return
	}

	// For the merged feed (empty allocationID) we need all allocation IDs
	// recorded in this tenant's journal.
	var userAllocations []string
	if allocationID == "" {
		var err error
		userAllocations, err = ts.journal.ListAllocations()
		if err != nil {
			s.logger.Error("tenant_journal_list_allocations_failed",
				"error", err, "tenant_id", id)
			writeJSONError(w, http.StatusInternalServerError, "journal_failed", "")
			return
		}
	}

	rows, nextCursor, err := ts.journal.Query(allocationID, limit, cursor, userAllocations)
	if err != nil {
		s.logger.Error("tenant_journal_query_failed",
			"error", err, "tenant_id", id)
		writeJSONError(w, http.StatusInternalServerError, "journal_failed", "")
		return
	}

	entries := make([]controlJournalEntry, 0, len(rows))
	for _, row := range rows {
		entries = append(entries, controlJournalEntry{
			SessionID:     row.SessionID,
			AllocationID:  row.AllocationID,
			Seq:           row.Seq,
			TsUnixMs:      row.TsUnixMs,
			Path:          row.Path,
			Op:            row.Op,
			AgentID:       row.AgentID,
			BeforeVersion: row.BeforeVersion,
			AfterVersion:  row.AfterVersion,
			RenameFrom:    row.RenameFrom,
			SizeBefore:    row.SizeBefore,
			SizeAfter:     row.SizeAfter,
		})
	}

	writeJSON(w, http.StatusOK, controlJournalResponse{
		Entries:    entries,
		NextCursor: nextCursor,
	})
}

// tenantJournalStream handles GET /control/tenants/{id}/journal/stream.
// It is protected by controlPlaneOnlyMiddleware — orlop-control is the only
// caller; allocation ownership is verified there before this endpoint is hit.
//
// Query params:
//   - allocation_id (required): the allocation to subscribe to
//   - after_seq     (optional, default 0): catch-up watermark; rows with
//     seq > after_seq for the allocation are flushed before subscribing.
//
// Wire shape: text/event-stream, one `data: <controlJournalEntry-JSON>` frame
// per row, `: keepalive` comments every streamKeepaliveInterval.
func (s *serverState) tenantJournalStream(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if !tenantIDRe.MatchString(id) {
		writeJSONError(w, http.StatusBadRequest, "invalid_tenant_id",
			"tenant_id must match ^[A-Za-z0-9_][A-Za-z0-9_-]{0,62}$")
		return
	}
	ts, ok := s.tenant(id)
	if !ok {
		writeJSONError(w, http.StatusNotFound, "tenant_not_found", "")
		return
	}

	allocationID := r.URL.Query().Get("allocation_id")
	if allocationID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing_allocation_id",
			"allocation_id query parameter is required")
		return
	}
	afterSeq, _ := strconv.ParseUint(r.URL.Query().Get("after_seq"), 10, 64)

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSONError(w, http.StatusInternalServerError, "no_flusher",
			"response writer does not support flushing")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	// Catch up first, then subscribe. Order matters: subscribing first risks
	// delivering an entry that also lands in the catch-up query, producing
	// a duplicate. We track the highest seq sent during catch-up as a
	// dedup watermark for subsequent live frames (per-session seqs are
	// monotonic and the (allocation,seq) pair is unique under the table's
	// (session_id, seq) primary key).
	// Bound the worst-case bulk dump (tab backgrounded for hours, or
	// after_seq=0 from a fresh page that hasn't run the GET yet). The GET
	// path uses the same 50-row default for plain reads.
	catchUp, err := ts.journal.QueryAfterSeq(allocationID, afterSeq, 50)
	if err != nil {
		s.logger.Error("tenant_journal_stream_catchup_failed",
			"error", err, "tenant_id", id, "allocation_id", allocationID)
		return
	}
	highestSentSeq := afterSeq
	for _, row := range catchUp {
		if err := writeSSEEntry(w, row); err != nil {
			return
		}
		if row.Seq > highestSentSeq {
			highestSentSeq = row.Seq
		}
	}
	flusher.Flush()

	ch, unsub := ts.journal.Subscribe(r.Context(), allocationID)
	defer unsub()

	ticker := time.NewTicker(streamKeepaliveInterval)
	defer ticker.Stop()

	for {
		select {
		case entry, ok := <-ch:
			if !ok {
				return
			}
			if entry.Seq <= highestSentSeq {
				continue
			}
			if err := writeSSEEntry(w, journalQueryRowFromEntry(entry)); err != nil {
				return
			}
			flusher.Flush()
			highestSentSeq = entry.Seq
		case <-ticker.C:
			// SSE comment frame: starts with ":" and is ignored by parsers,
			// but the bytes keep the underlying TCP connection warm.
			if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

// writeSSEEntry serialises one journal row as a single SSE `data:` frame in
// the same JSON shape as controlJournalEntry (used by tenantJournalQuery), so
// SSE consumers and one-shot GET consumers see identical entry envelopes.
func writeSSEEntry(w http.ResponseWriter, row JournalQueryRow) error {
	entry := controlJournalEntry{
		SessionID:     row.SessionID,
		AllocationID:  row.AllocationID,
		Seq:           row.Seq,
		TsUnixMs:      row.TsUnixMs,
		Path:          row.Path,
		Op:            row.Op,
		AgentID:       row.AgentID,
		BeforeVersion: row.BeforeVersion,
		AfterVersion:  row.AfterVersion,
		RenameFrom:    row.RenameFrom,
		SizeBefore:    row.SizeBefore,
		SizeAfter:     row.SizeAfter,
	}
	buf, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "data: %s\n\n", buf); err != nil {
		return err
	}
	return nil
}

// journalQueryRowFromEntry lifts a pub/sub-delivered SessionJournalEntry into
// the JournalQueryRow shape so writeSSEEntry can emit it through the same
// path as catch-up rows. SizeAfter is filled from the embedded before-manifest
// only when the op is delete (there is no live join here); the wire shape's
// SizeBefore mirrors what Query returns for delete/update/rename rows.
func journalQueryRowFromEntry(e SessionJournalEntry) JournalQueryRow {
	row := JournalQueryRow{
		SessionID:     e.SessionID,
		AllocationID:  e.AllocationID,
		Seq:           e.Seq,
		TsUnixMs:      e.TsUnixMs,
		Path:          e.Path,
		Op:            string(e.Op),
		AgentID:       e.AgentID,
		BeforeVersion: e.BeforeVersion,
		AfterVersion:  e.AfterVersion,
		RenameFrom:    e.RenameFrom,
	}
	if len(e.BeforeManifest) > 0 {
		if mf, decErr := decodeJournalManifest(e.Path, e.BeforeManifest); decErr == nil {
			v := mf.Size
			row.SizeBefore = &v
		}
	}
	return row
}
