package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/go-chi/chi/v5"
)

// agentIDRe accepts the agent ids orlop-control-plane mints (UUIDs) plus the
// same shape tenantIDRe allows, and rejects path-traversal / special-char
// input. The charset matters for purge: every allowed char is literal in a
// LIKE pattern except '_' , which escapeLike handles.
var agentIDRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_-]{0,62}$`)

// agentPurgeResult is what purgeAgentSubtree reports back to the handler.
type agentPurgeResult struct {
	ManifestsDeleted   int64  `json:"manifests_deleted"`
	JournalRowsDeleted int64  `json:"journal_rows_deleted"`
	ChunkRowsDeleted   int64  `json:"chunk_rows_deleted"`
	BytesFreed         uint64 `json:"bytes_freed"`
}

type purgeAgentResponse struct {
	TenantID string `json:"tenant_id"`
	AgentID  string `json:"agent_id"`
	agentPurgeResult
}

// purgeAgentData erases one agent's subtree from a tenant's store
// (DELETE /control/tenants/{id}/agents/{agentID}). An agent's data is the
// `/<agentID>` prefix inside the per-user tenant: manifest rows, dir entries,
// symlinks, and journal rows under that prefix, plus the chunk files that
// drop to refcount 0 once those manifests are gone. Chunks still referenced
// by another agent's manifests (content-addressed dedup) survive.
//
// Idempotent: purging an agent with no data (or re-purging) returns 200 with
// zero counts. An unknown tenant returns 404 — the caller treats that as
// already-gone (the whole tenant dir was unregistered).
func (s *serverState) purgeAgentData(w http.ResponseWriter, r *http.Request) {
	tenantID := chi.URLParam(r, "id")
	if !tenantIDRe.MatchString(tenantID) {
		writeJSONError(w, http.StatusBadRequest, "invalid_tenant_id", "tenant_id must match ^[A-Za-z0-9_][A-Za-z0-9_-]{0,62}$")
		return
	}
	agentID := chi.URLParam(r, "agentID")
	if !agentIDRe.MatchString(agentID) {
		writeJSONError(w, http.StatusBadRequest, "invalid_agent_id", "agent_id must match ^[A-Za-z0-9_][A-Za-z0-9_-]{0,62}$")
		return
	}

	tenant, ok := s.tenant(tenantID)
	if !ok {
		writeJSONError(w, http.StatusNotFound, "not_found", "tenant is not registered")
		return
	}

	result, err := purgeAgentSubtree(tenant, agentID)
	if err != nil {
		s.logger.Error("agent purge failed", "tenant_id", tenantID, "agent_id", agentID, "error", err)
		writeJSONError(w, http.StatusInternalServerError, "purge_failed", err.Error())
		return
	}

	count := uint64(result.ManifestsDeleted)
	s.audit.Record(AuditRecord{
		Event:      "agent_data_purged",
		TenantID:   tenantID,
		Allowed:    true,
		Command:    "orlop-server",
		Count:      &count,
		BytesFreed: &result.BytesFreed,
	})
	s.logger.Info("agent purge complete",
		"tenant_id", tenantID, "agent_id", agentID,
		"manifests_deleted", result.ManifestsDeleted,
		"journal_rows_deleted", result.JournalRowsDeleted,
		"chunk_rows_deleted", result.ChunkRowsDeleted,
		"bytes_freed", result.BytesFreed,
	)

	writeJSON(w, http.StatusOK, purgeAgentResponse{
		TenantID:         tenantID,
		AgentID:          agentID,
		agentPurgeResult: result,
	})
}

// purgeAgentSubtree deletes everything under "/"+agentID in the tenant's
// routes.db, then immediately sweeps the chunk files that the deletion left
// at refcount 0.
//
// Phase 1 (one transaction): read the doomed manifests' chunk lists, apply
// the negative refcount delta, and delete manifest / dir_entries / symlinks /
// session_journal rows under the prefix. This is the same refcount bookkeeping
// a ManifestStore.Delete performs, batched.
//
// Phase 2 (per-hash CAS, mirrors gcLoop.deleteGCBatch): for each hash the
// purge touched, delete its chunks row only if refcount is still 0, then
// unlink the file. Re-asserting `refcount = 0` in the DELETE means a
// concurrent manifest write that re-referenced the hash keeps its chunk —
// the same protection the background GC relies on. Unlink runs outside the
// transaction; a crash in between leaves an orphan file, exactly the orphan
// class the GC comment already documents.
func purgeAgentSubtree(t *tenantState, agentID string) (agentPurgeResult, error) {
	var result agentPurgeResult
	prefix := "/" + agentID
	likePrefix := escapeLike(prefix) + "/%"
	db := t.db.DB()

	tx, err := db.Begin()
	if err != nil {
		return result, err
	}
	defer func() { _ = tx.Rollback() }()

	// Collect the chunk references of every manifest under the prefix.
	rows, err := tx.Query(
		`select chunks from manifests where path = ? or path like ? escape '\'`,
		prefix, likePrefix,
	)
	if err != nil {
		return result, fmt.Errorf("select doomed manifests: %w", err)
	}
	delta := make(map[[HashLen]byte]int)
	for rows.Next() {
		var blob []byte
		if err := rows.Scan(&blob); err != nil {
			rows.Close()
			return result, err
		}
		refs, err := unpackChunks(blob)
		if err != nil {
			rows.Close()
			return result, fmt.Errorf("unpack doomed manifest: %w", err)
		}
		for _, ref := range refs {
			delta[ref.Hash]--
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return result, err
	}

	if err := applyChunkRefDelta(tx, delta); err != nil {
		return result, err
	}

	res, err := tx.Exec(
		`delete from manifests where path = ? or path like ? escape '\'`,
		prefix, likePrefix,
	)
	if err != nil {
		return result, fmt.Errorf("delete manifests: %w", err)
	}
	result.ManifestsDeleted, _ = res.RowsAffected()

	if _, err := tx.Exec(
		`delete from dir_entries
		  where (parent = '/' and name = ?)
		     or parent = ?
		     or parent like ? escape '\'`,
		agentID, prefix, likePrefix,
	); err != nil {
		return result, fmt.Errorf("delete dir_entries: %w", err)
	}

	if _, err := tx.Exec(
		`delete from symlinks where path = ? or path like ? escape '\'`,
		prefix, likePrefix,
	); err != nil {
		return result, fmt.Errorf("delete symlinks: %w", err)
	}

	// Journal rows under the prefix are unrevertable once the manifests are
	// gone; dropping them keeps the (revoked) allocation's history from
	// resurfacing in merged-feed queries.
	jres, err := tx.Exec(
		`delete from session_journal where path = ? or path like ? escape '\'`,
		prefix, likePrefix,
	)
	if err != nil {
		return result, fmt.Errorf("delete journal rows: %w", err)
	}
	result.JournalRowsDeleted, _ = jres.RowsAffected()

	if err := tx.Commit(); err != nil {
		return result, err
	}

	// Phase 2: immediate targeted sweep of the hashes this purge released.
	deleted, err := deletePurgedChunkRows(db, delta)
	if err != nil {
		return result, err
	}
	result.ChunkRowsDeleted = int64(len(deleted))
	for _, hash := range deleted {
		if p, perr := t.chunks.Path(hash[:]); perr == nil {
			if fi, serr := os.Stat(p); serr == nil {
				result.BytesFreed += uint64(fi.Size())
			}
		}
		if err := t.chunks.Delete(hash[:]); err != nil {
			// Orphan file; tolerable, same class the GC loop logs-and-continues on.
			continue
		}
	}
	return result, nil
}

// deletePurgedChunkRows removes the chunks rows for the given hashes when
// (and only when) their refcount is still 0 at delete time, returning the
// hashes whose rows were actually deleted. Same CAS shape as deleteGCBatch.
func deletePurgedChunkRows(db *sql.DB, delta map[[HashLen]byte]int) ([][HashLen]byte, error) {
	if len(delta) == 0 {
		return nil, nil
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.Prepare(`delete from chunks where hash = ? and refcount = 0`)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	deleted := make([][HashLen]byte, 0, len(delta))
	for hash := range delta {
		res, err := stmt.Exec(hash[:])
		if err != nil {
			return nil, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			deleted = append(deleted, hash)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return deleted, nil
}

// escapeLike escapes the SQLite LIKE wildcards in s so it can be used as a
// literal prefix with `LIKE ? ESCAPE '\'`.
func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}
