package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"lukechampine.com/blake3"
)

// putTestFile stores `data` as a single-chunk file at path for the given rig,
// registering the agent's root dir on first use. Returns the chunk hash.
func putTestFile(t *testing.T, rig *gcTestRig, agentID, path string, data []byte) [HashLen]byte {
	t.Helper()
	hash := blake3.Sum256(data)
	if _, err := rig.cs.Put(hash[:], data); err != nil {
		t.Fatalf("chunk put: %v", err)
	}
	if err := rig.tenant.manifests.RegisterDir("/", agentID); err != nil {
		t.Fatalf("register dir: %v", err)
	}
	mf := Manifest{
		Path: path, Size: uint64(len(data)), Mode: 0o644,
		Chunks: []ChunkRef{{Hash: hash, Offset: 0, Len: uint32(len(data))}},
	}
	if _, err := rig.tenant.manifests.Put(path, 0, mf, "", "", ""); err != nil {
		t.Fatalf("manifest put %s: %v", path, err)
	}
	return hash
}

func chunkFileExists(t *testing.T, rig *gcTestRig, hash [HashLen]byte) bool {
	t.Helper()
	p, err := rig.cs.Path(hash[:])
	if err != nil {
		t.Fatal(err)
	}
	_, err = os.Stat(p)
	return err == nil
}

func countRows(t *testing.T, rig *gcTestRig, query string, args ...any) int {
	t.Helper()
	var n int
	if err := rig.db.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatalf("count %q: %v", query, err)
	}
	return n
}

func TestPurgeAgentSubtreeErasesOnlyThatAgent(t *testing.T) {
	rig := newGCTestRig(t)

	shared := []byte("shared-content-across-agents")
	hashShared := putTestFile(t, rig, "agent-a", "/agent-a/shared.txt", shared)
	hashAOnly := putTestFile(t, rig, "agent-a", "/agent-a/only-a.txt", []byte("private to a"))
	// agent-b references the same content: dedup means one chunk, refcount 2.
	if h := putTestFile(t, rig, "agent-b", "/agent-b/shared.txt", shared); h != hashShared {
		t.Fatalf("expected dedup to reuse the same hash")
	}
	hashBOnly := putTestFile(t, rig, "agent-b", "/agent-b/only-b.txt", []byte("private to b"))

	// A journal row under agent-a's prefix (as a mount-session write would leave).
	if _, err := rig.db.Exec(
		`insert into session_journal (session_id, seq, path, op, ts_unix_ms, allocation_id)
		 values ('mount:dead', 1, '/agent-a/only-a.txt', 'create', 1, 'alloc-a')`,
	); err != nil {
		t.Fatal(err)
	}

	result, err := purgeAgentSubtree(rig.tenant, "agent-a")
	if err != nil {
		t.Fatalf("purge: %v", err)
	}

	if result.ManifestsDeleted != 2 {
		t.Errorf("manifests_deleted = %d, want 2", result.ManifestsDeleted)
	}
	if result.JournalRowsDeleted != 1 {
		t.Errorf("journal_rows_deleted = %d, want 1", result.JournalRowsDeleted)
	}
	if result.ChunkRowsDeleted != 1 {
		t.Errorf("chunk_rows_deleted = %d, want 1 (only the agent-a-private chunk)", result.ChunkRowsDeleted)
	}
	if result.BytesFreed != uint64(len("private to a")) {
		t.Errorf("bytes_freed = %d, want %d", result.BytesFreed, len("private to a"))
	}

	// agent-a's rows are gone; agent-b's are intact.
	if n := countRows(t, rig, `select count(*) from manifests where path like '/agent-a/%'`); n != 0 {
		t.Errorf("agent-a manifests remaining: %d", n)
	}
	if n := countRows(t, rig, `select count(*) from manifests where path like '/agent-b/%'`); n != 2 {
		t.Errorf("agent-b manifests = %d, want 2", n)
	}
	if n := countRows(t, rig, `select count(*) from dir_entries where parent = '/' and name = 'agent-a'`); n != 0 {
		t.Errorf("agent-a root dir_entry still present")
	}
	if n := countRows(t, rig, `select count(*) from session_journal where path like '/agent-a/%'`); n != 0 {
		t.Errorf("agent-a journal rows remaining: %d", n)
	}

	// The shared chunk survives with refcount 1; agent-a's private chunk file
	// is unlinked; agent-b's private chunk untouched.
	if !chunkFileExists(t, rig, hashShared) {
		t.Errorf("shared chunk file was deleted but agent-b still references it")
	}
	if n := countRows(t, rig, `select refcount from chunks where hash = ?`, hashShared[:]); n != 1 {
		t.Errorf("shared chunk refcount = %d, want 1", n)
	}
	if chunkFileExists(t, rig, hashAOnly) {
		t.Errorf("agent-a private chunk file still on disk")
	}
	if !chunkFileExists(t, rig, hashBOnly) {
		t.Errorf("agent-b private chunk file was deleted")
	}
}

func TestPurgeAgentSubtreeIsIdempotent(t *testing.T) {
	rig := newGCTestRig(t)
	putTestFile(t, rig, "agent-a", "/agent-a/f.txt", []byte("x"))

	if _, err := purgeAgentSubtree(rig.tenant, "agent-a"); err != nil {
		t.Fatalf("first purge: %v", err)
	}
	result, err := purgeAgentSubtree(rig.tenant, "agent-a")
	if err != nil {
		t.Fatalf("second purge: %v", err)
	}
	if result.ManifestsDeleted != 0 || result.ChunkRowsDeleted != 0 || result.BytesFreed != 0 {
		t.Errorf("second purge not a no-op: %+v", result)
	}
}

// A LIKE-pattern agent id must not escape its own subtree: agent "agent_a"
// (underscore is a LIKE single-char wildcard) must not purge "agentXa".
func TestPurgeAgentSubtreeEscapesLikeWildcards(t *testing.T) {
	rig := newGCTestRig(t)
	putTestFile(t, rig, "agent_a", "/agent_a/f.txt", []byte("underscore"))
	putTestFile(t, rig, "agentXa", "/agentXa/f.txt", []byte("wildcard bait"))

	result, err := purgeAgentSubtree(rig.tenant, "agent_a")
	if err != nil {
		t.Fatal(err)
	}
	if result.ManifestsDeleted != 1 {
		t.Errorf("manifests_deleted = %d, want 1", result.ManifestsDeleted)
	}
	if n := countRows(t, rig, `select count(*) from manifests where path = '/agentXa/f.txt'`); n != 1 {
		t.Errorf("wildcard sibling was purged")
	}
}

func TestPurgeAgentHandler(t *testing.T) {
	rig := newGCTestRig(t)
	putTestFile(t, rig, "agent-a", "/agent-a/f.txt", []byte("hello"))

	r := newRouter(rig.state)
	do := func(target string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodDelete, target, nil)
		req = req.WithContext(WithIdentity(req.Context(), Identity{
			AgentID:  "orlop-control",
			TenantID: controlPlaneTenantID,
		}))
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec
	}

	if rec := do("/control/tenants/nope/agents/agent-a"); rec.Code != http.StatusNotFound {
		t.Errorf("unknown tenant: status = %d, want 404", rec.Code)
	}
	if rec := do("/control/tenants/t1/agents/%2e%2e"); rec.Code != http.StatusBadRequest {
		t.Errorf("bad agent id: status = %d, want 400", rec.Code)
	}

	rec := do("/control/tenants/t1/agents/agent-a")
	if rec.Code != http.StatusOK {
		t.Fatalf("purge: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp purgeAgentResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.ManifestsDeleted != 1 {
		t.Errorf("manifests_deleted = %d, want 1", resp.ManifestsDeleted)
	}
}
