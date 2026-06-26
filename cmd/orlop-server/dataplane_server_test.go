package main

import (
	"errors"
	"io"
	"testing"

	"github.com/liu1700/orlop/cmd/orlop-server/dataplane"
	"github.com/vmihailenco/msgpack/v5"
	"lukechampine.com/blake3"
)

// Issue #103: when a CAS conflict propagates a *VersionConflictError,
// buildCasConflictHint surfaces the server's actual version on the wire so
// the client can retry without an extra manifest_get RTT.
func TestBuildCasConflictHintFromVersionConflictError(t *testing.T) {
	conflict := &VersionConflictError{Existing: 7}
	hint := buildCasConflictHint(5, conflict, nil)

	if hint == nil {
		t.Fatal("hint must not be nil")
	}
	if hint.Kind != dataplane.RecoveryKindCasConflict {
		t.Fatalf("kind = %q, want %q", hint.Kind, dataplane.RecoveryKindCasConflict)
	}
	if hint.YourVersion == nil || *hint.YourVersion != 5 {
		t.Fatalf("your_version = %v, want 5", hint.YourVersion)
	}
	if hint.CurrentVersion == nil || *hint.CurrentVersion != 7 {
		t.Fatalf("current_version = %v, want 7", hint.CurrentVersion)
	}
	if hint.SuggestedAction == "" {
		t.Fatal("suggested_action must be populated")
	}
	if hint.LastWriter != nil {
		t.Fatal("last_writer must be nil when no writer row was supplied")
	}
}

// On a bare ErrVersionConflict (no augmenting type), the hint still carries
// `your_version` + a generic suggestion — `current_version` stays nil so the
// client falls back to the legacy re-read path.
func TestBuildCasConflictHintBareSentinel(t *testing.T) {
	hint := buildCasConflictHint(3, errors.New("manifest version conflict"), nil)
	if hint.YourVersion == nil || *hint.YourVersion != 3 {
		t.Fatalf("your_version = %v, want 3", hint.YourVersion)
	}
	if hint.CurrentVersion != nil {
		t.Fatalf("current_version must be nil when error lacks Existing, got %v", *hint.CurrentVersion)
	}
	if hint.SuggestedAction == "" {
		t.Fatal("suggested_action must still be populated for the bare path")
	}
}

// Issue #100: when the manifest_put error path passes a non-nil
// *LastWriterRow, the hint surfaces agent_id + session_id + at_unix_ms so the
// client can name the conflicting prior writer without a separate audit
// query. Empty agent_id / session_id collapse to nil pointers on the wire so
// msgpack omits them rather than sending empty strings.
func TestBuildCasConflictHintIncludesLastWriter(t *testing.T) {
	conflict := &VersionConflictError{Existing: 4}
	lw := &LastWriterRow{AgentID: "agent_42", SessionID: "s_99", AtUnixMs: 1_700_000_000_500}
	hint := buildCasConflictHint(2, conflict, lw)

	if hint.LastWriter == nil {
		t.Fatal("last_writer must be populated when row is supplied")
	}
	if hint.LastWriter.AgentID == nil || *hint.LastWriter.AgentID != "agent_42" {
		t.Fatalf("agent_id = %v, want agent_42", hint.LastWriter.AgentID)
	}
	if hint.LastWriter.SessionID == nil || *hint.LastWriter.SessionID != "s_99" {
		t.Fatalf("session_id = %v, want s_99", hint.LastWriter.SessionID)
	}
	if hint.LastWriter.AtUnixMs != 1_700_000_000_500 {
		t.Fatalf("at_unix_ms = %d, want 1700000000500", hint.LastWriter.AtUnixMs)
	}

	hintLegacy := buildCasConflictHint(2, conflict, &LastWriterRow{SessionID: "s_legacy", AtUnixMs: 1})
	if hintLegacy.LastWriter == nil || hintLegacy.LastWriter.AgentID != nil {
		t.Fatalf("legacy last_writer agent_id = %v, want nil", hintLegacy.LastWriter.AgentID)
	}
	if hintLegacy.LastWriter.SessionID == nil || *hintLegacy.LastWriter.SessionID != "s_legacy" {
		t.Fatalf("legacy last_writer session_id = %v, want s_legacy", hintLegacy.LastWriter.SessionID)
	}
}

// Issue #100 (end-to-end): a manifest_put that loses a CAS race against a
// previously sessioned writer must surface that writer's identity on the
// wire — agent_id + session_id + at_unix_ms — so the client side can name
// the conflicting party in error UI without a separate audit query.
func TestManifestPutCasConflictPopulatesLastWriter(t *testing.T) {
	state := newTestState(t, nil, nil)
	tenant, ok := state.tenant(testTenant)
	if !ok {
		t.Fatalf("tenant %q not found", testTenant)
	}
	if err := tenant.manifests.DirCreate("/docs", 0o755); err != nil {
		t.Fatalf("seed /docs: %v", err)
	}

	const (
		path     = "/docs/file.txt"
		sessionA = "mount:61616161616161616161616161616161" // "mount:" + hex("aaaaaaaaaaaaaaaa")
		allocA   = "alloc_cas_test"
		agentA   = "agent_A"
	)
	seedMountLease(state, tenant, allocA, 0x61)
	identA := testIdentity()
	identA.AgentID = agentA
	priorPut := dataplane.ManifestPutRequest{
		Path:         path,
		Size:         4,
		Mode:         0o644,
		Chunks:       []dataplane.ChunkRef{{Hash: makeTestHash(1), Offset: 0, Len: 4}},
		SessionID:    func() *string { s := sessionA; return &s }(),
		AllocationID: func() *string { s := allocA; return &s }(),
	}
	dispatchAndReadFrame(t, state, tenant, identA, dataplane.OpManifestPut, priorPut, handleManifestPut)

	identB := testIdentity()
	identB.AgentID = "agent_B"
	conflictingPut := dataplane.ManifestPutRequest{
		Path:            path,
		VersionExpected: 5, // stale — server is at version 1
		Size:            4,
		Mode:            0o644,
		Chunks:          []dataplane.ChunkRef{{Hash: makeTestHash(2), Offset: 0, Len: 4}},
	}
	resp := dispatchAndReadFrame(t, state, tenant, identB, dataplane.OpManifestPut, conflictingPut, handleManifestPut)
	if resp.Flags&dataplane.FlagError == 0 {
		t.Fatal("expected error frame from CAS conflict")
	}
	var ep dataplane.ErrorPayload
	if err := msgpack.Unmarshal(resp.Payload, &ep); err != nil {
		t.Fatalf("decode error payload: %v", err)
	}
	if ep.Errno != dataplane.ErrnoESTALE {
		t.Fatalf("errno = %d, want ESTALE (%d)", ep.Errno, dataplane.ErrnoESTALE)
	}
	if ep.Recovery == nil {
		t.Fatal("recovery hint missing")
	}
	if ep.Recovery.LastWriter == nil {
		t.Fatal("recovery hint last_writer missing — issue #100 not wired")
	}
	if ep.Recovery.LastWriter.AgentID == nil || *ep.Recovery.LastWriter.AgentID != agentA {
		t.Fatalf("last_writer agent_id = %v, want %s", ep.Recovery.LastWriter.AgentID, agentA)
	}
	if ep.Recovery.LastWriter.SessionID == nil || *ep.Recovery.LastWriter.SessionID != sessionA {
		t.Fatalf("last_writer session_id = %v, want %s", ep.Recovery.LastWriter.SessionID, sessionA)
	}
	if ep.Recovery.LastWriter.AtUnixMs == 0 {
		t.Error("last_writer at_unix_ms must be populated")
	}
}

// makeTestHash builds a deterministic 32-byte hash filled with the given
// seed byte. The chunk store rejects empty chunk slices on insert (NOT NULL
// constraint on manifests.chunks), so manifest_put fixtures need at least
// one ChunkRef.
func makeTestHash(seed byte) []byte {
	h := make([]byte, 32)
	for i := range h {
		h[i] = seed
	}
	return h
}

// A write request tagged with session_id must surface it on the matching
// audit row. Covers every write opcode that carries the field, plus a
// manifest_get baseline that must stay session-less.
func TestWriteRequestsSurfaceSessionIDInAudit(t *testing.T) {
	state := newTestState(t, nil, nil)
	tenant, ok := state.tenant(testTenant)
	if !ok {
		t.Fatalf("tenant %q not found", testTenant)
	}
	if err := tenant.manifests.DirCreate("/docs", 0o755); err != nil {
		t.Fatalf("seed /docs: %v", err)
	}
	ident := testIdentity()
	w := newFrameWriter(io.Discard)
	w.connID = testConnID
	defer w.close()

	sessionPtr := func(s string) *string { return &s }
	const (
		sid     = "mount:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" // valid mount:<hex> session id
		allocID = "alloc_audit_test"
	)
	seedMountLease(state, tenant, allocID, 0xbb)

	dispatch := func(op dataplane.Op, payload any, handler func(*serverState, *tenantState, Identity, *frameWriter, dataplane.Frame)) {
		t.Helper()
		raw, err := msgpack.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal %v: %v", op, err)
		}
		handler(state, tenant, ident, w, dataplane.Frame{Op: op, RID: 1, Payload: raw})
	}

	dispatch(dataplane.OpDirCreate, dataplane.DirCreateRequest{
		Path: "/docs/sub", Mode: 0o755, SessionID: sessionPtr(sid),
	}, handleDirCreate)
	chunkBytes := []byte("data")
	chunkHashArr := blake3.Sum256(chunkBytes)
	chunkHash := chunkHashArr[:]
	dispatch(dataplane.OpChunkPut, dataplane.ChunkPutRequest{
		Hash: chunkHash, Bytes: chunkBytes, SessionID: sessionPtr(sid),
	}, handleChunkPut)
	dispatch(dataplane.OpManifestPut, dataplane.ManifestPutRequest{
		Path:         "/docs/sub/f.txt",
		Size:         uint64(len(chunkBytes)),
		Mode:         0o644,
		Chunks:       []dataplane.ChunkRef{{Hash: chunkHash, Offset: 0, Len: uint32(len(chunkBytes))}},
		SessionID:    sessionPtr(sid),
		AllocationID: sessionPtr(allocID),
	}, handleManifestPut)
	dispatch(dataplane.OpManifestRename, dataplane.ManifestRenameRequest{
		From: "/docs/sub/f.txt", To: "/docs/sub/g.txt",
		ExpectedVersionFrom: 1, SessionID: sessionPtr(sid), AllocationID: sessionPtr(allocID),
	}, handleManifestRename)
	dispatch(dataplane.OpManifestDelete, dataplane.ManifestDeleteRequest{
		Path: "/docs/sub/g.txt", ExpectedVersion: 1, SessionID: sessionPtr(sid), AllocationID: sessionPtr(allocID),
	}, handleManifestDelete)
	dispatch(dataplane.OpDirRemove, dataplane.DirRemoveRequest{
		Path: "/docs/sub", SessionID: sessionPtr(sid),
	}, handleDirRemove)

	dispatch(dataplane.OpManifestGet,
		dataplane.ManifestGetRequest{Path: "/docs/sub/g.txt"},
		handleManifestGet)

	if err := state.audit.file.Sync(); err != nil {
		t.Fatalf("sync: %v", err)
	}

	events := readAuditEvents(t, state.audit.Path())
	wantTagged := map[string]bool{
		"dir_create":      false,
		"chunk_put":       false,
		"manifest_put":    false,
		"manifest_rename": false,
		"manifest_delete": false,
		"dir_remove":      false,
	}
	for _, ev := range events {
		name, _ := ev["event"].(string)
		if _, tracked := wantTagged[name]; tracked {
			if ev["session_id"] != sid {
				t.Errorf("%s session_id = %v, want %q (event=%v)", name, ev["session_id"], sid, ev)
			}
			wantTagged[name] = true
		}
		if name == "manifest_get" {
			if _, present := ev["session_id"]; present {
				t.Errorf("manifest_get must omit session_id when client did not set it; got %v", ev["session_id"])
			}
		}
	}
	for name, seen := range wantTagged {
		if !seen {
			t.Errorf("expected %q audit event was not emitted", name)
		}
	}
}

// An old client that doesn't know about session_id must still interoperate.
// Encoding a payload via the legacy struct shape (no SessionID field) and
// dispatching it must succeed and emit an audit row that omits session_id.
func TestOldClientWithoutSessionIDStillDispatches(t *testing.T) {
	state := newTestState(t, nil, nil)
	tenant, ok := state.tenant(testTenant)
	if !ok {
		t.Fatalf("tenant %q not found", testTenant)
	}
	if err := tenant.manifests.DirCreate("/docs", 0o755); err != nil {
		t.Fatalf("seed /docs: %v", err)
	}
	ident := testIdentity()
	w := newFrameWriter(io.Discard)
	w.connID = testConnID
	defer w.close()

	type legacyManifestPut struct {
		Path            string               `msgpack:"path"`
		VersionExpected uint64               `msgpack:"version_expected"`
		Size            uint64               `msgpack:"size"`
		Mode            uint32               `msgpack:"mode"`
		Mtime           int64                `msgpack:"mtime"`
		Chunks          []dataplane.ChunkRef `msgpack:"chunks"`
	}
	raw, err := msgpack.Marshal(legacyManifestPut{
		Path:   "/docs/legacy.txt",
		Size:   4,
		Mode:   0o644,
		Chunks: []dataplane.ChunkRef{{Hash: makeTestHash(8), Offset: 0, Len: 4}},
	})
	if err != nil {
		t.Fatalf("marshal legacy: %v", err)
	}
	handleManifestPut(state, tenant, ident, w, dataplane.Frame{
		Op: dataplane.OpManifestPut, RID: 1, Payload: raw,
	})
	if err := state.audit.file.Sync(); err != nil {
		t.Fatalf("sync: %v", err)
	}

	events := readAuditEvents(t, state.audit.Path())
	var saw bool
	for _, ev := range events {
		if ev["event"] != "manifest_put" || ev["allowed"] != true {
			continue
		}
		saw = true
		if _, present := ev["session_id"]; present {
			t.Errorf("legacy client payload produced session_id=%v; expected omitted", ev["session_id"])
		}
	}
	if !saw {
		t.Errorf("expected manifest_put audit row not found (events=%v)", events)
	}
}
