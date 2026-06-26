package main

import (
	"bytes"
	"testing"

	"github.com/liu1700/orlop/cmd/orlop-server/dataplane"
	"github.com/vmihailenco/msgpack/v5"
)

// TestSessionIDRejectedOnDifferentConn covers the replay-across-connection
// case: a real lease exists in tenant.leases (held by connID=A) but a write
// arrives on a different connection (connID=B) carrying the same session_id.
// Phase 1.5's strict check (HeldByConn) requires the conn match — this is the
// piece that stops a leaked session_id from being replayed by an attacker who
// guesses or steals it but writes from a different connection.
//
// AC: §5 row 4 of an internal design spec
func TestSessionIDRejectedOnDifferentConn(t *testing.T) {
	state := newTestState(t, nil, nil)
	tenant, ok := state.tenant(testTenant)
	if !ok {
		t.Fatalf("tenant %q not found", testTenant)
	}
	if err := tenant.manifests.DirCreate("/docs", 0o755); err != nil {
		t.Fatalf("seed /docs: %v", err)
	}

	// Seed a lease record owned by connID=100 with the test-suffix hex.
	const grantedConnID uint64 = 100
	const attackerConnID uint64 = 200
	const suffix byte = 0xcd
	allocID := "alloc_conn_bind_test"
	tenant.leases.installForTest(testLeaseID(suffix), "holder", grantedConnID, "/", dataplane.LeaseExclusiveWrite)

	sid := testSessionID(suffix)
	ident := testIdentity()
	putReq := dataplane.ManifestPutRequest{
		Path:         "/docs/replayed.txt",
		Size:         4,
		Mode:         0o644,
		Chunks:       []dataplane.ChunkRef{{Hash: makeTestHash(1), Offset: 0, Len: 4}},
		SessionID:    &sid,
		AllocationID: &allocID,
	}

	// Drive the frame through a writer pinned to attackerConnID, NOT
	// grantedConnID. Expect EACCES.
	raw, err := msgpack.Marshal(putReq)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var buf bytes.Buffer
	w := newFrameWriter(&buf)
	w.connID = attackerConnID
	handleManifestPut(state, tenant, ident, w, dataplane.Frame{Op: dataplane.OpManifestPut, RID: 1, Payload: raw})
	w.close()

	r, err := dataplane.ReadFrame(&buf)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if r.Flags&dataplane.FlagError == 0 {
		t.Fatal("expected EACCES, got success — lease replay accepted across connections")
	}
	var ep dataplane.ErrorPayload
	if err := msgpack.Unmarshal(r.Payload, &ep); err != nil {
		t.Fatalf("decode error payload: %v", err)
	}
	if ep.Errno != dataplane.ErrnoEACCES {
		t.Errorf("errno = %d, want EACCES (%d)", ep.Errno, dataplane.ErrnoEACCES)
	}
}
