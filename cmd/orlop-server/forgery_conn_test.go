package main

import (
	"bytes"
	"testing"

	"github.com/liu1700/orlop/cmd/orlop-server/dataplane"
	"github.com/vmihailenco/msgpack/v5"
)

func gatheredCounter(t *testing.T, state *serverState, name string) float64 {
	t.Helper()
	families, err := state.metrics.registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var total float64
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.Metric {
			total += metric.GetCounter().GetValue()
		}
	}
	return total
}

// TestSessionIDRejectedForDifferentAgent covers cross-identity replay: a real
// lease exists for another agent and the caller presents its session id on a
// different authenticated connection. Reconnect support must never cross the
// certificate's agent boundary.
func TestSessionIDRejectedForDifferentAgent(t *testing.T) {
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
	tenant.leases.installForTest(testLeaseID(suffix), "other-agent", grantedConnID, "/", dataplane.LeaseExclusiveWrite)

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

func TestSessionIDRebindsForSameAgentOnNewConnection(t *testing.T) {
	state := newTestState(t, nil, nil)
	tenant, ok := state.tenant(testTenant)
	if !ok {
		t.Fatalf("tenant %q not found", testTenant)
	}
	if err := tenant.manifests.DirCreate("/docs", 0o755); err != nil {
		t.Fatalf("seed /docs: %v", err)
	}

	const oldConnID uint64 = 100
	const newConnID uint64 = 200
	const suffix byte = 0xce
	allocID := "alloc_reconnect"
	leaseID := testLeaseID(suffix)
	ident := testIdentity()
	tenant.leases.installForTest(leaseID, ident.AgentID, oldConnID, "/", dataplane.LeaseExclusiveWrite)

	sid := testSessionID(suffix)
	putReq := dataplane.ManifestPutRequest{
		Path:         "/docs/after-reconnect.txt",
		Size:         4,
		Mode:         0o644,
		Chunks:       []dataplane.ChunkRef{{Hash: makeTestHash(2), Offset: 0, Len: 4}},
		SessionID:    &sid,
		AllocationID: &allocID,
	}
	raw, err := msgpack.Marshal(putReq)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	w := newFrameWriter(&buf)
	w.connID = newConnID
	handleManifestPut(state, tenant, ident, w, dataplane.Frame{Op: dataplane.OpManifestPut, RID: 1, Payload: raw})
	w.close()
	resp, err := dataplane.ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Flags&dataplane.FlagError != 0 {
		t.Fatalf("legitimate reconnect rejected: %x", resp.Payload)
	}
	if !tenant.leases.HeldByConn(leaseID, newConnID) || tenant.leases.HeldByConn(leaseID, oldConnID) {
		t.Fatal("lease ownership was not atomically moved to the new connection")
	}
	// The old socket's deferred cleanup may run after the new request. Its
	// stale byConn slot must not delete the rebound live lease.
	tenant.leases.ReleaseAllForConn(oldConnID)
	if !tenant.leases.HeldByConn(leaseID, newConnID) {
		t.Fatal("old connection cleanup released the rebound lease")
	}
	if got := gatheredCounter(t, state, "orlop_session_rebind_total"); got != 1 {
		t.Fatalf("session rebind metric = %v, want 1", got)
	}
	if got := gatheredCounter(t, state, "orlop_session_forgery_rejected_total"); got != 0 {
		t.Fatalf("legitimate reconnect incremented forgery metric: %v", got)
	}
}
