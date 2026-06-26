package main

import (
	"testing"

	"github.com/liu1700/orlop/cmd/orlop-server/dataplane"
	"github.com/vmihailenco/msgpack/v5"
)

// TestForgedSessionIDRejectedWithoutLeaseGrant is the AC5 regression test for
// Phase 1.5. A client that has never called LeaseGrant invents a valid-format
// session_id (mount:<32 hex>) and sends manifest_put to a fresh allocation.
//
// Before Phase 1.5 the lazy install in mountLeases.Install accepted any hex on
// a fresh allocation, so the write succeeded — see
// an internal design spec §2. After the fix,
// checkSessionFence consults the tenant's lease store first and rejects with
// EACCES when the hex doesn't correspond to a real grant.
func TestForgedSessionIDRejectedWithoutLeaseGrant(t *testing.T) {
	state := newTestState(t, nil, nil)
	tenant, ok := state.tenant(testTenant)
	if !ok {
		t.Fatalf("tenant %q not found", testTenant)
	}
	if err := tenant.manifests.DirCreate("/docs", 0o755); err != nil {
		t.Fatalf("seed /docs: %v", err)
	}

	// No LeaseGrant, no seedMountLease — client invents a hex.
	sid := testSessionID(0xfa)
	allocID := "alloc_forgery_fresh"
	ident := testIdentity()

	putReq := dataplane.ManifestPutRequest{
		Path:         "/docs/forged.txt",
		Size:         4,
		Mode:         0o644,
		Chunks:       []dataplane.ChunkRef{{Hash: makeTestHash(1), Offset: 0, Len: 4}},
		SessionID:    &sid,
		AllocationID: &allocID,
	}
	r := dispatchAndReadFrame(t, state, tenant, ident, dataplane.OpManifestPut, putReq, handleManifestPut)
	if r.Flags&dataplane.FlagError == 0 {
		t.Fatal("expected EACCES, got success — forgery accepted")
	}
	var ep dataplane.ErrorPayload
	if err := msgpack.Unmarshal(r.Payload, &ep); err != nil {
		t.Fatalf("decode error payload: %v", err)
	}
	if ep.Errno != dataplane.ErrnoEACCES {
		t.Errorf("errno = %d, want EACCES (%d)", ep.Errno, dataplane.ErrnoEACCES)
	}
}
