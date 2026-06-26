package main

import (
	"testing"

	"github.com/liu1700/orlop/cmd/orlop-server/dataplane"
	"github.com/vmihailenco/msgpack/v5"
)

// TestMountLeaseFenceRejectsStaleSessionAfterTakeover is the regression test
// for issue #175. After a Take-over hands the lease for an allocation to a new
// agent, the previously-mounted client must be unable to write — even before
// its lease-refresh notices the conflict. We simulate this by writing a row
// under session A, swapping the active lease to session B, then trying another
// write under session A; the second write must error.
func TestMountLeaseFenceRejectsStaleSessionAfterTakeover(t *testing.T) {
	state := newTestState(t, nil, nil)
	tenant, ok := state.tenant(testTenant)
	if !ok {
		t.Fatalf("tenant %q not found", testTenant)
	}
	if err := tenant.manifests.DirCreate("/docs", 0o755); err != nil {
		t.Fatalf("seed /docs: %v", err)
	}

	allocID := "alloc_fence_takeover"
	sidA := testSessionID(0xa1)
	sidB := testSessionID(0xb1)
	ident := testIdentity()

	// Session A holds the lease and writes successfully.
	seedMountLease(state, tenant, allocID, 0xa1)
	putA := dataplane.ManifestPutRequest{
		Path:         "/docs/under_a.txt",
		Size:         3,
		Mode:         0o644,
		Chunks:       []dataplane.ChunkRef{{Hash: makeTestHash(1), Offset: 0, Len: 3}},
		SessionID:    &sidA,
		AllocationID: &allocID,
	}
	if r := dispatchAndReadFrame(t, state, tenant, ident, dataplane.OpManifestPut, putA, handleManifestPut); r.Flags&dataplane.FlagError != 0 {
		t.Fatalf("session A first put rejected: %x", r.Payload)
	}

	// Dashboard Take-over: orlop-control DELETEs the active lease, which
	// fences session A. Session B obtains its own lease (post-Phase 1.5
	// requires a real lease record, not just a fabricated hex) before its
	// first write.
	state.mountLeases.Clear(allocID)
	seedMountLease(state, tenant, allocID, 0xb1)

	// Session A keeps writing with its old session_id — must be rejected
	// IMMEDIATELY, without waiting for the client's lease-refresh window.
	putAgain := dataplane.ManifestPutRequest{
		Path:         "/docs/sneaky_a.txt",
		Size:         3,
		Mode:         0o644,
		Chunks:       []dataplane.ChunkRef{{Hash: makeTestHash(2), Offset: 0, Len: 3}},
		SessionID:    &sidA,
		AllocationID: &allocID,
	}
	r := dispatchAndReadFrame(t, state, tenant, ident, dataplane.OpManifestPut, putAgain, handleManifestPut)
	if r.Flags&dataplane.FlagError == 0 {
		t.Fatal("expected fence to reject session A after take-over, got success")
	}
	var ep dataplane.ErrorPayload
	if err := msgpack.Unmarshal(r.Payload, &ep); err != nil {
		t.Fatalf("decode error payload: %v", err)
	}
	if ep.Errno != dataplane.ErrnoEIO && ep.Errno != dataplane.ErrnoEACCES {
		t.Errorf("errno = %d, want EACCES or EIO (lease fence)", ep.Errno)
	}

	// Session B can write under the new lease.
	putB := dataplane.ManifestPutRequest{
		Path:         "/docs/under_b.txt",
		Size:         3,
		Mode:         0o644,
		Chunks:       []dataplane.ChunkRef{{Hash: makeTestHash(3), Offset: 0, Len: 3}},
		SessionID:    &sidB,
		AllocationID: &allocID,
	}
	if r := dispatchAndReadFrame(t, state, tenant, ident, dataplane.OpManifestPut, putB, handleManifestPut); r.Flags&dataplane.FlagError != 0 {
		t.Fatalf("session B put rejected: %x", r.Payload)
	}
}

// TestMountLeaseFenceRejectsWritesAfterRevoke verifies the revoke path: when
// orlop-control clears the active lease for an allocation, any in-flight
// client write is rejected on the next request.
func TestMountLeaseFenceRejectsWritesAfterRevoke(t *testing.T) {
	state := newTestState(t, nil, nil)
	tenant, ok := state.tenant(testTenant)
	if !ok {
		t.Fatalf("tenant %q not found", testTenant)
	}
	if err := tenant.manifests.DirCreate("/docs", 0o755); err != nil {
		t.Fatalf("seed /docs: %v", err)
	}

	allocID := "alloc_fence_revoke"
	sid := testSessionID(0xc1)
	ident := testIdentity()

	seedMountLease(state, tenant, allocID, 0xc1)
	first := dataplane.ManifestPutRequest{
		Path:         "/docs/before_revoke.txt",
		Size:         3,
		Mode:         0o644,
		Chunks:       []dataplane.ChunkRef{{Hash: makeTestHash(1), Offset: 0, Len: 3}},
		SessionID:    &sid,
		AllocationID: &allocID,
	}
	if r := dispatchAndReadFrame(t, state, tenant, ident, dataplane.OpManifestPut, first, handleManifestPut); r.Flags&dataplane.FlagError != 0 {
		t.Fatalf("first put rejected: %x", r.Payload)
	}

	// Dashboard revoke: registry clears.
	state.mountLeases.Clear(allocID)

	second := dataplane.ManifestPutRequest{
		Path:         "/docs/after_revoke.txt",
		Size:         3,
		Mode:         0o644,
		Chunks:       []dataplane.ChunkRef{{Hash: makeTestHash(2), Offset: 0, Len: 3}},
		SessionID:    &sid,
		AllocationID: &allocID,
	}
	r := dispatchAndReadFrame(t, state, tenant, ident, dataplane.OpManifestPut, second, handleManifestPut)
	if r.Flags&dataplane.FlagError == 0 {
		t.Fatal("expected fence to reject writes after revoke, got success")
	}
}

// TestMountLeaseRegistryTakesOverStaleActive locks the single-node mount fix: Install must
// ADOPT a non-fenced active hex left by a prior mount rather than reject it. On single-node
// (no server_pool placement) a released pod's fence no-ops, so its active hex is never
// Clear()ed; pre-fix the next mount's writes hit a stale active hex → EACCES → silently
// read-only disk (chmod/install fails). Single-writer is still enforced upstream (DB-lease
// takeover + HeldByConn); the registry only bars a FENCED (revoked/displaced) hex.
func TestMountLeaseRegistryTakesOverStaleActive(t *testing.T) {
	r := newMountLeaseRegistry()
	const alloc = "alloc_takeover"

	if !r.Install(alloc, "hexA") {
		t.Fatal("hexA initial install should succeed")
	}
	// Fresh re-mount, different non-fenced hex → must take over (pre-fix: returned false → RO).
	if !r.Install(alloc, "hexB") {
		t.Fatal("hexB should take over a stale non-fenced active slot")
	}
	if got := r.Get(alloc); got != "hexB" {
		t.Fatalf("active = %q, want hexB after take-over", got)
	}
	if !r.Install(alloc, "hexB") {
		t.Fatal("re-installing the active hex should be idempotent")
	}

	// Clear() fences hexB (real revoke/take-over): it must never resurrect, even though the
	// active slot is now empty and take-over is otherwise allowed.
	r.Clear(alloc)
	if r.Install(alloc, "hexB") {
		t.Fatal("fenced hexB must not re-install")
	}
	// A brand-new hex still installs into the cleared slot.
	if !r.Install(alloc, "hexC") {
		t.Fatal("hexC should install after clear")
	}
}
