package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/liu1700/orlop/cmd/orlop-server/dataplane"
	"github.com/vmihailenco/msgpack/v5"
	"lukechampine.com/blake3"
)

// registerForOrphanTest registers a tenant over the admin API and returns its
// live *tenantState plus its on-disk directory. The returned pointer models the
// one a data-plane connection captures at accept time and keeps using for the
// life of the connection — the crux of #103.
func registerForOrphanTest(t *testing.T, state *serverState, id string) (*tenantState, string) {
	t.Helper()
	body := registerTenantRequest{TenantID: id, Name: id, SizeBytes: 1 << 30}
	if rr := doAdminRequest(state, http.MethodPost, "/control/tenants", body); rr.Code != http.StatusOK {
		t.Fatalf("register %s: status = %d body = %s", id, rr.Code, rr.Body.String())
	}
	ts, ok := state.tenant(id)
	if !ok {
		t.Fatalf("precondition: tenant %s not registered", id)
	}
	return ts, filepath.Join(state.adminCfg.TenantsRoot, id)
}

// TestPutChunkGateRefusesAfterMarkClosed is the unit-level guard: once the write
// gate is closed, a chunk Put is refused with errTenantGone and does not touch
// disk, while before closing it stores normally.
func TestPutChunkGateRefusesAfterMarkClosed(t *testing.T) {
	state, _ := newAdminTestState(t, &fakeExec{})
	ts, tenantDir := registerForOrphanTest(t, state, "acme")

	data := []byte("hello chunk")
	h := blake3.Sum256(data)
	stored, err := ts.putChunk(h[:], data)
	if err != nil || !stored {
		t.Fatalf("putChunk before close: stored=%v err=%v, want (true, nil)", stored, err)
	}
	if _, statErr := os.Stat(tenantDir); statErr != nil {
		t.Fatalf("tenant dir missing after live put: %v", statErr)
	}

	ts.markClosed()

	other := []byte("second chunk written after close")
	h2 := blake3.Sum256(other)
	stored, err = ts.putChunk(h2[:], other)
	if !errors.Is(err, errTenantGone) {
		t.Fatalf("putChunk after markClosed: err = %v, want errTenantGone", err)
	}
	if stored {
		t.Fatalf("putChunk after markClosed reported stored=true")
	}
	// The second chunk must not exist on disk — the gate refused before any write.
	p, perr := ts.chunks.Path(h2[:])
	if perr != nil {
		t.Fatalf("chunk path: %v", perr)
	}
	if _, statErr := os.Stat(p); !os.IsNotExist(statErr) {
		t.Fatalf("post-close chunk was written to disk: stat err = %v", statErr)
	}
}

// TestUnregisterThenStaleChunkPutLeavesNoOrphan reproduces the exact #103
// scenario deterministically: after DELETE /control/tenants/{id} removes the
// directory, a chunk_put arriving on the dying pod's still-open connection (the
// captured stale *tenantState) must be refused and must NOT recreate the dir.
func TestUnregisterThenStaleChunkPutLeavesNoOrphan(t *testing.T) {
	state, _ := newAdminTestState(t, &fakeExec{})
	ts, tenantDir := registerForOrphanTest(t, state, "anon_race")

	// Control-plane purges the tenant while the pod is still terminating.
	if rr := doAdminRequest(state, http.MethodDelete, "/control/tenants/anon_race", nil); rr.Code != http.StatusNoContent {
		t.Fatalf("delete: status = %d body = %s", rr.Code, rr.Body.String())
	}
	if _, err := os.Stat(tenantDir); !os.IsNotExist(err) {
		t.Fatalf("precondition: tenant dir not removed by unregister: %v", err)
	}

	// The dying pod flushes one last chunk over its captured *tenantState.
	data := []byte("final flush from a doomed connection")
	h := blake3.Sum256(data)
	stored, err := ts.putChunk(h[:], data)
	if !errors.Is(err, errTenantGone) {
		t.Fatalf("stale putChunk: err = %v, want errTenantGone", err)
	}
	if stored {
		t.Fatalf("stale putChunk reported stored=true")
	}

	// The acceptance criterion: no orphan directory was recreated.
	if _, err := os.Stat(tenantDir); !os.IsNotExist(err) {
		t.Fatalf("orphan tenant dir recreated after unregister: stat err = %v", err)
	}
}

// TestConcurrentChunkPutAndUnregisterNoOrphan is the race UAT — run under
// `go test -race`. Many goroutines hammer chunk_put on the captured stale
// *tenantState while the tenant is unregistered concurrently. Regardless of
// interleaving, once unregister completes the tenant dir must be gone: markClosed
// drains in-flight puts before RemoveAll, and every put that starts afterward is
// refused, so RemoveAll is the last write to the directory.
func TestConcurrentChunkPutAndUnregisterNoOrphan(t *testing.T) {
	state, _ := newAdminTestState(t, &fakeExec{})
	ts, tenantDir := registerForOrphanTest(t, state, "anon_churn")

	const workers = 8
	const maxIters = 2000
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func(w int) {
			defer wg.Done()
			for i := 0; i < maxIters; i++ {
				data := []byte(fmt.Sprintf("chunk-%d-%d", w, i)) // unique hash each iter → would MkdirAll+write
				h := blake3.Sum256(data)
				if _, err := ts.putChunk(h[:], data); errors.Is(err, errTenantGone) {
					return // gate closed; stop hammering
				}
			}
		}(w)
	}

	// Unregister mid-flight.
	if rr := doAdminRequest(state, http.MethodDelete, "/control/tenants/anon_churn", nil); rr.Code != http.StatusNoContent {
		t.Fatalf("delete: status = %d body = %s", rr.Code, rr.Body.String())
	}
	wg.Wait()

	if _, err := os.Stat(tenantDir); !os.IsNotExist(err) {
		t.Fatalf("orphan tenant dir survived concurrent put/unregister: stat err = %v", err)
	}
	if _, ok := state.tenant("anon_churn"); ok {
		t.Fatalf("tenant still registered after delete")
	}
}

// TestChunkPutOnClosedTenantReturnsESTALE verifies the wire-level errno: a
// chunk_put dispatched to a torn-down tenant comes back as ESTALE (stale handle),
// not EINVAL — so the FUSE client reads it as "the mount is gone" rather than a
// malformed request.
func TestChunkPutOnClosedTenantReturnsESTALE(t *testing.T) {
	state := newTestState(t, nil, nil)
	ts, ok := state.tenant(testTenant)
	if !ok {
		t.Fatalf("precondition: %s not registered", testTenant)
	}
	ts.markClosed()

	data := []byte("chunk after teardown")
	h := blake3.Sum256(data)
	resp := dispatchAndReadFrame(t, state, ts, testIdentity(), dataplane.OpChunkPut,
		dataplane.ChunkPutRequest{Hash: h[:], Bytes: data}, handleChunkPut)

	if resp.Flags&dataplane.FlagError == 0 {
		t.Fatal("expected an error frame for chunk_put on a closed tenant")
	}
	var ep dataplane.ErrorPayload
	if err := msgpack.Unmarshal(resp.Payload, &ep); err != nil {
		t.Fatalf("decode error payload: %v", err)
	}
	if ep.Errno != dataplane.ErrnoESTALE {
		t.Fatalf("errno = %d, want ESTALE (%d); msg=%q", ep.Errno, dataplane.ErrnoESTALE, ep.Message)
	}
}
