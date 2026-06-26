package main

import (
	"bytes"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/vmihailenco/msgpack/v5"

	"github.com/liu1700/orlop/cmd/orlop-server/dataplane"
)

// bombPayload reproduces the security-review PoC: a 13-byte frame whose msgpack
// header declares a ~4.29-billion-element array. Before the guard, the
// typed-slice decoder pre-allocated that many ChunkRefs and OOM-killed the
// process from this tiny input.
func bombPayload() []byte {
	return []byte{
		0x81,                               // fixmap, 1 entry
		0xa6, 'c', 'h', 'u', 'n', 'k', 's', // fixstr(6) "chunks"
		0xdd, 0xFF, 0xFF, 0xFF, 0xF0, // array32, len 4294967280
	}
}

func TestGuardRejectsHugeArrayHeader(t *testing.T) {
	// A bare array32 header claiming ~4.29B elements with nothing following.
	payload := []byte{0xdd, 0xFF, 0xFF, 0xFF, 0xF0}
	if err := guardMsgpackLimits(payload); err == nil {
		t.Fatal("guard accepted a 4-billion-element array header")
	}
}

func TestSafeUnmarshalRejectsManifestPutBomb(t *testing.T) {
	// Reaching the assertion at all (no OOM-kill) is the real proof; the error
	// confirms the guard short-circuited before the greedy pre-allocation.
	var req dataplane.ManifestPutRequest
	if err := safeUnmarshal(bombPayload(), &req); err == nil {
		t.Fatal("safeUnmarshal accepted the OOM-bomb payload")
	}
}

func TestSafeUnmarshalAcceptsLegitManifestPut(t *testing.T) {
	in := dataplane.ManifestPutRequest{
		Path: "/agents/demo/file.txt",
		Size: 3072,
		Chunks: []dataplane.ChunkRef{
			{Hash: bytes.Repeat([]byte{1}, 32), Offset: 0, Len: 1024},
			{Hash: bytes.Repeat([]byte{2}, 32), Offset: 1024, Len: 2048},
		},
	}
	payload, err := msgpack.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out dataplane.ManifestPutRequest
	if err := safeUnmarshal(payload, &out); err != nil {
		t.Fatalf("safeUnmarshal rejected a legitimate ManifestPut: %v", err)
	}
	if out.Path != in.Path || len(out.Chunks) != len(in.Chunks) {
		t.Fatalf("round-trip mismatch: got %+v", out)
	}
}

func TestCheckContainerLen(t *testing.T) {
	if err := checkContainerLen(10, 1000); err != nil {
		t.Fatalf("legitimate length rejected: %v", err)
	}
	if checkContainerLen(10, 5) == nil {
		t.Fatal("length exceeding the byte budget was accepted")
	}
	if checkContainerLen(maxMsgpackContainerLen+1, 1<<40) == nil {
		t.Fatal("length exceeding the absolute cap was accepted")
	}
	if checkContainerLen(-1, 1000) == nil {
		t.Fatal("negative length was accepted")
	}
}

func TestRecoverRequestCatchesPanicAndWritesEIO(t *testing.T) {
	s := &serverState{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	var buf bytes.Buffer
	w := newFrameWriter(&buf)
	frame := dataplane.Frame{Op: dataplane.OpManifestPut, RID: 99}

	// A panic in the handler body must be swallowed by recoverRequest, not
	// escape and crash the process.
	func() {
		defer recoverRequest(s, w, frame)
		panic("boom")
	}()
	w.close() // drain the writer goroutine into buf

	resp, err := dataplane.ReadFrame(&buf)
	if err != nil {
		t.Fatalf("expected an error response frame, got read error: %v", err)
	}
	if !resp.IsError() || resp.RID != 99 {
		t.Fatalf("expected an EIO error frame for RID 99, got %+v", resp)
	}
	var ep dataplane.ErrorPayload
	if err := msgpack.Unmarshal(resp.Payload, &ep); err != nil {
		t.Fatalf("decode error payload: %v", err)
	}
	if ep.Errno != dataplane.ErrnoEIO {
		t.Fatalf("expected EIO errno %d, got %d", dataplane.ErrnoEIO, ep.Errno)
	}
}

func TestHandleChunkPutRejectsOversizedChunk(t *testing.T) {
	state := newTestState(t, nil, nil)
	tenant := state.tenants[testTenant]
	var buf bytes.Buffer
	w := newFrameWriter(&buf)

	// One byte over the cap. The size check runs before the BLAKE3 verify, so an
	// all-zero hash is fine — we only care that it is rejected, not stored.
	req := dataplane.ChunkPutRequest{Hash: make([]byte, 32), Bytes: make([]byte, maxChunkBytes+1)}
	payload, err := msgpack.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	handleChunkPut(state, tenant, testIdentity(), w, dataplane.Frame{Op: dataplane.OpChunkPut, RID: 5, Payload: payload})
	w.close()

	resp, err := dataplane.ReadFrame(&buf)
	if err != nil {
		t.Fatalf("expected an error response frame: %v", err)
	}
	if !resp.IsError() || resp.RID != 5 {
		t.Fatalf("expected an error frame for RID 5, got %+v", resp)
	}
}

func TestGoRequestBoundsConcurrency(t *testing.T) {
	const limit = 2
	s := &serverState{reqSem: make(chan struct{}, limit)}

	var (
		mu       sync.Mutex
		cur, max int
		wg       sync.WaitGroup
	)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		s.goRequest(func() {
			defer wg.Done()
			mu.Lock()
			cur++
			if cur > max {
				max = cur
			}
			mu.Unlock()
			time.Sleep(5 * time.Millisecond)
			mu.Lock()
			cur--
			mu.Unlock()
		})
	}
	wg.Wait()
	if max > limit {
		t.Fatalf("peak concurrency = %d, want <= %d", max, limit)
	}
}

func TestGoRequestNilSemaphoreStillRuns(t *testing.T) {
	s := &serverState{} // nil reqSem: must not deadlock
	done := make(chan struct{})
	s.goRequest(func() { close(done) })
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("goRequest with nil semaphore did not run fn")
	}
}

func TestEnvInt(t *testing.T) {
	if got := envInt("ORLOP_DATAGW_NONEXISTENT_ZZZ", 7); got != 7 {
		t.Fatalf("missing env: got %d, want 7", got)
	}
	t.Setenv("ORLOP_DATAGW_TEST_INT", "42")
	if got := envInt("ORLOP_DATAGW_TEST_INT", 7); got != 42 {
		t.Fatalf("valid env: got %d, want 42", got)
	}
	t.Setenv("ORLOP_DATAGW_TEST_INT", "-5")
	if got := envInt("ORLOP_DATAGW_TEST_INT", 7); got != 7 {
		t.Fatalf("negative env should fall back: got %d, want 7", got)
	}
	t.Setenv("ORLOP_DATAGW_TEST_INT", "notanumber")
	if got := envInt("ORLOP_DATAGW_TEST_INT", 7); got != 7 {
		t.Fatalf("invalid env should fall back: got %d, want 7", got)
	}
}
