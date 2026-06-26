package main

import (
	"bytes"
	"fmt"
	"os"
	"runtime/debug"
	"strconv"

	"github.com/vmihailenco/msgpack/v5"
	"github.com/vmihailenco/msgpack/v5/msgpcode"

	"github.com/liu1700/orlop/cmd/orlop-server/dataplane"
)

// Data-plane DoS hardening for hostile-but-authenticated agents.
//
// Two guard rails live here:
//   - safeUnmarshal: bounds untrusted msgpack decoding so a tiny frame can't
//     force a multi-gigabyte pre-allocation (see below).
//   - recoverRequest: turns a panic in one request handler into an error
//     response for that request instead of a crash of the whole server.

const (
	// maxMsgpackContainerLen caps the declared element count of any array/map in
	// an inbound payload. The vmihailenco/msgpack v5 decoder pre-allocates a
	// typed slice/map to the length declared in the wire header BEFORE reading a
	// single element, and its built-in alloc-limit guard is dead code in this
	// version (decode_slice.go computes `flags & 2 != 1`, which is never true),
	// so a 13-byte frame declaring a 4-billion-element array OOM-kills the
	// process. We reject any container longer than this cap, which bounds the
	// worst-case pre-allocation to tens of MiB. The largest legitimate container
	// is a manifest's chunk list: an 8 GiB file at the 1 MiB minimum chunk size
	// is ~8192 chunks, so 1<<20 is generous headroom.
	maxMsgpackContainerLen = 1 << 20
	// maxMsgpackDepth bounds recursion during the guard walk so a deeply nested
	// payload can't exhaust the goroutine stack.
	maxMsgpackDepth = 64
)

// safeUnmarshal validates that payload cannot force an oversized pre-allocation,
// then unmarshals it into v. Use it for every decode of untrusted wire input.
func safeUnmarshal(payload []byte, v any) error {
	if err := guardMsgpackLimits(payload); err != nil {
		return err
	}
	return msgpack.Unmarshal(payload, v)
}

// guardMsgpackLimits walks payload once, rejecting any array/map whose declared
// length exceeds both the bytes that could possibly follow (every element is at
// least one byte) and an absolute cap. The walk uses Skip and allocates nothing
// proportional to the declared lengths, so it is safe to run on hostile input.
func guardMsgpackLimits(payload []byte) error {
	dec := msgpack.NewDecoder(bytes.NewReader(payload))
	return scanMsgpackValue(dec, len(payload), 0)
}

func scanMsgpackValue(dec *msgpack.Decoder, budget, depth int) error {
	if depth > maxMsgpackDepth {
		return fmt.Errorf("msgpack nesting exceeds depth %d", maxMsgpackDepth)
	}
	code, err := dec.PeekCode()
	if err != nil {
		return err
	}
	switch {
	case msgpcode.IsFixedArray(code) || code == msgpcode.Array16 || code == msgpcode.Array32:
		n, err := dec.DecodeArrayLen()
		if err != nil {
			return err
		}
		if err := checkContainerLen(n, budget); err != nil {
			return err
		}
		for i := 0; i < n; i++ {
			if err := scanMsgpackValue(dec, budget, depth+1); err != nil {
				return err
			}
		}
	case msgpcode.IsFixedMap(code) || code == msgpcode.Map16 || code == msgpcode.Map32:
		n, err := dec.DecodeMapLen()
		if err != nil {
			return err
		}
		if err := checkContainerLen(n, budget); err != nil {
			return err
		}
		for i := 0; i < n; i++ {
			if err := scanMsgpackValue(dec, budget, depth+1); err != nil { // key
				return err
			}
			if err := scanMsgpackValue(dec, budget, depth+1); err != nil { // value
				return err
			}
		}
	default:
		// Scalars, strings, and bin. Skip advances past the value without a
		// length-proportional allocation; the library already bounds string/bin
		// allocation (the OOM bug is specific to typed slices/maps) and the frame
		// is capped at MaxPayloadLen.
		if err := dec.Skip(); err != nil {
			return err
		}
	}
	return nil
}

func checkContainerLen(n, budget int) error {
	if n < 0 || n > maxMsgpackContainerLen || n > budget {
		return fmt.Errorf("msgpack container length %d exceeds limit (budget %d, cap %d)",
			n, budget, maxMsgpackContainerLen)
	}
	return nil
}

// Data-plane resource limits. The defaults are generous enough that a
// well-behaved fleet never approaches them; they exist to turn "unbounded" into
// "finite" against a hostile authenticated agent. Override via env on small
// hosts. (Before these, the data plane had NO connection cap, NO in-flight
// request cap, and NO per-chunk size cap — one agent could exhaust goroutines,
// memory, or host disk for every tenant on the server.)
var (
	// maxDataPlaneSessions bounds concurrent framed sessions (a TCP connection
	// or a single QUIC stream, which both funnel through serveFrames). When the
	// cap is hit, new sessions are rejected (the connection is closed) rather
	// than queued, so a flood fails fast instead of growing memory.
	maxDataPlaneSessions = envInt("ORLOP_DATAGW_MAX_SESSIONS", 1024)
	// maxInFlightRequests bounds concurrent request-handler goroutines across the
	// whole server. Acquired before the goroutine is spawned, so a single
	// connection can't outrun its handlers — the read loop blocks (backpressure)
	// instead of spawning unbounded goroutines.
	maxInFlightRequests = envInt("ORLOP_DATAGW_MAX_INFLIGHT", 256)
)

// maxChunkBytes caps a single stored chunk. The client's FastCDC chunker never
// emits a chunk larger than CHUNK_MAX (16 MiB); we accept headroom and reject
// anything larger so a hostile agent can't force the server to buffer and store
// 64 MiB blobs (the frame limit) on every chunk_put. Enforced only on the wire
// path (handleChunkPut), not in ChunkStore.Put, so trusted seed/migration
// writers are unaffected.
const maxChunkBytes = 20 << 20 // 20 MiB

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return fallback
}

// goRequest runs fn on a new goroutine, bounded by the in-flight request
// semaphore. Acquiring the slot BEFORE spawning applies backpressure to the
// read loop, so one connection can't spawn unbounded handler goroutines. Nil
// semaphore (e.g. a serverState built directly in a test) falls back to an
// unbounded spawn.
func (s *serverState) goRequest(fn func()) {
	sem := s.reqSem
	if sem != nil {
		sem <- struct{}{}
	}
	go func() {
		if sem != nil {
			defer func() { <-sem }()
		}
		fn()
	}()
}

// recoverRequest turns a panic in a single request handler into an EIO response
// for that one request instead of a process crash. serveFrames dispatches each
// op on its own goroutine, so without this an index-out-of-range, nil deref, or
// a panic deep in SQLite/journal code on crafted input would take down the whole
// data-plane server and every tenant on it. Defer it as the first statement of a
// handler so it is the outermost deferred call.
func recoverRequest(s *serverState, w *frameWriter, frame dataplane.Frame) {
	if r := recover(); r != nil {
		if s.logger != nil {
			s.logger.Error("data-plane handler panic recovered",
				"op", opLabel(frame.Op),
				"rid", frame.RID,
				"panic", fmt.Sprintf("%v", r),
				"stack", string(debug.Stack()))
		}
		writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEIO("internal error"))
	}
}
