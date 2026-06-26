package main

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"
)

// startControlStream spins up an httptest.Server wrapped around the SSE
// handler with a control-plane identity injected into the request context
// (so controlPlaneOnlyMiddleware lets the request through). It returns the
// open response (Body still being read from) and a cleanup that shuts both
// the server and the response down.
func startControlStream(t *testing.T, state *serverState, target string) (*http.Response, func()) {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(WithIdentity(r.Context(), Identity{
			AgentID:  "orlop-control",
			TenantID: controlPlaneTenantID,
		}))
		newRouter(state).ServeHTTP(w, r)
	}))

	req, err := http.NewRequest(http.MethodGet, srv.URL+target, nil)
	if err != nil {
		srv.Close()
		t.Fatalf("new request: %v", err)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		srv.Close()
		t.Fatalf("do request: %v", err)
	}
	cleanup := func() {
		resp.Body.Close()
		srv.Close()
	}
	return resp, cleanup
}

// readSSEFrame reads one full SSE frame (lines until a blank line) and
// returns it joined by '\n'. Returns io.EOF if the connection closed.
func readSSEFrame(r *bufio.Reader) (string, error) {
	var lines []string
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			if len(lines) > 0 {
				return strings.Join(lines, "\n"), nil
			}
			return "", err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			return strings.Join(lines, "\n"), nil
		}
		lines = append(lines, line)
	}
}

// readSSEFrameWithTimeout reads one frame on a separate goroutine so the
// test can fail fast instead of hanging.
func readSSEFrameWithTimeout(t *testing.T, r *bufio.Reader, d time.Duration) string {
	t.Helper()
	type result struct {
		frame string
		err   error
	}
	out := make(chan result, 1)
	go func() {
		f, err := readSSEFrame(r)
		out <- result{f, err}
	}()
	select {
	case res := <-out:
		if res.err != nil {
			t.Fatalf("read frame: %v", res.err)
		}
		return res.frame
	case <-time.After(d):
		t.Fatalf("no SSE frame within %s", d)
		return ""
	}
}

// parseDataFrame strips the `data: ` prefix and json-decodes the payload.
func parseDataFrame(t *testing.T, frame string) controlJournalEntry {
	t.Helper()
	if !strings.HasPrefix(frame, "data: ") {
		t.Fatalf("frame is not a data frame: %q", frame)
	}
	var e controlJournalEntry
	if err := json.Unmarshal([]byte(frame[len("data: "):]), &e); err != nil {
		t.Fatalf("decode entry: %v (frame=%q)", err, frame)
	}
	return e
}

// streamRegisteredAcme registers tenant "acme" on the given state and returns
// its tenantState.
func streamRegisteredAcme(t *testing.T, state *serverState) *tenantState {
	t.Helper()
	body := registerTenantRequest{TenantID: "acme", Name: "Acme Corp", SizeBytes: 1 << 30}
	if rr := doAdminRequest(state, http.MethodPost, "/control/tenants", body); rr.Code != http.StatusOK {
		t.Fatalf("register status=%d body=%s", rr.Code, rr.Body.String())
	}
	ts, ok := state.tenant("acme")
	if !ok {
		t.Fatal("tenant acme not found after registration")
	}
	return ts
}

func TestControlJournalStream_LiveBroadcastDelivered(t *testing.T) {
	exec := &fakeExec{}
	state, _ := newAdminTestState(t, exec)
	ts := streamRegisteredAcme(t, state)

	resp, cleanup := startControlStream(t, state,
		"/control/tenants/acme/journal/stream?allocation_id=alloc_live")
	defer cleanup()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("Content-Type=%q, want text/event-stream", ct)
	}

	reader := bufio.NewReader(resp.Body)

	// Give the handler a moment to register its pub/sub subscription before
	// we broadcast — otherwise Broadcast happens with no subscribers.
	waitForSubscribers(t, ts, "alloc_live", 1)

	insertJournalRowDirect(t, ts, "sess_live", "alloc_live", "agent_l", "/live.txt")
	// Mirror the production path's post-commit broadcast.
	ts.journal.Broadcast("alloc_live", SessionJournalEntry{
		SessionID:    "sess_live",
		AllocationID: "alloc_live",
		Seq:          1,
		Path:         "/live.txt",
		Op:           SessionOpCreate,
		TsUnixMs:     time.Now().UnixMilli(),
	})

	frame := readSSEFrameWithTimeout(t, reader, 500*time.Millisecond)
	entry := parseDataFrame(t, frame)
	if entry.AllocationID != "alloc_live" {
		t.Errorf("allocation_id = %q, want alloc_live", entry.AllocationID)
	}
	if entry.Path != "/live.txt" {
		t.Errorf("path = %q, want /live.txt", entry.Path)
	}
	if entry.Op != string(SessionOpCreate) {
		t.Errorf("op = %q, want create", entry.Op)
	}
	if entry.Seq == 0 {
		t.Errorf("seq = 0, want >0")
	}
}

// TestControlJournalStream_LiveBroadcastCarriesAgentID locks in the
// fix for the silent agent_id drop: the SSE-serialised live entry must
// expose the agent_id the broadcaster set, matching what catch-up rows
// (loaded from SQL) carry.
func TestControlJournalStream_LiveBroadcastCarriesAgentID(t *testing.T) {
	exec := &fakeExec{}
	state, _ := newAdminTestState(t, exec)
	ts := streamRegisteredAcme(t, state)

	resp, cleanup := startControlStream(t, state,
		"/control/tenants/acme/journal/stream?allocation_id=alloc_agent")
	defer cleanup()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	reader := bufio.NewReader(resp.Body)
	waitForSubscribers(t, ts, "alloc_agent", 1)

	const wantAgent = "user:abc"
	insertJournalRowDirect(t, ts, "sess_agent", "alloc_agent", wantAgent, "/a.txt")
	ts.journal.Broadcast("alloc_agent", SessionJournalEntry{
		SessionID: "sess_agent", AllocationID: "alloc_agent", AgentID: wantAgent,
		Seq: 1, Path: "/a.txt", Op: SessionOpCreate, TsUnixMs: time.Now().UnixMilli(),
	})

	frame := readSSEFrameWithTimeout(t, reader, 500*time.Millisecond)
	entry := parseDataFrame(t, frame)
	if entry.AgentID != wantAgent {
		t.Fatalf("agent_id = %q, want %q (live broadcast must propagate AgentID)", entry.AgentID, wantAgent)
	}
}

func TestControlJournalStream_CatchUpThenLiveNoDuplicates(t *testing.T) {
	exec := &fakeExec{}
	state, _ := newAdminTestState(t, exec)
	ts := streamRegisteredAcme(t, state)

	// Seed three rows: seqs 1..3 for the session.
	insertJournalRowDirect(t, ts, "sess_x", "alloc_catchup", "agent_x", "/a.txt")
	insertJournalRowDirect(t, ts, "sess_x", "alloc_catchup", "agent_x", "/b.txt")
	insertJournalRowDirect(t, ts, "sess_x", "alloc_catchup", "agent_x", "/c.txt")

	// Client claims to have seen seq=1; expects 2 and 3 via catch-up.
	resp, cleanup := startControlStream(t, state,
		"/control/tenants/acme/journal/stream?allocation_id=alloc_catchup&after_seq=1")
	defer cleanup()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	reader := bufio.NewReader(resp.Body)

	frame1 := readSSEFrameWithTimeout(t, reader, 500*time.Millisecond)
	e1 := parseDataFrame(t, frame1)
	if e1.Seq != 2 || e1.Path != "/b.txt" {
		t.Fatalf("catch-up[0] = (seq=%d, path=%s), want (2, /b.txt)", e1.Seq, e1.Path)
	}
	frame2 := readSSEFrameWithTimeout(t, reader, 500*time.Millisecond)
	e2 := parseDataFrame(t, frame2)
	if e2.Seq != 3 || e2.Path != "/c.txt" {
		t.Fatalf("catch-up[1] = (seq=%d, path=%s), want (3, /c.txt)", e2.Seq, e2.Path)
	}

	// Wait for the handler to register its subscriber, then broadcast seq=4
	// via the live path. It must arrive — and only arrive once.
	waitForSubscribers(t, ts, "alloc_catchup", 1)

	insertJournalRowDirect(t, ts, "sess_x", "alloc_catchup", "agent_x", "/d.txt")
	ts.journal.Broadcast("alloc_catchup", SessionJournalEntry{
		SessionID: "sess_x", AllocationID: "alloc_catchup", Seq: 4,
		Path: "/d.txt", Op: SessionOpCreate, TsUnixMs: time.Now().UnixMilli(),
	})

	frame3 := readSSEFrameWithTimeout(t, reader, 500*time.Millisecond)
	e3 := parseDataFrame(t, frame3)
	if e3.Seq != 4 || e3.Path != "/d.txt" {
		t.Fatalf("live = (seq=%d, path=%s), want (4, /d.txt)", e3.Seq, e3.Path)
	}

	// Re-broadcasting a seq <= the highest sent must NOT produce a frame.
	ts.journal.Broadcast("alloc_catchup", SessionJournalEntry{
		SessionID: "sess_x", AllocationID: "alloc_catchup", Seq: 2,
		Path: "/b.txt", Op: SessionOpUpdate, TsUnixMs: time.Now().UnixMilli(),
	})

	// Expect a quiet window. We can't easily prove a negative; use a short
	// read with a deadline and assert the only thing that could arrive is
	// either (a) nothing, or (b) a keepalive. Use a 150ms window.
	dupCh := make(chan string, 1)
	go func() {
		f, err := readSSEFrame(reader)
		if err == nil && strings.HasPrefix(f, "data:") {
			dupCh <- f
		}
	}()
	select {
	case dup := <-dupCh:
		t.Fatalf("got duplicate data frame after live: %q", dup)
	case <-time.After(150 * time.Millisecond):
	}
}

func TestControlJournalStream_Keepalive(t *testing.T) {
	// Shorten the keepalive interval for the duration of this test so we
	// don't sit through 30s. Restored on cleanup.
	orig := streamKeepaliveInterval
	streamKeepaliveInterval = 50 * time.Millisecond
	defer func() { streamKeepaliveInterval = orig }()

	exec := &fakeExec{}
	state, _ := newAdminTestState(t, exec)
	streamRegisteredAcme(t, state)

	resp, cleanup := startControlStream(t, state,
		"/control/tenants/acme/journal/stream?allocation_id=alloc_idle")
	defer cleanup()
	reader := bufio.NewReader(resp.Body)

	frame := readSSEFrameWithTimeout(t, reader, time.Second)
	if !strings.HasPrefix(frame, ": keepalive") {
		t.Fatalf("expected keepalive comment, got %q", frame)
	}
}

func TestControlJournalStream_ContextCancelNoGoroutineLeak(t *testing.T) {
	exec := &fakeExec{}
	state, _ := newAdminTestState(t, exec)
	ts := streamRegisteredAcme(t, state)

	runtime.GC()
	time.Sleep(20 * time.Millisecond)
	before := runtime.NumGoroutine()

	// Open and close 5 streams. Each handler should drop its subscriber on
	// resp.Body.Close() (server-side r.Context() cancels).
	for i := 0; i < 5; i++ {
		resp, cleanup := startControlStream(t, state,
			"/control/tenants/acme/journal/stream?allocation_id=alloc_cancel")
		if resp.StatusCode != http.StatusOK {
			cleanup()
			t.Fatalf("iter %d: status=%d", i, resp.StatusCode)
		}
		waitForSubscribers(t, ts, "alloc_cancel", 1)
		cleanup()
	}

	// Wait for handler goroutines + the pub/sub watchdogs to wind down.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if mapEmpty(ts, "alloc_cancel") && runtime.NumGoroutine()-before <= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if !mapEmpty(ts, "alloc_cancel") {
		t.Fatalf("subscribers not cleared from pub/sub map")
	}
	if diff := runtime.NumGoroutine() - before; diff > 2 {
		t.Fatalf("goroutine leak: before=%d after=%d diff=%d", before, runtime.NumGoroutine(), diff)
	}
}

func TestControlJournalStream_MissingAllocationID(t *testing.T) {
	exec := &fakeExec{}
	state, _ := newAdminTestState(t, exec)
	streamRegisteredAcme(t, state)

	rr := doAdminRequest(state, http.MethodGet,
		"/control/tenants/acme/journal/stream", nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestControlJournalStream_UnknownTenantReturns404(t *testing.T) {
	exec := &fakeExec{}
	state, _ := newAdminTestState(t, exec)

	rr := doAdminRequest(state, http.MethodGet,
		"/control/tenants/ghost/journal/stream?allocation_id=alloc_x", nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestControlJournalStream_RequiresControlPlaneCert(t *testing.T) {
	exec := &fakeExec{}
	state, _ := newAdminTestState(t, exec)

	req := httptest.NewRequest(http.MethodGet,
		"/control/tenants/acme/journal/stream?allocation_id=alloc_x", nil)
	rr := httptest.NewRecorder()
	newRouter(state).ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d", rr.Code)
	}
}

// waitForSubscribers polls the tenant's pub/sub map until at least `want`
// subscribers are registered for allocID, or fails the test after 500ms.
func waitForSubscribers(t *testing.T, ts *tenantState, allocID string, want int) {
	t.Helper()
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		ts.journal.pubsub.mu.RLock()
		got := len(ts.journal.pubsub.subs[allocID])
		ts.journal.pubsub.mu.RUnlock()
		if got >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("subscribers for %q not registered within 500ms", allocID)
}

func mapEmpty(ts *tenantState, allocID string) bool {
	ts.journal.pubsub.mu.RLock()
	defer ts.journal.pubsub.mu.RUnlock()
	return len(ts.journal.pubsub.subs[allocID]) == 0
}

