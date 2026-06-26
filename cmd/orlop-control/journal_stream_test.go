package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// dialJournalWS dials /api/v1/journal/stream over WebSocket against the
// supplied httptest server, attaching an optional admin cookie. Returns the
// dialed *websocket.Conn; the caller closes it.
func dialJournalWS(t *testing.T, srvURL string, cookie *http.Cookie, query string) (*websocket.Conn, *http.Response) {
	t.Helper()
	u, err := url.Parse(srvURL + "/api/v1/journal/stream")
	if err != nil {
		t.Fatal(err)
	}
	u.Scheme = "ws"
	if query != "" {
		u.RawQuery = query
	}
	header := http.Header{}
	if cookie != nil {
		header.Set("Cookie", cookie.Name+"="+cookie.Value)
	}
	conn, resp, err := websocket.DefaultDialer.Dial(u.String(), header)
	if err != nil {
		// Return the response (if any) so the caller can assert on the HTTP
		// status; otherwise re-raise.
		if resp != nil {
			return nil, resp
		}
		t.Fatalf("ws dial: %v", err)
	}
	return conn, resp
}

// TestJournalStreamAppendedFrame — server-side StreamJournal channel emits
// an entry; WS client receives a JSON {"event":"appended","entry":{...}}.
func TestJournalStreamAppendedFrame(t *testing.T) {
	// Tighten the ping ticker so the test doesn't pay 30s of wall clock.
	prevKA := journalWSKeepalive
	journalWSKeepalive = 50 * time.Millisecond
	t.Cleanup(func() { journalWSKeepalive = prevKA })

	pool := httpOpenTestPool(t)
	streamCh := make(chan journalEntryJSON, 4)
	jq := &fakeJournal{stream: streamCh}
	srv, svc := startJournalServer(t, pool, jq)
	cookie, _ := httpSeedAdmin(t, pool, svc)
	userID := dashGetUserID(t, cookie, srv.URL)
	alloc, err := dashAllocSvc(pool).Allocate(context.Background(), userID, dashGiB)
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	allocID := uuidString(alloc.ID)

	conn, _ := dialJournalWS(t, srv.URL, cookie, "allocation_id="+allocID+"&after_seq=12")
	defer conn.Close()

	if jq.gotAfterSeq != 12 {
		t.Fatalf("after_seq forwarded to streamer = %d, want 12", jq.gotAfterSeq)
	}

	streamCh <- journalEntryJSON{AllocationID: allocID, Seq: 13, Path: "/foo.md", Op: "create"}

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, data, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var frame journalWSFrame
	if err := json.Unmarshal(data, &frame); err != nil {
		t.Fatal(err)
	}
	if frame.Event != "appended" {
		t.Fatalf("event=%q, want appended", frame.Event)
	}
	if frame.Entry == nil || frame.Entry.Seq != 13 || frame.Entry.Path != "/foo.md" {
		t.Fatalf("entry=%+v", frame.Entry)
	}
}

// TestJournalStreamPingFrame — when no entries flow the handler emits
// {"event":"ping"} on the keepalive ticker.
func TestJournalStreamPingFrame(t *testing.T) {
	prev := journalWSKeepalive
	journalWSKeepalive = 50 * time.Millisecond
	t.Cleanup(func() { journalWSKeepalive = prev })

	pool := httpOpenTestPool(t)
	streamCh := make(chan journalEntryJSON, 1) // never written to
	jq := &fakeJournal{stream: streamCh}
	srv, svc := startJournalServer(t, pool, jq)
	cookie, _ := httpSeedAdmin(t, pool, svc)
	userID := dashGetUserID(t, cookie, srv.URL)
	alloc, err := dashAllocSvc(pool).Allocate(context.Background(), userID, dashGiB)
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	allocID := uuidString(alloc.ID)

	conn, _ := dialJournalWS(t, srv.URL, cookie, "allocation_id="+allocID)
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	_, data, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var frame journalWSFrame
	if err := json.Unmarshal(data, &frame); err != nil {
		t.Fatal(err)
	}
	if frame.Event != "ping" {
		t.Fatalf("first frame event=%q, want ping", frame.Event)
	}
}

// TestJournalStreamClosesOnUpstreamClose — when the upstream channel closes
// (server-side EOF), the WS handler returns and the client sees an error.
func TestJournalStreamClosesOnUpstreamClose(t *testing.T) {
	prev := journalWSKeepalive
	journalWSKeepalive = time.Hour // suppress pings for this test
	t.Cleanup(func() { journalWSKeepalive = prev })

	pool := httpOpenTestPool(t)
	streamCh := make(chan journalEntryJSON)
	jq := &fakeJournal{stream: streamCh}
	srv, svc := startJournalServer(t, pool, jq)
	cookie, _ := httpSeedAdmin(t, pool, svc)
	userID := dashGetUserID(t, cookie, srv.URL)
	alloc, err := dashAllocSvc(pool).Allocate(context.Background(), userID, dashGiB)
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	allocID := uuidString(alloc.ID)

	conn, _ := dialJournalWS(t, srv.URL, cookie, "allocation_id="+allocID)
	defer conn.Close()

	// Close upstream → handler returns → server closes the WS.
	close(streamCh)

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := conn.ReadMessage(); err == nil {
		t.Fatal("expected read error after upstream close")
	}
}

// TestJournalStreamRequiresAuth — no cookie → 401 with the upgrade refused.
func TestJournalStreamRequiresAuth(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv, _ := startJournalServer(t, pool, &fakeJournal{})
	_, resp := dialJournalWS(t, srv.URL, nil, "allocation_id=00000000-0000-0000-0000-000000000000")
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%v, want 401", resp)
	}
}

// TestJournalStreamMissingAllocation — handler returns 400 if allocation_id
// is omitted.
func TestJournalStreamMissingAllocation(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv, svc := startJournalServer(t, pool, &fakeJournal{})
	cookie, _ := httpSeedAdmin(t, pool, svc)
	_, resp := dialJournalWS(t, srv.URL, cookie, "")
	if resp == nil || resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%v, want 400", resp)
	}
}
