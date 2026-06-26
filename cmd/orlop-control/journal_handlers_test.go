package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/allocations"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/db/sqlcdb"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/devauth"
)

// fakeJournal is a test double for journalQuerier.
type fakeJournal struct {
	// entries is keyed by allocationID; empty key "" is the merged feed.
	entries map[string][]journalEntryJSON
	// afterSeqEntries is keyed by allocationID; entries returned for
	// QueryJournalAfterSeq when afterSeq < entry.Seq.
	afterSeqEntries map[string][]journalEntryJSON
	// stream is an optional channel returned by StreamJournal; tests
	// drive it directly. If nil, StreamJournal returns an empty closed
	// channel.
	stream chan journalEntryJSON
	// streamErr forces StreamJournal to error before returning a channel.
	streamErr error
	// revertResult / revertErr drive the response of RevertPath.
	revertResult revertResult
	revertErr    error
	err          error
	// captured args from the last call
	gotTenant        string
	gotAllocationID  string
	gotLimit         uint32
	gotCursor        string
	gotAfterSeq      uint64
	gotRevertSession string
	gotRevertPath    string
	gotRevertSeq     uint64
	gotRevertForce   bool
	gotRevertAgent   string
}

func (f *fakeJournal) QueryJournal(
	_ context.Context,
	tenantID, allocationID string,
	limit uint32,
	cursor string,
) ([]journalEntryJSON, string, error) {
	f.gotTenant = tenantID
	f.gotAllocationID = allocationID
	f.gotLimit = limit
	f.gotCursor = cursor
	if f.err != nil {
		return nil, "", f.err
	}
	all := f.entries[allocationID]
	if uint32(len(all)) > limit {
		page := all[:limit]
		return page, "more", nil // non-empty opaque cursor ⇒ more pages
	}
	return all, "", nil
}

func (f *fakeJournal) QueryJournalAfterSeq(
	_ context.Context,
	tenantID, allocationID string,
	limit uint32,
	afterSeq uint64,
) ([]journalEntryJSON, error) {
	f.gotTenant = tenantID
	f.gotAllocationID = allocationID
	f.gotLimit = limit
	f.gotAfterSeq = afterSeq
	if f.err != nil {
		return nil, f.err
	}
	src := f.afterSeqEntries[allocationID]
	out := make([]journalEntryJSON, 0, len(src))
	for _, e := range src {
		if e.Seq > afterSeq {
			out = append(out, e)
		}
	}
	if limit > 0 && uint32(len(out)) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (f *fakeJournal) StreamJournal(
	_ context.Context,
	tenantID, allocationID string,
	afterSeq uint64,
) (<-chan journalEntryJSON, error) {
	f.gotTenant = tenantID
	f.gotAllocationID = allocationID
	f.gotAfterSeq = afterSeq
	if f.streamErr != nil {
		return nil, f.streamErr
	}
	if f.stream != nil {
		return f.stream, nil
	}
	ch := make(chan journalEntryJSON)
	close(ch)
	return ch, nil
}

func (f *fakeJournal) RevertPath(
	_ context.Context,
	tenantID, allocationID, sessionID, path string,
	seq uint64,
	force bool,
	agentID string,
) (revertResult, error) {
	f.gotTenant = tenantID
	f.gotAllocationID = allocationID
	f.gotRevertSession = sessionID
	f.gotRevertPath = path
	f.gotRevertSeq = seq
	f.gotRevertForce = force
	f.gotRevertAgent = agentID
	if f.revertErr != nil {
		return revertResult{}, f.revertErr
	}
	return f.revertResult, nil
}

func startJournalServer(t *testing.T, pool *pgxpool.Pool, jq journalQuerier) (*httptest.Server, *devauth.Service) {
	t.Helper()
	svc := devauth.NewService(pool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	router := newRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), runtimeDeps{
		devAuth:        svc,
		queries:        sqlcdb.New(pool),
		allocations:    allocations.NewService(pool, nil),
		mailer:         newFakeMailer(),
		journalQuerier: jq,
	}, config{})
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	return srv, svc
}

// journalGet is a small helper that sends GET /api/v1/journal with optional
// query params and optional auth cookie. It returns the *http.Response.
func journalGet(t *testing.T, srvURL string, cookie *http.Cookie, query string) *http.Response {
	t.Helper()
	url := srvURL + "/api/v1/journal"
	if query != "" {
		url += "?" + query
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// TestJournalHandlerRequiresAuth — no bearer token → 401.
func TestJournalHandlerRequiresAuth(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv, _ := startJournalServer(t, pool, &fakeJournal{})

	resp := journalGet(t, srv.URL, nil, "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d; want 401", resp.StatusCode)
	}
}

// TestJournalHandlerReturnsMergedFeed — user with 2 allocations, no
// allocation_id filter → all rows from the fake querier returned.
func TestJournalHandlerReturnsMergedFeed(t *testing.T) {
	pool := httpOpenTestPool(t)

	jq := &fakeJournal{
		entries: map[string][]journalEntryJSON{
			"": {
				{AllocationID: "alloc1", Seq: 2, TsUnixMs: 2000, Path: "/b", Op: "create"},
				{AllocationID: "alloc2", Seq: 1, TsUnixMs: 1000, Path: "/a", Op: "create"},
			},
		},
	}
	srv, svc := startJournalServer(t, pool, jq)
	cookie, _ := httpSeedAdmin(t, pool, svc)

	resp := journalGet(t, srv.URL, cookie, "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d body = %s", resp.StatusCode, body)
	}

	var got journalResponseJSON
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Entries) != 2 {
		t.Fatalf("len = %d, want 2", len(got.Entries))
	}
	// Newest first.
	if got.Entries[0].TsUnixMs != 2000 || got.Entries[1].TsUnixMs != 1000 {
		t.Fatalf("ordering wrong: %+v", got.Entries)
	}
	// Forwarded to querier with empty allocationID (merged-feed).
	if jq.gotAllocationID != "" {
		t.Fatalf("querier got allocation_id %q; want empty (merged feed)", jq.gotAllocationID)
	}
}

// TestJournalHandlerFiltersByAllocation — GET ?allocation_id=alloc1 → only
// alloc1 rows returned, ownership is verified via alloc.GetForUser.
func TestJournalHandlerFiltersByAllocation(t *testing.T) {
	pool := httpOpenTestPool(t)

	jq := &fakeJournal{
		entries: map[string][]journalEntryJSON{
			"alloc1": {
				{AllocationID: "alloc1", Seq: 1, TsUnixMs: 1000, Path: "/x", Op: "create"},
			},
		},
	}
	srv, svc := startJournalServer(t, pool, jq)
	cookie, _ := httpSeedAdmin(t, pool, svc)
	userID := dashGetUserID(t, cookie, srv.URL)

	asvc := dashAllocSvc(pool)
	alloc1, err := asvc.Allocate(context.Background(), userID, dashGiB)
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	alloc1ID := uuidString(alloc1.ID)

	resp := journalGet(t, srv.URL, cookie, "allocation_id="+alloc1ID)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d body = %s", resp.StatusCode, body)
	}

	var got journalResponseJSON
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Our fake returns the alloc1 entry for the real UUID allocation_id.
	// The handler passes the UUID through to the querier.
	if jq.gotAllocationID != alloc1ID {
		t.Fatalf("querier got allocation_id %q; want %q", jq.gotAllocationID, alloc1ID)
	}
}

// TestJournalHandlerRejectsOtherUserAllocation — user A tries to query user
// B's allocation_id → 404 (don't reveal ownership).
func TestJournalHandlerRejectsOtherUserAllocation(t *testing.T) {
	pool := httpOpenTestPool(t)
	jq := &fakeJournal{}
	srv, svc := startJournalServer(t, pool, jq)
	cookie, _ := httpSeedAdmin(t, pool, svc)

	// Create a second user + allocation they don't own.
	q := sqlcdb.New(pool)
	if _, err := q.CreateTenant(context.Background(), sqlcdb.CreateTenantParams{ID: "other-tenant", Name: "Other"}); err != nil {
		t.Fatal(err)
	}
	bob, err := q.CreateUser(context.Background(), sqlcdb.CreateUserParams{Email: "bob@other-tenant.example", TenantID: "other-tenant"})
	if err != nil {
		t.Fatal(err)
	}
	asvc := dashAllocSvc(pool)
	bobsAlloc, err := asvc.Allocate(context.Background(), bob.ID, dashGiB)
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}

	resp := journalGet(t, srv.URL, cookie, "allocation_id="+uuidString(bobsAlloc.ID))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d; want 404 (cross-user query rejected)", resp.StatusCode)
	}
}

// TestJournalHandlerHonorsLimit — fake querier truncates at limit, handler
// surfaces a non-empty next_cursor.
func TestJournalHandlerHonorsLimit(t *testing.T) {
	pool := httpOpenTestPool(t)

	// 10 entries in the merged feed.
	entries := make([]journalEntryJSON, 10)
	for i := range entries {
		entries[i] = journalEntryJSON{
			AllocationID: "a1",
			Seq:          uint64(10 - i),
			TsUnixMs:     int64(10000 - i*1000),
			Path:         "/f",
			Op:           "create",
		}
	}
	jq := &fakeJournal{
		entries: map[string][]journalEntryJSON{"": entries},
	}
	srv, svc := startJournalServer(t, pool, jq)
	cookie, _ := httpSeedAdmin(t, pool, svc)

	resp := journalGet(t, srv.URL, cookie, "limit=5")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d body = %s", resp.StatusCode, body)
	}

	var got journalResponseJSON
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Entries) != 5 {
		t.Fatalf("len = %d; want 5", len(got.Entries))
	}
	if got.NextCursor == "" {
		t.Fatalf("next_cursor empty; want non-empty (more pages available)")
	}
	if jq.gotLimit != 5 {
		t.Fatalf("querier got limit %d; want 5", jq.gotLimit)
	}
}

// TestJournalHandlerAfterSeqReturnsAscending — when after_seq is set the
// handler routes through QueryJournalAfterSeq and returns rows whose seq is
// strictly greater than the cursor, in ascending order. The keyset cursor is
// silently ignored in that mode.
func TestJournalHandlerAfterSeqReturnsAscending(t *testing.T) {
	pool := httpOpenTestPool(t)
	jq := &fakeJournal{
		afterSeqEntries: map[string][]journalEntryJSON{},
	}
	srv, svc := startJournalServer(t, pool, jq)
	cookie, _ := httpSeedAdmin(t, pool, svc)
	userID := dashGetUserID(t, cookie, srv.URL)
	alloc, err := dashAllocSvc(pool).Allocate(context.Background(), userID, dashGiB)
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	allocID := uuidString(alloc.ID)
	// Three rows in ascending-seq order; only seq>5 should come back.
	jq.afterSeqEntries[allocID] = []journalEntryJSON{
		{AllocationID: allocID, Seq: 4, TsUnixMs: 400, Path: "/a", Op: "create"},
		{AllocationID: allocID, Seq: 6, TsUnixMs: 600, Path: "/b", Op: "create"},
		{AllocationID: allocID, Seq: 7, TsUnixMs: 700, Path: "/c", Op: "create"},
	}

	resp := journalGet(t, srv.URL, cookie, "allocation_id="+allocID+"&after_seq=5&cursor=10000.7")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
	var got journalResponseJSON
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got.Entries) != 2 {
		t.Fatalf("len=%d, want 2 (seq>5)", len(got.Entries))
	}
	if got.Entries[0].Seq != 6 || got.Entries[1].Seq != 7 {
		t.Fatalf("ordering wrong: %+v", got.Entries)
	}
	if jq.gotAfterSeq != 5 {
		t.Fatalf("after_seq forwarded=%d, want 5", jq.gotAfterSeq)
	}
	// The keyset cursor must NOT be forwarded when after_seq is set; the
	// after_seq path never touches QueryJournal, so gotCursor stays empty.
	if jq.gotCursor != "" {
		t.Fatalf("cursor forwarded=%q, want empty (ignored)", jq.gotCursor)
	}
}

// TestJournalHandlerAfterSeqRequiresAllocation — after_seq without
// allocation_id → 400.
func TestJournalHandlerAfterSeqRequiresAllocation(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv, svc := startJournalServer(t, pool, &fakeJournal{})
	cookie, _ := httpSeedAdmin(t, pool, svc)

	resp := journalGet(t, srv.URL, cookie, "after_seq=5")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", resp.StatusCode)
	}
}

// TestJournalHandlerAfterSeqRespectsLimit — limit caps the result set.
func TestJournalHandlerAfterSeqRespectsLimit(t *testing.T) {
	pool := httpOpenTestPool(t)
	jq := &fakeJournal{
		afterSeqEntries: map[string][]journalEntryJSON{},
	}
	srv, svc := startJournalServer(t, pool, jq)
	cookie, _ := httpSeedAdmin(t, pool, svc)
	userID := dashGetUserID(t, cookie, srv.URL)
	alloc, err := dashAllocSvc(pool).Allocate(context.Background(), userID, dashGiB)
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	allocID := uuidString(alloc.ID)
	var entries []journalEntryJSON
	for i := 1; i <= 10; i++ {
		entries = append(entries, journalEntryJSON{
			AllocationID: allocID,
			Seq:          uint64(i),
			TsUnixMs:     int64(i * 100),
			Path:         "/f",
			Op:           "create",
		})
	}
	jq.afterSeqEntries[allocID] = entries

	resp := journalGet(t, srv.URL, cookie, "allocation_id="+allocID+"&after_seq=0&limit=3")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	var got journalResponseJSON
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got.Entries) != 3 {
		t.Fatalf("len=%d, want 3", len(got.Entries))
	}
}
