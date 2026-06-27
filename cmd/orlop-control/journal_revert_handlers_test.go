package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage/postgres/db/sqlcdb"
)

// Local aliases keep the test file's imports light and the call sites
// terse without dragging the sqlcdb package name through every line.
type sqlcdbCreateTenantParams = sqlcdb.CreateTenantParams
type sqlcdbCreateUserParams = sqlcdb.CreateUserParams

func sqlcdbForTest(pool *pgxpool.Pool) *sqlcdb.Queries { return sqlcdb.New(pool) }

// postRevert is a small helper that posts a JSON body to
// /api/v1/journal/revert, optionally adding cookie or query string. Returns
// the *http.Response so the test can assert status + body.
func postRevert(t *testing.T, srvURL string, cookie *http.Cookie, query string, body any) *http.Response {
	t.Helper()
	url := srvURL + "/api/v1/journal/revert"
	if query != "" {
		url += "?" + query
	}
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// TestJournalRevertBearerHappyPath — cookie auth + owned allocation_id →
// querier sees the call and returns ok:true.
func TestJournalRevertBearerHappyPath(t *testing.T) {
	pool := httpOpenTestPool(t)
	jq := &fakeJournal{revertResult: revertResult{Ok: true}}
	srv, svc := startJournalServer(t, pool, jq)
	cookie, _ := httpSeedAdmin(t, pool, svc)
	userID := dashGetUserID(t, cookie, srv.URL)

	alloc, err := dashAllocSvc(pool).Allocate(context.Background(), userID, dashGiB)
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	allocID := uuidString(alloc.ID)

	resp := postRevert(t, srv.URL, cookie, "", map[string]any{
		"allocation_id": allocID,
		"path":          "/notes.md",
		"seq":           42,
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, b)
	}
	var got journalRevertResponseJSON
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if !got.Ok {
		t.Fatalf("ok=false, want true: %+v", got)
	}
	if jq.gotRevertPath != "/notes.md" || jq.gotRevertSeq != 42 || jq.gotRevertForce {
		t.Fatalf("forwarded args wrong: path=%q seq=%d force=%v", jq.gotRevertPath, jq.gotRevertSeq, jq.gotRevertForce)
	}
	if jq.gotAllocationID != allocID {
		t.Fatalf("allocation_id forwarded=%q want %q", jq.gotAllocationID, allocID)
	}
	if !strings.HasPrefix(jq.gotRevertAgent, "user:") {
		t.Fatalf("agent_id=%q, want user:<uuid>", jq.gotRevertAgent)
	}
}

// TestJournalRevertConflictPassthrough — fake returns ok:false → handler
// echoes the body without rewriting (200 OK, not 4xx).
func TestJournalRevertConflictPassthrough(t *testing.T) {
	pool := httpOpenTestPool(t)
	jq := &fakeJournal{revertResult: revertResult{Ok: false, Conflict: &revertConflict{Reason: "concurrent_writer"}}}
	srv, svc := startJournalServer(t, pool, jq)
	cookie, _ := httpSeedAdmin(t, pool, svc)
	userID := dashGetUserID(t, cookie, srv.URL)

	alloc, err := dashAllocSvc(pool).Allocate(context.Background(), userID, dashGiB)
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}

	resp := postRevert(t, srv.URL, cookie, "", map[string]any{
		"allocation_id": uuidString(alloc.ID),
		"path":          "/x",
		"seq":           1,
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	var got journalRevertResponseJSON
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Ok {
		t.Fatalf("ok=true, want false")
	}
	if got.Conflict == nil || got.Conflict.Reason != "concurrent_writer" {
		t.Fatalf("conflict mismatch: %+v", got.Conflict)
	}
}

// TestJournalRevertForceTrue — handler forwards force=true to the backend.
func TestJournalRevertForceTrue(t *testing.T) {
	pool := httpOpenTestPool(t)
	jq := &fakeJournal{revertResult: revertResult{Ok: true}}
	srv, svc := startJournalServer(t, pool, jq)
	cookie, _ := httpSeedAdmin(t, pool, svc)
	userID := dashGetUserID(t, cookie, srv.URL)
	alloc, err := dashAllocSvc(pool).Allocate(context.Background(), userID, dashGiB)
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}

	resp := postRevert(t, srv.URL, cookie, "", map[string]any{
		"allocation_id": uuidString(alloc.ID),
		"path":          "/x",
		"seq":           7,
		"force":         true,
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	if !jq.gotRevertForce {
		t.Fatalf("force not forwarded: %+v", jq)
	}
}

// TestJournalRevertMissingFields — 400 on missing path / seq / allocation_id.
func TestJournalRevertMissingFields(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv, svc := startJournalServer(t, pool, &fakeJournal{})
	cookie, _ := httpSeedAdmin(t, pool, svc)

	tests := []struct {
		name string
		body map[string]any
	}{
		{"missing path", map[string]any{"allocation_id": "00000000-0000-0000-0000-000000000000", "seq": 1}},
		{"missing seq", map[string]any{"allocation_id": "00000000-0000-0000-0000-000000000000", "path": "/x"}},
		{"missing allocation_id", map[string]any{"path": "/x", "seq": 1}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := postRevert(t, srv.URL, cookie, "", tc.body)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status=%d, want 400", resp.StatusCode)
			}
		})
	}
}

// TestJournalRevertRejectsOtherUserAllocation — user A tries to revert user
// B's allocation → 404 (don't reveal ownership).
func TestJournalRevertRejectsOtherUserAllocation(t *testing.T) {
	pool := httpOpenTestPool(t)
	jq := &fakeJournal{revertResult: revertResult{Ok: true}}
	srv, svc := startJournalServer(t, pool, jq)
	cookie, _ := httpSeedAdmin(t, pool, svc)

	q := sqlcdbForTest(pool)
	if _, err := q.CreateTenant(context.Background(), sqlcdbCreateTenantParams{ID: "other-tenant-revert", Name: "Other"}); err != nil {
		t.Fatal(err)
	}
	bob, err := q.CreateUser(context.Background(), sqlcdbCreateUserParams{Email: "bob-revert@other-tenant.example", TenantID: "other-tenant-revert"})
	if err != nil {
		t.Fatal(err)
	}
	bobsAlloc, err := dashAllocSvc(pool).Allocate(context.Background(), bob.ID, dashGiB)
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}

	resp := postRevert(t, srv.URL, cookie, "", map[string]any{
		"allocation_id": uuidString(bobsAlloc.ID),
		"path":          "/x",
		"seq":           1,
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status=%d, want 404", resp.StatusCode)
	}
	if jq.gotRevertPath != "" {
		t.Fatalf("querier should not have been called on cross-user reject")
	}
}

// TestJournalRevertBackendError — querier returns a real error → 502.
func TestJournalRevertBackendError(t *testing.T) {
	pool := httpOpenTestPool(t)
	jq := &fakeJournal{revertErr: errors.New("boom")}
	srv, svc := startJournalServer(t, pool, jq)
	cookie, _ := httpSeedAdmin(t, pool, svc)
	userID := dashGetUserID(t, cookie, srv.URL)
	alloc, err := dashAllocSvc(pool).Allocate(context.Background(), userID, dashGiB)
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	resp := postRevert(t, srv.URL, cookie, "", map[string]any{
		"allocation_id": uuidString(alloc.ID),
		"path":          "/x",
		"seq":           1,
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status=%d, want 502", resp.StatusCode)
	}
}
