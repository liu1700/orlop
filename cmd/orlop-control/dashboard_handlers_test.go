package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/allocations"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage/postgres"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage/postgres/db/sqlcdb"
)

const dashGiB = int64(1) << 30

func dashSeedAgent(t *testing.T, pool *pgxpool.Pool, userID pgtype.UUID) pgtype.UUID {
	t.Helper()
	q := sqlcdb.New(pool)
	var serial [8]byte
	if _, err := rand.Read(serial[:]); err != nil {
		t.Fatal(err)
	}
	row, err := q.CreateAgentEnrollment(context.Background(), sqlcdb.CreateAgentEnrollmentParams{
		UserID:       userID,
		CertSerial:   hex.EncodeToString(serial[:]),
		CertNotAfter: pgtype.Timestamptz{Time: time.Now().Add(24 * time.Hour), Valid: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	return row.ID
}

func dashAllocSvc(pool *pgxpool.Pool) *allocations.Service {
	return allocations.NewService(postgres.New(pool), nil)
}

func dashGetUserID(t *testing.T, cookie *http.Cookie, srvURL string) pgtype.UUID {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srvURL+"/api/me", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/api/me status = %d", resp.StatusCode)
	}
	var me struct {
		UserID string `json:"user_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&me); err != nil {
		t.Fatal(err)
	}
	var uid pgtype.UUID
	if err := uid.Scan(me.UserID); err != nil {
		t.Fatalf("parse user uuid %q: %v", me.UserID, err)
	}
	return uid
}

func TestDashboardListAllocationsRequiresAuth(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv, _ := httpStartServer(t, pool)

	resp, err := http.Get(srv.URL + "/api/allocations")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestDashboardRevokeRequiresAuth(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv, _ := httpStartServer(t, pool)

	resp, err := http.Post(srv.URL+"/api/allocations/00000000-0000-0000-0000-000000000000/revoke", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestDashboardListAllocationsShape(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv, svc := httpStartServer(t, pool)
	cookie, _ := httpSeedAdmin(t, pool, svc)
	userID := dashGetUserID(t, cookie, srv.URL)
	asvc := dashAllocSvc(pool)

	idle, err := asvc.Allocate(context.Background(), userID, 2*dashGiB)
	if err != nil {
		t.Fatal(err)
	}
	mounted, err := asvc.Allocate(context.Background(), userID, 3*dashGiB)
	if err != nil {
		t.Fatal(err)
	}
	agentID := dashSeedAgent(t, pool, userID)
	if _, err := asvc.Bind(context.Background(), mounted.ID, userID, agentID); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if _, err := asvc.AcquireMountLease(context.Background(), mounted.ID, agentID, allocations.LeaseTTL); err != nil {
		t.Fatalf("acquire lease: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/allocations", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d body = %s", resp.StatusCode, body)
	}
	var got struct {
		Allocations []allocationDTO `json:"allocations"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got.Allocations) != 2 {
		t.Fatalf("len = %d, want 2", len(got.Allocations))
	}
	// Newest first.
	if got.Allocations[0].SizeBytes != 3*dashGiB || got.Allocations[1].SizeBytes != 2*dashGiB {
		t.Fatalf("ordering wrong: %+v", got.Allocations)
	}
	if got.Allocations[0].MountedAgentID == "" {
		t.Fatalf("mounted alloc missing agent id: %+v", got.Allocations[0])
	}
	if len(got.Allocations[0].MountedAgentID) != 8 {
		t.Fatalf("agent id not short form: %q", got.Allocations[0].MountedAgentID)
	}
	if got.Allocations[1].MountedAgentID != "" {
		t.Fatalf("idle alloc should not have agent id: %+v", got.Allocations[1])
	}
	_ = idle
}

func TestDashboardListAllocationsScopedToCaller(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv, svc := httpStartServer(t, pool)
	cookie, _ := httpSeedAdmin(t, pool, svc)
	userID := dashGetUserID(t, cookie, srv.URL)
	asvc := dashAllocSvc(pool)

	// Allocation owned by another user should not appear.
	q := sqlcdb.New(pool)
	if _, err := q.CreateTenant(context.Background(), sqlcdb.CreateTenantParams{ID: "other", Name: "Other"}); err != nil {
		t.Fatal(err)
	}
	other, err := q.CreateUser(context.Background(), sqlcdb.CreateUserParams{Email: "bob@other.example", TenantID: "other"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := asvc.Allocate(context.Background(), other.ID, dashGiB); err != nil {
		t.Fatal(err)
	}
	if _, err := asvc.Allocate(context.Background(), userID, dashGiB); err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/allocations", nil)
	req.AddCookie(cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got struct {
		Allocations []allocationDTO `json:"allocations"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got.Allocations) != 1 {
		t.Fatalf("len = %d, want 1 (only caller's)", len(got.Allocations))
	}
}

func TestDashboardRevokeSuccess(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv, svc := httpStartServer(t, pool)
	cookie, _ := httpSeedAdmin(t, pool, svc)
	userID := dashGetUserID(t, cookie, srv.URL)
	asvc := dashAllocSvc(pool)

	a, err := asvc.Allocate(context.Background(), userID, dashGiB)
	if err != nil {
		t.Fatal(err)
	}
	allocID := uuidString(a.ID)

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/allocations/"+allocID+"/revoke", nil)
	req.AddCookie(cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d body = %s", resp.StatusCode, body)
	}

	rows, err := asvc.ListForUser(context.Background(), userID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("revoked allocation still listed: %+v", rows)
	}
}

func TestDashboardRevokeIdempotent(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv, svc := httpStartServer(t, pool)
	cookie, _ := httpSeedAdmin(t, pool, svc)
	userID := dashGetUserID(t, cookie, srv.URL)
	asvc := dashAllocSvc(pool)

	a, err := asvc.Allocate(context.Background(), userID, dashGiB)
	if err != nil {
		t.Fatal(err)
	}
	url := srv.URL + "/api/allocations/" + uuidString(a.ID) + "/revoke"

	for i := 0; i < 2; i++ {
		req, _ := http.NewRequest(http.MethodPost, url, nil)
		req.AddCookie(cookie)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("attempt %d status = %d, want 204", i, resp.StatusCode)
		}
	}
}

func TestDashboardRevokeOtherUserReturns404(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv, svc := httpStartServer(t, pool)
	cookie, _ := httpSeedAdmin(t, pool, svc)
	asvc := dashAllocSvc(pool)

	q := sqlcdb.New(pool)
	if _, err := q.CreateTenant(context.Background(), sqlcdb.CreateTenantParams{ID: "victim", Name: "Victim"}); err != nil {
		t.Fatal(err)
	}
	victim, err := q.CreateUser(context.Background(), sqlcdb.CreateUserParams{Email: "victim@x.example", TenantID: "victim"})
	if err != nil {
		t.Fatal(err)
	}
	a, err := asvc.Allocate(context.Background(), victim.ID, dashGiB)
	if err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/allocations/"+uuidString(a.ID)+"/revoke", nil)
	req.AddCookie(cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	// Confirm victim's allocation is still active.
	rows, err := asvc.ListForUser(context.Background(), victim.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("victim allocation tampered: %+v", rows)
	}
}

func TestDashboardRevokeBadIDReturns400(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv, svc := httpStartServer(t, pool)
	cookie, _ := httpSeedAdmin(t, pool, svc)

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/allocations/not-a-uuid/revoke", nil)
	req.AddCookie(cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "invalid_request") {
		t.Fatalf("body = %s", body)
	}
}

// testAllocationDTO mirrors allocationDTO for decoding responses in
// mount-status tests without exporting the production struct.
type testAllocationDTO struct {
	ID                  string `json:"id"`
	SizeBytes           int64  `json:"size_bytes"`
	CreatedAt           string `json:"created_at"`
	MountStatus         string `json:"mount_status"`
	MountedAgentID      string `json:"mounted_agent_id,omitempty"`
	MountLeaseExpiresAt string `json:"mount_lease_expires_at,omitempty"`
}

// dashboardResponseForLease returns an HTTP response for GET /api/allocations
// where the single allocation is bound + has a lease whose expiry is set to
// leaseExpiresAt via a direct SQL UPDATE (bypassing LeaseTTL).
func dashboardResponseForLease(t *testing.T, leaseExpiresAt time.Time) *http.Response {
	t.Helper()
	pool := httpOpenTestPool(t)
	srv, svc := httpStartServer(t, pool)
	cookie, _ := httpSeedAdmin(t, pool, svc)
	userID := dashGetUserID(t, cookie, srv.URL)
	asvc := dashAllocSvc(pool)

	a, err := asvc.Allocate(context.Background(), userID, dashGiB)
	if err != nil {
		t.Fatal(err)
	}
	agentID := dashSeedAgent(t, pool, userID)
	if _, err := asvc.Bind(context.Background(), a.ID, userID, agentID); err != nil {
		t.Fatalf("bind: %v", err)
	}
	// Acquire a real lease first (satisfies the DB constraint), then overwrite
	// lease_expires_at with the exact time we need to test the threshold.
	if _, err := asvc.AcquireMountLease(context.Background(), a.ID, agentID, allocations.LeaseTTL); err != nil {
		t.Fatalf("acquire lease: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		"UPDATE disk_allocations SET lease_expires_at = $1 WHERE id = $2",
		leaseExpiresAt, a.ID,
	); err != nil {
		t.Fatalf("set lease_expires_at: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/allocations", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// dashboardResponseForUnbound returns an HTTP response for GET /api/allocations
// where the single allocation has no bound agent (Free state).
func dashboardResponseForUnbound(t *testing.T) *http.Response {
	t.Helper()
	pool := httpOpenTestPool(t)
	srv, svc := httpStartServer(t, pool)
	cookie, _ := httpSeedAdmin(t, pool, svc)
	userID := dashGetUserID(t, cookie, srv.URL)
	asvc := dashAllocSvc(pool)

	if _, err := asvc.Allocate(context.Background(), userID, dashGiB); err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/allocations", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// decodeAllocations decodes the "allocations" array from an /api/allocations
// JSON response into []testAllocationDTO.
func decodeAllocations(t *testing.T, resp *http.Response) []testAllocationDTO {
	t.Helper()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d body = %s", resp.StatusCode, body)
	}
	var got struct {
		Allocations []testAllocationDTO `json:"allocations"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	return got.Allocations
}

func TestDashboardListAllocationsMountStatusMounted(t *testing.T) {
	// Lease refreshed within the threshold (60s TTL, refresh every 30s,
	// horizon = now + 30s). Server marks Mounted.
	resp := dashboardResponseForLease(t, time.Now().Add(45*time.Second))
	allocs := decodeAllocations(t, resp)
	if len(allocs) != 1 {
		t.Fatalf("len = %d, want 1", len(allocs))
	}
	if allocs[0].MountStatus != "mounted" {
		t.Errorf("mount_status = %q, want %q", allocs[0].MountStatus, "mounted")
	}
	if allocs[0].MountedAgentID == "" {
		t.Errorf("mounted_agent_id is empty, want non-empty")
	}
}

func TestDashboardListAllocationsMountStatusJustInsideThreshold(t *testing.T) {
	// lease_expires_at = now + 31s — still > horizon of now + 30s.
	resp := dashboardResponseForLease(t, time.Now().Add(31*time.Second))
	allocs := decodeAllocations(t, resp)
	if len(allocs) != 1 {
		t.Fatalf("len = %d, want 1", len(allocs))
	}
	if allocs[0].MountStatus != "mounted" {
		t.Errorf("mount_status = %q, want %q", allocs[0].MountStatus, "mounted")
	}
}

func TestDashboardListAllocationsMountStatusJustOutsideThreshold(t *testing.T) {
	// lease_expires_at = now + 29s — below horizon.
	resp := dashboardResponseForLease(t, time.Now().Add(29*time.Second))
	allocs := decodeAllocations(t, resp)
	if len(allocs) != 1 {
		t.Fatalf("len = %d, want 1", len(allocs))
	}
	if allocs[0].MountStatus != "idle" {
		t.Errorf("mount_status = %q, want %q", allocs[0].MountStatus, "idle")
	}
	if allocs[0].MountedAgentID != "" {
		t.Errorf("mounted_agent_id = %q, want empty", allocs[0].MountedAgentID)
	}
}

func TestDashboardListAllocationsMountStatusExpired(t *testing.T) {
	resp := dashboardResponseForLease(t, time.Now().Add(-5*time.Second))
	allocs := decodeAllocations(t, resp)
	if len(allocs) != 1 {
		t.Fatalf("len = %d, want 1", len(allocs))
	}
	if allocs[0].MountStatus != "idle" {
		t.Errorf("mount_status = %q, want %q", allocs[0].MountStatus, "idle")
	}
}

func TestDashboardListAllocationsMountStatusUnbound(t *testing.T) {
	// No BoundAgentID — should be Idle regardless of lease.
	resp := dashboardResponseForUnbound(t)
	allocs := decodeAllocations(t, resp)
	if len(allocs) != 1 {
		t.Fatalf("len = %d, want 1", len(allocs))
	}
	if allocs[0].MountStatus != "idle" {
		t.Errorf("mount_status = %q, want %q", allocs[0].MountStatus, "idle")
	}
}

func TestDashboardMeIncludesUsedBytes(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv, svc := httpStartServer(t, pool)
	cookie, _ := httpSeedAdmin(t, pool, svc)
	userID := dashGetUserID(t, cookie, srv.URL)
	asvc := dashAllocSvc(pool)

	if _, err := asvc.Allocate(context.Background(), userID, 2*dashGiB); err != nil {
		t.Fatal(err)
	}
	if _, err := asvc.Allocate(context.Background(), userID, 3*dashGiB); err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/me", nil)
	req.AddCookie(cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var me struct {
		UsedBytes  int64 `json:"used_bytes"`
		QuotaBytes int64 `json:"quota_bytes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&me); err != nil {
		t.Fatal(err)
	}
	if me.UsedBytes != 5*dashGiB {
		t.Fatalf("used_bytes = %d, want %d", me.UsedBytes, 5*dashGiB)
	}
	if me.QuotaBytes <= me.UsedBytes {
		t.Fatalf("quota_bytes (%d) should exceed used_bytes (%d)", me.QuotaBytes, me.UsedBytes)
	}
}
