package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/allocations"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/db/sqlcdb"
)

// mountBindAgentID sets the allocation's stable orlop agent id (disk_allocations.agent_id,
// as the live bridge allocation path does), which is what the mount lease now keys on
// (NOT the per-enroll cert). Returns the agent id for use as the direct lease identity.
func mountBindAgentID(t *testing.T, pool *pgxpool.Pool, allocID pgtype.UUID) pgtype.UUID {
	t.Helper()
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal(err)
	}
	s := fmt.Sprintf("%x-%x-%x-%x-%x", raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16])
	if _, err := pool.Exec(context.Background(), "UPDATE disk_allocations SET agent_id=$1 WHERE id=$2", s, allocID); err != nil {
		t.Fatal(err)
	}
	var u pgtype.UUID
	if err := u.Scan(s); err != nil {
		t.Fatal(err)
	}
	return u
}

func mountBody(fp string) *bytes.Reader {
	body, _ := json.Marshal(map[string]string{"agent_fingerprint": fp})
	return bytes.NewReader(body)
}

func mountSeedAgent(t *testing.T, pool *pgxpool.Pool, userID pgtype.UUID) (pgtype.UUID, string) {
	t.Helper()
	q := sqlcdb.New(pool)
	var serial [8]byte
	if _, err := rand.Read(serial[:]); err != nil {
		t.Fatal(err)
	}
	fp := strings.ToUpper(hex.EncodeToString(serial[:]))
	row, err := q.CreateAgentEnrollment(context.Background(), sqlcdb.CreateAgentEnrollmentParams{
		UserID:       userID,
		CertSerial:   fp,
		CertNotAfter: pgtype.Timestamptz{Time: time.Now().Add(24 * time.Hour), Valid: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	return row.ID, fp
}

func TestMountLeaseAcquireConflictRefreshAndRelease(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv, svc := httpStartServer(t, pool)
	cookie, _ := httpSeedAdmin(t, pool, svc)
	userID := dashGetUserID(t, cookie, srv.URL)
	asvc := dashAllocSvc(pool)
	allocation, err := asvc.Allocate(context.Background(), userID, dashGiB)
	if err != nil {
		t.Fatal(err)
	}
	_, fp := mountSeedAgent(t, pool, userID)
	mountBindAgentID(t, pool, allocation.ID)
	url := srv.URL + "/api/allocations/" + uuidString(allocation.ID) + "/mount"

	resp, err := http.Post(url, "application/json", mountBody(fp))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("acquire status = %d body = %s", resp.StatusCode, body)
	}
	var acquired struct {
		LeaseID   string `json:"lease_id"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&acquired); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if acquired.LeaseID != uuidString(allocation.ID) || acquired.ExpiresAt == "" {
		t.Fatalf("bad acquire response: %+v", acquired)
	}

	// The SAME agent re-acquiring its own live lease now TAKES OVER (200), not 409:
	// one-shot pods re-mount the same agent every turn, so a leaked lease must not block
	// the next mount. (Cross-agent exclusivity is covered at the allocations layer.)
	resp, err = http.Post(url, "application/json", mountBody(fp))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("same-agent re-acquire (takeover) status = %d body = %s", resp.StatusCode, body)
	}

	resp, err = http.Post(url+"/refresh", "application/json", mountBody(fp))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("refresh status = %d body = %s", resp.StatusCode, body)
	}
	resp.Body.Close()

	req, _ := http.NewRequest(http.MethodDelete, url, mountBody(fp))
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("release status = %d", resp.StatusCode)
	}
}

func TestMountLeaseExpiredLeaseCanMoveAgents(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv, svc := httpStartServer(t, pool)
	cookie, _ := httpSeedAdmin(t, pool, svc)
	userID := dashGetUserID(t, cookie, srv.URL)
	asvc := dashAllocSvc(pool)
	allocation, err := asvc.Allocate(context.Background(), userID, dashGiB)
	if err != nil {
		t.Fatal(err)
	}
	agent1, _ := mountSeedAgent(t, pool, userID)
	_, fp2 := mountSeedAgent(t, pool, userID)
	// A second enrollment of the owning user takes the lease over (the way a one-shot pod
	// re-mounts with a fresh cert). The allocation must be agent-bound to be mountable.
	mountBindAgentID(t, pool, allocation.ID)
	if _, err := asvc.AcquireMountLease(context.Background(), allocation.ID, agent1, 50*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(80 * time.Millisecond)

	url := srv.URL + "/api/allocations/" + uuidString(allocation.ID) + "/mount"
	resp, err := http.Post(url, "application/json", mountBody(fp2))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("agent2 acquire status = %d body = %s", resp.StatusCode, body)
	}
}

func TestUnmountByOwnerClearsLease(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv, svc := httpStartServer(t, pool)
	cookie, _ := httpSeedAdmin(t, pool, svc)
	userID := dashGetUserID(t, cookie, srv.URL)
	asvc := dashAllocSvc(pool)

	alloc, err := asvc.Allocate(context.Background(), userID, dashGiB)
	if err != nil {
		t.Fatal(err)
	}
	agentID, _ := mountSeedAgent(t, pool, userID)
	if _, err := asvc.Bind(context.Background(), alloc.ID, userID, agentID); err != nil {
		t.Fatal(err)
	}
	if _, err := asvc.AcquireMountLease(context.Background(), alloc.ID, agentID, allocations.LeaseTTL); err != nil {
		t.Fatal(err)
	}

	url := srv.URL + "/api/allocations/" + uuidString(alloc.ID) + "/unmount"
	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}

	req2, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req2.AddCookie(cookie)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusNoContent {
		t.Fatalf("idempotent status = %d", resp2.StatusCode)
	}
}

func TestUnmountByOwnerCrossUserReturns404(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv, svc := httpStartServer(t, pool)
	owner, _ := httpSeedAdmin(t, pool, svc)
	other, _ := httpSeedAdmin(t, pool, svc)
	ownerID := dashGetUserID(t, owner, srv.URL)
	asvc := dashAllocSvc(pool)
	alloc, err := asvc.Allocate(context.Background(), ownerID, dashGiB)
	if err != nil {
		t.Fatal(err)
	}

	url := srv.URL + "/api/allocations/" + uuidString(alloc.ID) + "/unmount"
	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(other)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestUnmountByOwnerRevokedReturns410(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv, svc := httpStartServer(t, pool)
	cookie, _ := httpSeedAdmin(t, pool, svc)
	userID := dashGetUserID(t, cookie, srv.URL)
	asvc := dashAllocSvc(pool)
	alloc, err := asvc.Allocate(context.Background(), userID, dashGiB)
	if err != nil {
		t.Fatal(err)
	}
	if err := asvc.Revoke(context.Background(), alloc.ID, userID); err != nil {
		t.Fatal(err)
	}

	url := srv.URL + "/api/allocations/" + uuidString(alloc.ID) + "/unmount"
	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusGone {
		t.Fatalf("status = %d, want 410", resp.StatusCode)
	}
}

func TestUnmountByOwnerRequiresAuth(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv, _ := httpStartServer(t, pool)
	resp, err := http.Post(
		srv.URL+"/api/allocations/00000000-0000-0000-0000-000000000000/unmount",
		"application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestMountLeaseRefreshRevokedReturnsGone(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv, svc := httpStartServer(t, pool)
	cookie, _ := httpSeedAdmin(t, pool, svc)
	userID := dashGetUserID(t, cookie, srv.URL)
	asvc := dashAllocSvc(pool)
	allocation, err := asvc.Allocate(context.Background(), userID, dashGiB)
	if err != nil {
		t.Fatal(err)
	}
	agent, fp := mountSeedAgent(t, pool, userID)
	mountBindAgentID(t, pool, allocation.ID)
	if _, err := asvc.AcquireMountLease(context.Background(), allocation.ID, agent, allocations.LeaseTTL); err != nil {
		t.Fatal(err)
	}
	if err := asvc.Revoke(context.Background(), allocation.ID, userID); err != nil {
		t.Fatal(err)
	}

	resp, err := http.Post(srv.URL+"/api/allocations/"+uuidString(allocation.ID)+"/mount/refresh", "application/json", mountBody(fp))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusGone || !strings.Contains(string(body), "revoked") {
		t.Fatalf("refresh status = %d body = %s", resp.StatusCode, body)
	}
}
