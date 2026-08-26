package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/allocations"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage/postgres/db/sqlcdb"
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

func mountBodyWithToken(fp, token string) *bytes.Reader {
	body, _ := json.Marshal(map[string]string{
		"agent_fingerprint": fp,
		"lease_token":       token,
	})
	return bytes.NewReader(body)
}

func mountTokenRequest(method, url string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(mountLeaseTokenHeader, "1")
	return http.DefaultClient.Do(req)
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
		LeaseID    string `json:"lease_id"`
		LeaseToken string `json:"lease_token"`
		ExpiresAt  string `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&acquired); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if acquired.LeaseID != uuidString(allocation.ID) || acquired.ExpiresAt == "" {
		t.Fatalf("bad acquire response: %+v", acquired)
	}
	if acquired.LeaseToken != "" {
		t.Fatalf("legacy acquire unexpectedly received token %q", acquired.LeaseToken)
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
	var refreshed struct {
		LeaseToken string `json:"lease_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&refreshed); err != nil {
		resp.Body.Close()
		t.Fatal(err)
	}
	resp.Body.Close()
	if refreshed.LeaseToken != "" {
		t.Fatalf("legacy refresh unexpectedly received token %q", refreshed.LeaseToken)
	}

	// A capable v0.6.5 client can adopt a pre-upgrade, tokenless lease on its
	// first refresh. The header is ignored by old control planes.
	resp, err = mountTokenRequest(http.MethodPost, url+"/refresh", mountBody(fp))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewDecoder(resp.Body).Decode(&refreshed); err != nil {
		resp.Body.Close()
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || refreshed.LeaseToken == "" {
		t.Fatalf("capable refresh status=%d token=%q", resp.StatusCode, refreshed.LeaseToken)
	}

	resp, err = mountTokenRequest(http.MethodDelete, url, mountBodyWithToken(fp, refreshed.LeaseToken))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("release status = %d", resp.StatusCode)
	}
}

func TestMountLeaseTokenBridgesCertificateRenewalAndTakeoverInvalidatesIt(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv, svc := httpStartServer(t, pool)
	cookie, _ := httpSeedAdmin(t, pool, svc)
	userID := dashGetUserID(t, cookie, srv.URL)
	asvc := dashAllocSvc(pool)
	allocation, err := asvc.Allocate(context.Background(), userID, dashGiB)
	if err != nil {
		t.Fatal(err)
	}
	agent1, fp1 := mountSeedAgent(t, pool, userID)
	agentRenewed, fpRenewed := mountSeedAgent(t, pool, userID)
	_, fpTakeover := mountSeedAgent(t, pool, userID)
	mountBindAgentID(t, pool, allocation.ID)
	url := srv.URL + "/api/allocations/" + uuidString(allocation.ID) + "/mount"

	resp, err := mountTokenRequest(http.MethodPost, url, mountBody(fp1))
	if err != nil {
		t.Fatal(err)
	}
	var acquired struct {
		LeaseToken string `json:"lease_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&acquired); err != nil {
		resp.Body.Close()
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || acquired.LeaseToken == "" {
		t.Fatalf("acquire status=%d token=%q", resp.StatusCode, acquired.LeaseToken)
	}
	// Once a lease has a token, omitting it must not fall back to the legacy
	// enrollment guard; that would let a displaced process bypass takeover.
	resp, err = http.Post(url+"/refresh", "application/json", mountBody(fp1))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict || !strings.Contains(string(body), "already_mounted") {
		t.Fatalf("token omission status=%d body=%s", resp.StatusCode, body)
	}

	// Renewal creates a new enrollment row. The opaque token proves this is
	// still the same mount and atomically rebinds the live lease.
	resp, err = mountTokenRequest(http.MethodPost, url+"/refresh", mountBodyWithToken(fpRenewed, acquired.LeaseToken))
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("renewed refresh status=%d body=%s", resp.StatusCode, body)
	}
	row, err := sqlcdb.New(pool).GetAllocation(context.Background(), allocation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !row.BoundAgentID.Valid || row.BoundAgentID.Bytes != agentRenewed.Bytes {
		t.Fatalf("bound enrollment = %+v, want %s", row.BoundAgentID, uuidString(agentRenewed))
	}

	// A stop immediately after rotation can release with the same token.
	resp, err = mountTokenRequest(http.MethodDelete, url, mountBodyWithToken(fpRenewed, acquired.LeaseToken))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("renewed release status=%d", resp.StatusCode)
	}

	// Re-acquire, then force a takeover. The takeover mints a different token,
	// so the displaced process cannot refresh its way back in.
	resp, err = mountTokenRequest(http.MethodPost, url, mountBody(fp1))
	if err != nil {
		t.Fatal(err)
	}
	var old struct {
		LeaseToken string `json:"lease_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&old); err != nil {
		resp.Body.Close()
		t.Fatal(err)
	}
	resp.Body.Close()
	forced, _ := json.Marshal(map[string]any{"agent_fingerprint": fpTakeover, "force": true})
	resp, err = mountTokenRequest(http.MethodPost, url, bytes.NewReader(forced))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("forced takeover status=%d", resp.StatusCode)
	}

	resp, err = mountTokenRequest(http.MethodPost, url+"/refresh", mountBodyWithToken(fp1, old.LeaseToken))
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict || !strings.Contains(string(body), "already_mounted") {
		t.Fatalf("displaced refresh status=%d body=%s", resp.StatusCode, body)
	}

	_ = agent1 // documents that fp1 belongs to the original enrollment
}

func TestMountLeaseExpiredEnrollmentIsRetryableAuthError(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv, svc := httpStartServer(t, pool)
	cookie, _ := httpSeedAdmin(t, pool, svc)
	userID := dashGetUserID(t, cookie, srv.URL)
	asvc := dashAllocSvc(pool)
	allocation, err := asvc.Allocate(context.Background(), userID, dashGiB)
	if err != nil {
		t.Fatal(err)
	}
	mountBindAgentID(t, pool, allocation.ID)
	fp := "A1B2C3EXPIRED"
	_, err = sqlcdb.New(pool).CreateAgentEnrollment(context.Background(), sqlcdb.CreateAgentEnrollmentParams{
		UserID:       userID,
		CertSerial:   fp,
		CertNotAfter: pgtype.Timestamptz{Time: time.Now().Add(-time.Minute), Valid: true},
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := http.Post(
		srv.URL+"/api/allocations/"+uuidString(allocation.ID)+"/mount/refresh",
		"application/json", mountBody(fp))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(string(body), "expired_client") {
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
}

// A DIFFERENT enrollment acquiring while the incumbent's lease is still live gets a
// distinct 409 lease_live carrying the incumbent's expiry, and succeeds only with an
// explicit {"force": true} (issue #93). The incumbent keeps refreshing until then.
func TestMountLeaseLiveTakeoverRequiresForce(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv, svc := httpStartServer(t, pool)
	cookie, _ := httpSeedAdmin(t, pool, svc)
	userID := dashGetUserID(t, cookie, srv.URL)
	asvc := dashAllocSvc(pool)
	allocation, err := asvc.Allocate(context.Background(), userID, dashGiB)
	if err != nil {
		t.Fatal(err)
	}
	agent1, fp1 := mountSeedAgent(t, pool, userID)
	_, fp2 := mountSeedAgent(t, pool, userID)
	mountBindAgentID(t, pool, allocation.ID)
	if _, err := asvc.AcquireMountLease(context.Background(), allocation.ID, agent1, allocations.DefaultMountLeaseTTL, false); err != nil {
		t.Fatal(err)
	}
	url := srv.URL + "/api/allocations/" + uuidString(allocation.ID) + "/mount"

	resp, err := http.Post(url, "application/json", mountBody(fp2))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("live takeover without force status = %d body = %s (want 409)", resp.StatusCode, body)
	}
	var conflict struct {
		Error          string `json:"error"`
		LeaseExpiresAt string `json:"lease_expires_at"`
		BoundAt        string `json:"bound_at"`
	}
	if err := json.Unmarshal(body, &conflict); err != nil {
		t.Fatalf("decode 409 body %s: %v", body, err)
	}
	if conflict.Error != "lease_live" || conflict.LeaseExpiresAt == "" || conflict.BoundAt == "" {
		t.Fatalf("409 body = %s (want error=lease_live with lease_expires_at and bound_at)", body)
	}

	// The incumbent still owns the lease.
	refresh, err := http.Post(url+"/refresh", "application/json", mountBody(fp1))
	if err != nil {
		t.Fatal(err)
	}
	refresh.Body.Close()
	if refresh.StatusCode != http.StatusOK {
		t.Fatalf("incumbent refresh after refused takeover status = %d", refresh.StatusCode)
	}

	forced, _ := json.Marshal(map[string]any{"agent_fingerprint": fp2, "force": true})
	resp, err = http.Post(url, "application/json", bytes.NewReader(forced))
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("forced takeover status = %d body = %s", resp.StatusCode, body)
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
	if _, err := asvc.AcquireMountLease(context.Background(), allocation.ID, agent1, 50*time.Millisecond, false); err != nil {
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
	if _, err := asvc.AcquireMountLease(context.Background(), alloc.ID, agentID, allocations.DefaultMountLeaseTTL, false); err != nil {
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
	if _, err := asvc.AcquireMountLease(context.Background(), allocation.ID, agent, allocations.DefaultMountLeaseTTL, false); err != nil {
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

// mountLiveTakeoverFixture builds an allocation whose mount lease is LIVE and
// held by agent1, plus a second agent's fingerprint to claim it with. This is
// the exact state issue #114 is about: the row says "held", and only the data
// plane knows whether the holder still exists.
func mountLiveTakeoverFixture(t *testing.T, fencer mountLeaseFencer) (url, claimantFP string) {
	t.Helper()
	pool := httpOpenTestPool(t)
	srv, svc := httpStartServerWithFencer(t, pool, fencer)
	cookie, _ := httpSeedAdmin(t, pool, svc)
	userID := dashGetUserID(t, cookie, srv.URL)
	asvc := dashAllocSvc(pool)
	allocation, err := asvc.Allocate(context.Background(), userID, dashGiB)
	if err != nil {
		t.Fatal(err)
	}
	agent1, _ := mountSeedAgent(t, pool, userID)
	_, fp2 := mountSeedAgent(t, pool, userID)
	mountBindAgentID(t, pool, allocation.ID)
	if _, err := asvc.AcquireMountLease(context.Background(), allocation.ID, agent1,
		allocations.DefaultMountLeaseTTL, false); err != nil {
		t.Fatal(err)
	}
	return srv.URL + "/api/allocations/" + uuidString(allocation.ID) + "/mount", fp2
}

func mountPostStatus(t *testing.T, url, fp string) (int, string) {
	t.Helper()
	resp, err := http.Post(url, "application/json", mountBody(fp))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// #114: a mount lease is a timed reservation, so it outlives a mounter that
// crashed. Refusing a re-mount on the row alone locked an agent out of its own
// disk for the rest of the TTL — 18% of production runs on one measured day.
// When the data plane confirms nothing is mounted, the claim must succeed.
func TestMountLeaseReclaimedWhenDataPlaneSaysHolderIsGone(t *testing.T) {
	fencer := &recordingFencer{sessionLive: false}
	url, fp := mountLiveTakeoverFixture(t, fencer)

	if st, body := mountPostStatus(t, url, fp); st != http.StatusOK {
		t.Fatalf("claim over a dead holder status = %d, want 200; body = %s", st, body)
	}
	if fencer.liveProbes == 0 {
		t.Fatal("the data plane was never asked; the lease was reclaimed on the row alone")
	}
}

// The other direction, and the one that must never regress: a holder that is
// genuinely mounted and mid-write keeps its lease. Displacing it silently loses
// its data (issue #93), which is why force stays the only way past a live one.
func TestMountLeaseNotReclaimedWhileDataPlaneReportsALiveHolder(t *testing.T) {
	fencer := &recordingFencer{sessionLive: true}
	url, fp := mountLiveTakeoverFixture(t, fencer)

	if st, body := mountPostStatus(t, url, fp); st != http.StatusConflict {
		t.Fatalf("claim over a LIVE holder status = %d, want 409; body = %s", st, body)
	}
}

// An unreachable or erroring data plane is "unknown", not "dead". Reclaiming on
// a failed probe would turn a network blip into data loss, so the caller waits
// out the TTL exactly as it did before this check existed.
func TestMountLeaseNotReclaimedWhenLivenessProbeFails(t *testing.T) {
	fencer := &recordingFencer{sessionLiveErr: errors.New("data plane unreachable")}
	url, fp := mountLiveTakeoverFixture(t, fencer)

	if st, body := mountPostStatus(t, url, fp); st != http.StatusConflict {
		t.Fatalf("claim after a failed liveness probe status = %d, want 409; body = %s", st, body)
	}
}
