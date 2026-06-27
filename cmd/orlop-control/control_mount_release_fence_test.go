package main

import (
	"context"
	"net/http"
	"sync"
	"testing"
)

// recordingFencer captures FenceAllocation calls so a test can assert that
// clean unmount actually drops the server-side active lease record.
type recordingFencer struct {
	mu    sync.Mutex
	calls []fenceCall
}

type fenceCall struct {
	TenantID     string
	AllocationID string
}

func (r *recordingFencer) FenceAllocation(_ context.Context, tenantID, allocationID string) error {
	r.mu.Lock()
	r.calls = append(r.calls, fenceCall{TenantID: tenantID, AllocationID: allocationID})
	r.mu.Unlock()
	return nil
}

// A clean DELETE /api/allocations/{id}/mount (agent-driven unmount) must
// fence the server-side active mount-lease so the next mount with a fresh
// session_id isn't rejected with EACCES "session fenced". See #181.
func TestMountLeaseReleaseFencesServerSideLease(t *testing.T) {
	pool := httpOpenTestPool(t)
	fencer := &recordingFencer{}
	srv, svc := httpStartServerWithFencer(t, pool, fencer)
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

	// Acquire.
	acquireResp, err := http.Post(url, "application/json", mountBody(fp))
	if err != nil {
		t.Fatal(err)
	}
	acquireResp.Body.Close()
	if acquireResp.StatusCode != http.StatusOK {
		t.Fatalf("acquire status = %d, want 200", acquireResp.StatusCode)
	}

	// Release.
	req, _ := http.NewRequest(http.MethodDelete, url, mountBody(fp))
	releaseResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	releaseResp.Body.Close()
	if releaseResp.StatusCode != http.StatusNoContent {
		t.Fatalf("release status = %d, want 204", releaseResp.StatusCode)
	}

	fencer.mu.Lock()
	defer fencer.mu.Unlock()
	// Both acquire (which fences any stale session so a takeover's new hex is accepted)
	// and release fence the allocation, so expect 2 calls; the last is the release.
	if len(fencer.calls) != 2 {
		t.Fatalf("fencer.calls = %d, want 2 (acquire + release)", len(fencer.calls))
	}
	got := fencer.calls[len(fencer.calls)-1]
	if got.AllocationID != uuidString(allocation.ID) {
		t.Errorf("fenced allocation_id = %q, want %q", got.AllocationID, uuidString(allocation.ID))
	}
	if got.TenantID == "" {
		t.Errorf("fenced tenant_id is empty")
	}
}
