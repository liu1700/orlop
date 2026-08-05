package main

import (
	"encoding/json"
	"net/http"
	"testing"
)

// mountSessionLiveViaHTTP reads the endpoint orlop-control actually calls, so
// these tests cover the wire answer and not just the helper beneath it.
func mountSessionLiveViaHTTP(t *testing.T, state *serverState, tenantID, allocID string) bool {
	t.Helper()
	rr := doAdminRequest(state, http.MethodGet,
		"/control/tenants/"+tenantID+"/allocations/"+allocID+"/mount-lease", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("mount-lease status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var out struct {
		SessionLive bool `json:"session_live"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %s: %v", rr.Body.String(), err)
	}
	return out.SessionLive
}

// #114: this endpoint is the only thing that can tell orlop-control a mount
// holder has died, because the control database's lease is a timed reservation
// that outlives its holder. A mounted client must read as live.
func TestMountSessionStatusReportsALiveMountAsLive(t *testing.T) {
	state := newTestState(t, nil, nil)
	tenant, ok := state.tenant(testTenant)
	if !ok {
		t.Fatalf("tenant %q not found", testTenant)
	}
	const allocID = "alloc_live_probe"
	seedMountLease(state, tenant, allocID, 0xc1)

	if !mountSessionLiveViaHTTP(t, state, testTenant, allocID) {
		t.Fatal("a mounted allocation reported not live; control would displace a live writer")
	}
}

// The case the fix turns on: the holder's transport dropped, so its lease is
// gone from this server while orlop-control's row still says it holds the
// mount. Reporting false is what lets the agent back onto its own disk.
func TestMountSessionStatusReportsADroppedConnectionAsDead(t *testing.T) {
	state := newTestState(t, nil, nil)
	tenant, ok := state.tenant(testTenant)
	if !ok {
		t.Fatalf("tenant %q not found", testTenant)
	}
	const allocID = "alloc_dead_probe"
	seedMountLease(state, tenant, allocID, 0xc2)

	// What ReleaseAllForConn does when the mount's socket dies. The registry
	// still holds the active hex, exactly as it does in production.
	tenant.leases.ReleaseAllForConn(testConnID)

	if mountSessionLiveViaHTTP(t, state, testTenant, allocID) {
		t.Fatal("a dropped mount still reported live; the agent stays locked out for the full TTL")
	}
}

// An allocation nobody ever mounted has no active session, so there is nothing
// alive to protect.
func TestMountSessionStatusReportsAnUnmountedAllocationAsDead(t *testing.T) {
	state := newTestState(t, nil, nil)
	if mountSessionLiveViaHTTP(t, state, testTenant, "alloc_never_mounted") {
		t.Fatal("an allocation with no session reported live")
	}
}

// Unknown tenants must not answer "live" — that would be a way to keep a lease
// pinned forever by naming a tenant this server does not serve.
func TestMountSessionStatusReportsAnUnknownTenantAsDead(t *testing.T) {
	state := newTestState(t, nil, nil)
	rr := doAdminRequest(state, http.MethodGet,
		"/control/tenants/nosuchtenant/allocations/alloc_x/mount-lease", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("unknown tenant status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var out struct {
		SessionLive bool `json:"session_live"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.SessionLive {
		t.Fatal("unknown tenant reported live")
	}
}
