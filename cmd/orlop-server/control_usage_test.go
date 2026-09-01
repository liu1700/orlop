package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"lukechampine.com/blake3"

	"github.com/liu1700/orlop/cmd/orlop-server/internal/usage"
)

// seedChunk stores one content chunk for a tenant exactly the way the data-plane
// write path does (dataplane_server.go): Put writes the physical object under
// <storeRoot>/objects, then NoteChunkStored records the chunks row with the real
// byte size. That makes the chunks-table sum the usage meter reads reflect the
// bytes actually on disk.
func seedChunk(t *testing.T, ts *tenantState, data []byte) {
	t.Helper()
	h := blake3.Sum256(data)
	if _, err := ts.chunks.Put(h[:], data); err != nil {
		t.Fatalf("put chunk: %v", err)
	}
	if err := ts.manifests.NoteChunkStored(h[:], int64(len(data)), time.Now().Unix()); err != nil {
		t.Fatalf("note chunk stored: %v", err)
	}
}

func TestTenantUsage_HappyPath(t *testing.T) {
	exec := &fakeExec{}
	state, _ := newAdminTestState(t, exec)

	// Register a tenant so it's known + has a quota record.
	body := registerTenantRequest{TenantID: "acme", Name: "Acme Corp", SizeBytes: 1 << 30}
	if rr := doAdminRequest(state, http.MethodPost, "/control/tenants", body); rr.Code != http.StatusOK {
		t.Fatalf("register status=%d body=%s", rr.Code, rr.Body.String())
	}

	// Store two distinct chunks (4096 + 1024 bytes) through the real chunk path;
	// used_bytes is the sum read from the chunks table, not a filesystem walk.
	ts, ok := state.tenant("acme")
	if !ok {
		t.Fatal("tenant acme not live after register")
	}
	seedChunk(t, ts, make([]byte, 4096))
	seedChunk(t, ts, make([]byte, 1024))

	rr := doAdminRequest(state, http.MethodGet, "/control/tenants/acme/usage", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var resp tenantUsageResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.TenantID != "acme" {
		t.Fatalf("tenant_id = %q, want acme", resp.TenantID)
	}
	if resp.UsedBytes != 4096+1024 {
		t.Fatalf("used_bytes = %d, want %d", resp.UsedBytes, 4096+1024)
	}
	if resp.SizeBytes != 1<<30 {
		t.Fatalf("size_bytes = %d, want %d", resp.SizeBytes, 1<<30)
	}
}

// TestTenantUsage_EmptyTenantIsZero guards the coalesce: a placed tenant that has
// stored nothing must meter zero, never error — the sweeper reads that as
// "nothing to bill".
func TestTenantUsage_EmptyTenantIsZero(t *testing.T) {
	exec := &fakeExec{}
	state, _ := newAdminTestState(t, exec)

	body := registerTenantRequest{TenantID: "acme", Name: "Acme Corp", SizeBytes: 1 << 30}
	if rr := doAdminRequest(state, http.MethodPost, "/control/tenants", body); rr.Code != http.StatusOK {
		t.Fatalf("register status=%d body=%s", rr.Code, rr.Body.String())
	}

	rr := doAdminRequest(state, http.MethodGet, "/control/tenants/acme/usage", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var resp tenantUsageResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.UsedBytes != 0 {
		t.Fatalf("used_bytes = %d, want 0", resp.UsedBytes)
	}
}

// TestTenantUsage_ReconcilesWithDirSize is the correctness oracle for the switch
// from an O(files) walk to a chunks-table SUM (PLO-292): after storing chunks the
// production way, the metadata sum must equal a du-style walk of the store byte
// for byte. This is what makes the constant-time query a safe replacement rather
// than an approximation — it guards against compression, size-column drift, and
// object/row atomicity all at once, because it seeds through the real ChunkStore.
func TestTenantUsage_ReconcilesWithDirSize(t *testing.T) {
	exec := &fakeExec{}
	state, _ := newAdminTestState(t, exec)

	body := registerTenantRequest{TenantID: "acme", Name: "Acme Corp", SizeBytes: 1 << 30}
	if rr := doAdminRequest(state, http.MethodPost, "/control/tenants", body); rr.Code != http.StatusOK {
		t.Fatalf("register status=%d body=%s", rr.Code, rr.Body.String())
	}
	ts, ok := state.tenant("acme")
	if !ok {
		t.Fatal("tenant acme not live after register")
	}

	// A spread of distinct sizes, including a byte-count that is not a round
	// block, so any block-rounding divergence would surface.
	for _, n := range []int{1, 4096, 5000, 65536, 131071} {
		buf := make([]byte, n)
		for i := range buf {
			buf[i] = byte(i + n) // distinct content per chunk so none dedup away
		}
		seedChunk(t, ts, buf)
	}

	sum, count, err := ts.db.UsedBytes(context.Background())
	if err != nil {
		t.Fatalf("UsedBytes: %v", err)
	}
	if count != 5 {
		t.Fatalf("chunk_count = %d, want 5", count)
	}
	walked, err := usage.DirSize(ts.storeRoot)
	if err != nil {
		t.Fatalf("DirSize: %v", err)
	}
	if sum != walked {
		t.Fatalf("chunks-table sum = %d but store walk = %d; the metadata meter diverged from on-disk bytes", sum, walked)
	}
	if sum != 1+4096+5000+65536+131071 {
		t.Fatalf("used_bytes = %d, want %d", sum, 1+4096+5000+65536+131071)
	}
}

func TestTenantUsage_UnknownTenantReturns404(t *testing.T) {
	exec := &fakeExec{}
	state, _ := newAdminTestState(t, exec)

	rr := doAdminRequest(state, http.MethodGet, "/control/tenants/ghost/usage", nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestTenantUsage_InvalidIDReturns400(t *testing.T) {
	exec := &fakeExec{}
	state, _ := newAdminTestState(t, exec)

	rr := doAdminRequest(state, http.MethodGet, "/control/tenants/has..dots/usage", nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestTenantUsage_RequiresControlPlaneCert(t *testing.T) {
	exec := &fakeExec{}
	state, _ := newAdminTestState(t, exec)

	// No control-plane identity in context => middleware rejects.
	req := httptest.NewRequest(http.MethodGet, "/control/tenants/acme/usage", nil)
	rr := httptest.NewRecorder()
	newRouter(state).ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}
