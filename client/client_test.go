package client_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/liu1700/orlop/client"
)

const (
	agentID = "11111111-1111-1111-1111-111111111111"
	ownerID = "99999999-9999-9999-9999-999999999999"
)

func TestHTTPClientAllocateResolve(t *testing.T) {
	var gotAuth string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/entities":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["entity_type"] != "agent" || body["entity_id"] != agentID || body["owner_id"] != ownerID {
				t.Errorf("alloc body = %+v", body)
			}
			if body["grant_bytes"].(float64) != float64(128<<20) {
				t.Errorf("grant_bytes not threaded: %+v", body["grant_bytes"])
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"handle": "disk-h", "virtual_path": "/mnt/orlop/agents/" + agentID, "quota_bytes": 128 << 20,
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/entities/agent/"+agentID:
			_ = json.NewEncoder(w).Encode(map[string]string{"handle": "disk-h"})
		default:
			http.Error(w, "nf "+r.Method+" "+r.URL.Path, http.StatusNotFound)
		}
	}))
	defer ts.Close()

	c := client.New(ts.URL, "tok")
	disk, err := c.AllocateDisk(context.Background(), agentID, ownerID, 128<<20)
	if err != nil {
		t.Fatal(err)
	}
	if disk.Handle != "disk-h" || disk.VirtualPath != "/mnt/orlop/agents/"+agentID || disk.QuotaBytes != 128<<20 {
		t.Fatalf("alloc disk = %+v", disk)
	}
	if gotAuth != "Bearer tok" {
		t.Errorf("auth = %q", gotAuth)
	}

	// Resolve falls back to the deterministic mount path when none returned.
	got, err := c.ResolveDisk(context.Background(), agentID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Handle != "disk-h" || got.VirtualPath != client.MountPath(agentID) {
		t.Fatalf("resolve disk = %+v", got)
	}
}

func TestHTTPClientMintEnrollToken(t *testing.T) {
	var gotPath, gotMethod, gotAuth string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod, gotAuth = r.URL.Path, r.Method, r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"token":      "enroll-xyz",
			"expires_at": "2026-06-04T12:00:00Z",
		})
	}))
	defer ts.Close()

	c := client.New(ts.URL, "svc")
	tok, err := c.MintEnrollToken(context.Background(), agentID)
	if err != nil {
		t.Fatal(err)
	}
	if tok != "enroll-xyz" {
		t.Errorf("token = %q; want enroll-xyz", tok)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q; want POST", gotMethod)
	}
	if want := "/v1/agents/" + agentID + "/enroll-token"; gotPath != want {
		t.Errorf("path = %q; want %q", gotPath, want)
	}
	if gotAuth != "Bearer svc" {
		t.Errorf("auth = %q; want Bearer svc", gotAuth)
	}
}

func TestHTTPClientMintEnrollTokenEmpty(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"expires_at": "2026-06-04T12:00:00Z"})
	}))
	defer ts.Close()
	c := client.New(ts.URL, "svc")
	if _, err := c.MintEnrollToken(context.Background(), agentID); err == nil {
		t.Fatal("expected error on empty token")
	}
}

func TestHTTPClientUserDiskUsage(t *testing.T) {
	var gotPath, gotMethod string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		_ = json.NewEncoder(w).Encode(map[string]any{"owner_id": ownerID, "used_bytes": 7 << 30})
	}))
	defer ts.Close()

	c := client.New(ts.URL, "svc")
	bytes, err := c.UserDiskUsage(context.Background(), ownerID)
	if err != nil {
		t.Fatal(err)
	}
	if bytes != 7<<30 {
		t.Errorf("used_bytes = %d; want %d", bytes, int64(7<<30))
	}
	if gotMethod != http.MethodGet {
		t.Errorf("method = %q; want GET", gotMethod)
	}
	if want := "/v1/tenants/" + ownerID + "/usage"; gotPath != want {
		t.Errorf("path = %q; want %q", gotPath, want)
	}
}

func TestHTTPClientErrorStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer ts.Close()
	c := client.New(ts.URL, "")
	if _, err := c.AllocateDisk(context.Background(), agentID, ownerID, 0); err == nil {
		t.Fatal("expected error on 500")
	}
}

func TestHTTPClientSetQuotaAndRevoke(t *testing.T) {
	var gotQuota float64
	var deleted bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPatch && r.URL.Path == "/v1/entities/agent/"+agentID:
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			gotQuota, _ = body["grant_bytes"].(float64)
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/entities/agent/"+agentID:
			deleted = true
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "nf "+r.Method+" "+r.URL.Path, http.StatusNotFound)
		}
	}))
	defer ts.Close()

	c := client.New(ts.URL, "")
	if err := c.SetDiskQuota(context.Background(), agentID, 10<<30); err != nil {
		t.Fatal(err)
	}
	if gotQuota != float64(10<<30) {
		t.Fatalf("patched quota = %v", gotQuota)
	}
	if err := c.RevokeDisk(context.Background(), agentID); err != nil {
		t.Fatal(err)
	}
	if !deleted {
		t.Fatal("expected DELETE call")
	}
}

func TestFakeAllocateIdempotentAndUsage(t *testing.T) {
	f := client.NewFake()
	d1, err := f.AllocateDisk(context.Background(), "agent-1", "owner-1", 128<<20)
	if err != nil {
		t.Fatal(err)
	}
	if d1.VirtualPath != "/mnt/orlop/agents/agent-1" {
		t.Fatalf("virtual path = %q", d1.VirtualPath)
	}
	d2, _ := f.AllocateDisk(context.Background(), "agent-1", "owner-1", 999)
	if d2 != d1 {
		t.Fatalf("allocate not idempotent: %+v vs %+v", d2, d1)
	}
	f.SetUserDiskUsage("owner-1", 5<<30)
	if got, _ := f.UserDiskUsage(context.Background(), "owner-1"); got != 5<<30 {
		t.Fatalf("usage = %d", got)
	}
}

// Example shows the typical control-plane flow a host runs per agent: allocate
// the agent's disk, then mint the short-lived enroll token to hand to the
// sandbox (which trades it at /agent/enroll for its per-agent certificate).
func Example() {
	c := client.New("https://orlop-control.example", "service-token")
	ctx := context.Background()

	disk, err := c.AllocateDisk(ctx, "agent-42", "owner-7", 1<<30)
	if err != nil {
		// handle error
		return
	}
	fmt.Println(disk.VirtualPath)

	if _, err := c.MintEnrollToken(ctx, "agent-42"); err != nil {
		return
	}
}
