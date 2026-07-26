package client_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-ID", "req-123")
		w.Header().Set("Retry-After", "7")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "server_error",
			"error_description": "boom",
		})
	}))
	defer ts.Close()
	c := client.New(ts.URL, "")
	_, err := c.AllocateDisk(context.Background(), agentID, ownerID, 0)
	if err == nil {
		t.Fatal("expected error on 500")
	}
	var apiErr *client.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error type = %T; want *client.APIError", err)
	}
	if apiErr.Op != "AllocateDisk" ||
		apiErr.Method != http.MethodPost ||
		apiErr.Path != "/v1/entities" ||
		apiErr.StatusCode != http.StatusInternalServerError ||
		apiErr.Code != "server_error" ||
		apiErr.Message != "boom" ||
		apiErr.RequestID != "req-123" ||
		apiErr.Header.Get("Content-Type") != "application/json" ||
		apiErr.RetryAfter != 7*time.Second ||
		!strings.Contains(apiErr.Body, `"server_error"`) {
		t.Fatalf("APIError = %+v", apiErr)
	}
	if !apiErr.Retryable() {
		t.Fatal("500 should be retryable")
	}
}

func TestAPIErrorRetryableStatusIsBounded(t *testing.T) {
	for _, status := range []int{
		http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout,
	} {
		if !(&client.APIError{StatusCode: status}).Retryable() {
			t.Errorf("status %d should be retryable", status)
		}
	}
	for _, status := range []int{
		http.StatusBadRequest,
		http.StatusNotImplemented,
		http.StatusHTTPVersionNotSupported,
	} {
		if (&client.APIError{StatusCode: status}).Retryable() {
			t.Errorf("status %d should not be retryable", status)
		}
	}
}

func TestHTTPClientErrorSentinels(t *testing.T) {
	tests := []struct {
		name   string
		status int
		code   string
		target error
	}{
		{"not found", http.StatusNotFound, "not_found", client.ErrNotFound},
		{"conflict", http.StatusConflict, "already_mounted", client.ErrConflict},
		{"unauthorized", http.StatusUnauthorized, "invalid_token", client.ErrUnauthorized},
		{"forbidden", http.StatusForbidden, "access_denied", client.ErrForbidden},
		{"rate limited", http.StatusTooManyRequests, "rate_limited", client.ErrRateLimited},
		{"quota", http.StatusConflict, "quota_exceeded", client.ErrQuotaExceeded},
		{"capacity", http.StatusConflict, "insufficient_capacity", client.ErrInsufficientCapacity},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				writeErr := map[string]string{"error": tt.code}
				w.WriteHeader(tt.status)
				_ = json.NewEncoder(w).Encode(writeErr)
			}))
			defer ts.Close()

			_, err := client.New(ts.URL, "tok").ResolveDisk(context.Background(), agentID)
			if !errors.Is(err, tt.target) {
				t.Fatalf("errors.Is(%v, %v) = false", err, tt.target)
			}
		})
	}
}

func TestHTTPClientPlainTextErrorIsPreserved(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "plain failure", http.StatusBadGateway)
	}))
	defer ts.Close()

	_, err := client.New(ts.URL, "tok").ResolveDisk(context.Background(), agentID)
	var apiErr *client.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error type = %T; want *client.APIError", err)
	}
	if apiErr.Message != "plain failure" || !apiErr.Retryable() {
		t.Fatalf("APIError = %+v", apiErr)
	}
}

func TestHTTPClientErrorBodyIsBounded(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(strings.Repeat("x", (64<<10)+1024)))
	}))
	defer ts.Close()

	_, err := client.New(ts.URL, "tok").ResolveDisk(context.Background(), agentID)
	var apiErr *client.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error type = %T; want *client.APIError", err)
	}
	if len(apiErr.Body) != 64<<10 {
		t.Fatalf("error body length = %d; want %d", len(apiErr.Body), 64<<10)
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

func TestFakeNotFoundMatchesLiveClientContract(t *testing.T) {
	f := client.NewFake()
	_, err := f.ResolveDisk(context.Background(), "missing")
	if !errors.Is(err, client.ErrNotFound) {
		t.Fatalf("ResolveDisk error = %v; want ErrNotFound", err)
	}
	var apiErr *client.APIError
	if !errors.As(err, &apiErr) || apiErr.Op != "ResolveDisk" || apiErr.StatusCode != http.StatusNotFound {
		t.Fatalf("ResolveDisk error = %#v; want typed 404", err)
	}

	if err := f.SetDiskQuota(context.Background(), "missing", 1); !errors.Is(err, client.ErrNotFound) {
		t.Fatalf("SetDiskQuota error = %v; want ErrNotFound", err)
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
