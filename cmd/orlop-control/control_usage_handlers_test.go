package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/allocations"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/devauth"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/serverapi"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage/postgres"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage/postgres/db/sqlcdb"
)

type fakeUsage struct {
	resp serverapi.TenantUsage
	err  error
	// Captured args from the last call.
	gotOps    string
	gotTenant string
	calls     int
}

func (f *fakeUsage) GetTenantUsage(_ context.Context, opsAddr, tenantID string) (serverapi.TenantUsage, error) {
	f.calls++
	f.gotOps = opsAddr
	f.gotTenant = tenantID
	return f.resp, f.err
}

func startUsageServer(t *testing.T, pool *pgxpool.Pool, usage tenantUsageClient) (*httptest.Server, *devauth.Service) {
	t.Helper()
	svc := devauth.NewService(postgres.New(pool), slog.New(slog.NewTextHandler(io.Discard, nil)))
	router := newRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), runtimeDeps{
		devAuth:     svc,
		store:       postgres.New(pool),
		allocations: allocations.NewService(postgres.New(pool), nil),
		serverUsage: usage,
	}, config{})
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	return srv, svc
}

func seedServerVMAndPool(t *testing.T, pool *pgxpool.Pool, tenantID, dataAddr, opsAddr string) {
	t.Helper()
	q := sqlcdb.New(pool)
	if _, err := q.UpsertServerPool(context.Background(), sqlcdb.UpsertServerPoolParams{
		DataAddr:   dataAddr,
		OpsAddr:    opsAddr,
		TotalBytes: 100 << 30,
		FreeBytes:  100 << 30,
		Status:     "available",
	}); err != nil {
		t.Fatalf("upsert server pool: %v", err)
	}
	if _, err := q.CreateServerVM(context.Background(), sqlcdb.CreateServerVMParams{
		TenantID: tenantID,
		DataAddr: dataAddr,
		Status:   "active",
	}); err != nil {
		t.Fatalf("create server vm: %v", err)
	}
}

func TestAllocationUsage_HappyPath(t *testing.T) {
	pool := httpOpenTestPool(t)
	usage := &fakeUsage{resp: serverapi.TenantUsage{TenantID: "acme", UsedBytes: 4096, SizeBytes: dashGiB}}
	srv, svc := startUsageServer(t, pool, usage)
	cookie, tenantID := httpSeedAdmin(t, pool, svc)
	userID := dashGetUserID(t, cookie, srv.URL)

	asvc := dashAllocSvc(pool)
	alloc, err := asvc.Allocate(context.Background(), userID, dashGiB)
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	seedServerVMAndPool(t, pool, tenantID, "data-srv-1.example.com:6363", "ops-srv-1.example.com:6443")

	url := srv.URL + "/api/allocations/" + uuidString(alloc.ID) + "/usage"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.AddCookie(cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var body allocationUsageDTO
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.AllocationID != uuidString(alloc.ID) {
		t.Fatalf("allocation_id = %q", body.AllocationID)
	}
	if body.UsedBytes != 4096 {
		t.Fatalf("used_bytes = %d, want 4096", body.UsedBytes)
	}
	if body.SizeBytes != dashGiB {
		t.Fatalf("size_bytes = %d, want %d", body.SizeBytes, dashGiB)
	}
	if usage.gotOps != "ops-srv-1.example.com:6443" || usage.gotTenant != tenantID {
		t.Fatalf("usage call = ops=%q tenant=%q", usage.gotOps, usage.gotTenant)
	}
}

func TestAllocationUsage_BeforeFirstMountReportsZero(t *testing.T) {
	pool := httpOpenTestPool(t)
	usage := &fakeUsage{}
	srv, svc := startUsageServer(t, pool, usage)
	cookie, _ := httpSeedAdmin(t, pool, svc)
	userID := dashGetUserID(t, cookie, srv.URL)

	asvc := dashAllocSvc(pool)
	alloc, err := asvc.Allocate(context.Background(), userID, 2*dashGiB)
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	// No server_vms row → handler returns zero usage with the DB-known size.

	url := srv.URL + "/api/allocations/" + uuidString(alloc.ID) + "/usage"
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.AddCookie(cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var body allocationUsageDTO
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.UsedBytes != 0 || body.SizeBytes != 2*dashGiB {
		t.Fatalf("body = %+v", body)
	}
	if usage.calls != 0 {
		t.Fatalf("expected no remote call, got %d", usage.calls)
	}
}

func TestAllocationUsage_RequiresAuth(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv, _ := startUsageServer(t, pool, &fakeUsage{})

	resp, err := http.Get(srv.URL + "/api/allocations/00000000-0000-0000-0000-000000000000/usage")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestAllocationUsage_OtherUserAllocationReturns404(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv, svc := startUsageServer(t, pool, &fakeUsage{})
	cookie, _ := httpSeedAdmin(t, pool, svc)

	q := sqlcdb.New(pool)
	if _, err := q.CreateUser(context.Background(), sqlcdb.CreateUserParams{Email: "bob@acme.example", TenantID: "acme"}); err != nil {
		t.Fatal(err)
	}
	bob, err := q.GetUserByEmail(context.Background(), "bob@acme.example")
	if err != nil {
		t.Fatal(err)
	}
	asvc := dashAllocSvc(pool)
	bobsAlloc, err := asvc.Allocate(context.Background(), bob.ID, dashGiB)
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}

	url := srv.URL + "/api/allocations/" + uuidString(bobsAlloc.ID) + "/usage"
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.AddCookie(cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestAllocationUsage_RemoteFailureReturns502(t *testing.T) {
	pool := httpOpenTestPool(t)
	usage := &fakeUsage{err: errors.New("boom")}
	srv, svc := startUsageServer(t, pool, usage)
	cookie, tenantID := httpSeedAdmin(t, pool, svc)
	userID := dashGetUserID(t, cookie, srv.URL)

	asvc := dashAllocSvc(pool)
	alloc, _ := asvc.Allocate(context.Background(), userID, dashGiB)
	seedServerVMAndPool(t, pool, tenantID, "data-srv-1.example.com:6363", "ops-srv-1.example.com:6443")

	url := srv.URL + "/api/allocations/" + uuidString(alloc.ID) + "/usage"
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.AddCookie(cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
}
