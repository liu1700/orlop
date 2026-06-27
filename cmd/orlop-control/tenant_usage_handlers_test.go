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

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/serverapi"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
)

const tenantUsageOwner = "99999999-9999-9999-9999-999999999999"

// stubTenantUsageQuerier injects fixed rows (or errors) for the owner→tenant→
// server resolution so the handler is testable without a live DB.
type stubTenantUsageQuerier struct {
	user     storage.User
	userErr  error
	allocs   []storage.Allocation
	allocErr error
	vm       storage.ServerVM
	vmErr    error
	pool     storage.Server
	poolErr  error
}

func (s stubTenantUsageQuerier) GetUser(context.Context, uuid.UUID) (storage.User, error) {
	return s.user, s.userErr
}

func (s stubTenantUsageQuerier) ListAllocationsForUser(context.Context, uuid.UUID) ([]storage.Allocation, error) {
	return s.allocs, s.allocErr
}

func (s stubTenantUsageQuerier) GetServerVMByTenant(context.Context, string) (storage.ServerVM, error) {
	return s.vm, s.vmErr
}

func (s stubTenantUsageQuerier) GetServerPoolByDataAddr(context.Context, string) (storage.Server, error) {
	return s.pool, s.poolErr
}

func tenantUsageRouter(q controlTenantUsageQuerier, usage tenantUsageClient, token string) http.Handler {
	r := chi.NewRouter()
	mountControlTenantUsage(r, RequireServiceToken(token),
		newControlTenantUsageHandlers(slog.New(slog.NewTextHandler(io.Discard, nil)), q, usage))
	return r
}

func doTenantUsage(t *testing.T, h http.Handler, owner, auth string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1/tenants/"+owner+"/usage", nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestTenantUsage_HappyPath(t *testing.T) {
	q := stubTenantUsageQuerier{
		user:   storage.User{TenantID: "u_" + tenantUsageOwner},
		allocs: []storage.Allocation{{}}, // one allocation (no per-agent tenant → owner tenant)
		vm:     storage.ServerVM{DataAddr: "data-srv-1:6363"},
		pool:   storage.Server{OpsAddr: "ops-srv-1:6443"},
	}
	usage := &fakeUsage{resp: serverapi.TenantUsage{UsedBytes: 4096}}
	rec := doTenantUsage(t, tenantUsageRouter(q, usage, "svc"), tenantUsageOwner, "Bearer svc")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var body tenantUsageDTO
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.OwnerID != tenantUsageOwner || body.UsedBytes != 4096 {
		t.Fatalf("body = %+v", body)
	}
	if usage.gotOps != "ops-srv-1:6443" || usage.gotTenant != "u_"+tenantUsageOwner {
		t.Fatalf("usage call = ops=%q tenant=%q", usage.gotOps, usage.gotTenant)
	}
}

func TestTenantUsage_NoUserReportsZero(t *testing.T) {
	q := stubTenantUsageQuerier{userErr: storage.ErrNotFound}
	usage := &fakeUsage{}
	rec := doTenantUsage(t, tenantUsageRouter(q, usage, "svc"), tenantUsageOwner, "Bearer svc")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var body tenantUsageDTO
	_ = json.NewDecoder(rec.Body).Decode(&body)
	if body.UsedBytes != 0 {
		t.Fatalf("used_bytes = %d, want 0", body.UsedBytes)
	}
	if usage.calls != 0 {
		t.Fatalf("expected no remote call, got %d", usage.calls)
	}
}

func TestTenantUsage_NeverPlacedReportsZero(t *testing.T) {
	q := stubTenantUsageQuerier{
		user:   storage.User{TenantID: "u_" + tenantUsageOwner},
		allocs: []storage.Allocation{{}},
		vmErr:  storage.ErrNotFound, // tenant has no server_vms row yet (no mount)
	}
	usage := &fakeUsage{}
	rec := doTenantUsage(t, tenantUsageRouter(q, usage, "svc"), tenantUsageOwner, "Bearer svc")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var body tenantUsageDTO
	_ = json.NewDecoder(rec.Body).Decode(&body)
	if body.UsedBytes != 0 {
		t.Fatalf("used_bytes = %d, want 0", body.UsedBytes)
	}
	if usage.calls != 0 {
		t.Fatalf("expected no remote call, got %d", usage.calls)
	}
}

func TestTenantUsage_RequiresServiceToken(t *testing.T) {
	q := stubTenantUsageQuerier{user: storage.User{TenantID: "u_" + tenantUsageOwner}}
	h := tenantUsageRouter(q, &fakeUsage{}, "svc")

	if rec := doTenantUsage(t, h, tenantUsageOwner, "Bearer wrong"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token status = %d, want 401", rec.Code)
	}
	if rec := doTenantUsage(t, h, tenantUsageOwner, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing token status = %d, want 401", rec.Code)
	}
}

func TestTenantUsage_RemoteFailureReturns502(t *testing.T) {
	q := stubTenantUsageQuerier{
		user:   storage.User{TenantID: "u_" + tenantUsageOwner},
		allocs: []storage.Allocation{{}},
		vm:     storage.ServerVM{DataAddr: "data-srv-1:6363"},
		pool:   storage.Server{OpsAddr: "ops-srv-1:6443"},
	}
	usage := &fakeUsage{err: errors.New("boom")}
	rec := doTenantUsage(t, tenantUsageRouter(q, usage, "svc"), tenantUsageOwner, "Bearer svc")
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
}

func TestTenantUsage_NoUsageClientReturns503(t *testing.T) {
	q := stubTenantUsageQuerier{user: storage.User{TenantID: "u_" + tenantUsageOwner}}
	rec := doTenantUsage(t, tenantUsageRouter(q, nil, "svc"), tenantUsageOwner, "Bearer svc")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}
