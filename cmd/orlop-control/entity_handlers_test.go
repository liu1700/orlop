package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/allocations"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/db/sqlcdb"
)

const (
	testOwnerID = "22222222-2222-2222-2222-222222222222"
	testAgentID = "33333333-3333-3333-3333-333333333333"
	testHandle  = "44444444-4444-4444-4444-444444444444"
	testTenant  = "u_22222222-2222-2222-2222-222222222222"
)

// fakeEntityQuerier is an in-memory entityQuerier so the handler tests need no
// live database. It records the calls it received and serves a canned
// allocation row keyed on agent_id.
type fakeEntityQuerier struct {
	ensuredTenant  sqlcdb.EnsureTenantParams
	ensuredUser    sqlcdb.EnsureUserWithIDParams
	upserted       sqlcdb.UpsertAgentAllocationParams
	allocByAgent   map[string]sqlcdb.DiskAllocation // agent_id -> row
	usersByID      map[string]sqlcdb.User           // uuid string -> row
	reassigned     sqlcdb.ReassignAgentAllocationParams
	ensureTenantEr error
	upsertErr      error
}

func newFakeEntityQuerier() *fakeEntityQuerier {
	return &fakeEntityQuerier{
		allocByAgent: map[string]sqlcdb.DiskAllocation{},
		usersByID:    map[string]sqlcdb.User{},
	}
}

// Account-budget path stubs: no placement in unit tests, so the live resize is skipped.
func (f *fakeEntityQuerier) ListAllocationsForUser(_ context.Context, _ pgtype.UUID) ([]sqlcdb.DiskAllocation, error) {
	return nil, nil
}
func (f *fakeEntityQuerier) UpdateAllocationSize(_ context.Context, _ sqlcdb.UpdateAllocationSizeParams) (sqlcdb.DiskAllocation, error) {
	return sqlcdb.DiskAllocation{}, nil
}
func (f *fakeEntityQuerier) GetServerVMByTenant(_ context.Context, _ string) (sqlcdb.ServerVm, error) {
	return sqlcdb.ServerVm{}, pgx.ErrNoRows
}
func (f *fakeEntityQuerier) GetServerPoolByDataAddr(_ context.Context, _ string) (sqlcdb.ServerPool, error) {
	return sqlcdb.ServerPool{}, pgx.ErrNoRows
}

func (f *fakeEntityQuerier) GetUser(_ context.Context, id pgtype.UUID) (sqlcdb.User, error) {
	row, ok := f.usersByID[uuidString(id)]
	if !ok {
		return sqlcdb.User{}, pgx.ErrNoRows
	}
	return row, nil
}

func (f *fakeEntityQuerier) EnsureTenant(_ context.Context, arg sqlcdb.EnsureTenantParams) error {
	f.ensuredTenant = arg
	return f.ensureTenantEr
}

func (f *fakeEntityQuerier) EnsureUserWithID(_ context.Context, arg sqlcdb.EnsureUserWithIDParams) error {
	f.ensuredUser = arg
	return nil
}

func (f *fakeEntityQuerier) UpsertAgentAllocation(_ context.Context, arg sqlcdb.UpsertAgentAllocationParams) (sqlcdb.DiskAllocation, error) {
	f.upserted = arg
	if f.upsertErr != nil {
		return sqlcdb.DiskAllocation{}, f.upsertErr
	}
	var id pgtype.UUID
	_ = id.Scan(testHandle)
	row := sqlcdb.DiskAllocation{ID: id, UserID: arg.UserID, AgentID: arg.AgentID, SizeBytes: arg.SizeBytes}
	f.allocByAgent[arg.AgentID.String] = row
	return row, nil
}

func (f *fakeEntityQuerier) GetAllocationByAgent(_ context.Context, agentID pgtype.Text) (sqlcdb.DiskAllocation, error) {
	row, ok := f.allocByAgent[agentID.String]
	if !ok {
		return sqlcdb.DiskAllocation{}, pgx.ErrNoRows
	}
	return row, nil
}

func (f *fakeEntityQuerier) ReassignAgentAllocation(_ context.Context, arg sqlcdb.ReassignAgentAllocationParams) error {
	f.reassigned = arg
	if row, ok := f.allocByAgent[arg.AgentID.String]; ok {
		row.UserID = arg.UserID
		f.allocByAgent[arg.AgentID.String] = row
	}
	return nil
}

func (f *fakeEntityQuerier) RevokeAllocation(_ context.Context, arg sqlcdb.RevokeAllocationParams) (sqlcdb.DiskAllocation, error) {
	for k, row := range f.allocByAgent {
		if uuidString(row.ID) == uuidString(arg.ID) {
			delete(f.allocByAgent, k)
			return row, nil
		}
	}
	return sqlcdb.DiskAllocation{}, pgx.ErrNoRows
}

// recordingMinter is a stub enrollTokenMinter that records its last-call args
// and returns a canned token/expiry, so the enroll-token handler tests need no
// live devauth.Service.
type recordingMinter struct {
	called     bool
	gotUserID  pgtype.UUID
	gotTenant  string
	gotAllocID pgtype.UUID
	token      string
	expiresAt  time.Time
	err        error
}

func (m *recordingMinter) mint(_ context.Context, userID pgtype.UUID, tenantID string, allocationID pgtype.UUID) (string, time.Time, error) {
	m.called = true
	m.gotUserID = userID
	m.gotTenant = tenantID
	m.gotAllocID = allocationID
	if m.err != nil {
		return "", time.Time{}, m.err
	}
	return m.token, m.expiresAt, nil
}

// fakeResizer is a stub allocationResizer: it records the Resize call and
// returns a canned allocation, so the handler tests need neither a live
// allocations.Service nor a orlop-server.
type fakeResizer struct {
	called   bool
	gotAlloc pgtype.UUID
	gotUser  pgtype.UUID
	gotSize  int64
	err      error
}

func (f *fakeResizer) Resize(_ context.Context, _ allocations.TenantResizer, allocationID, userID pgtype.UUID, newSizeBytes int64) (allocations.Allocation, error) {
	f.called = true
	f.gotAlloc, f.gotUser, f.gotSize = allocationID, userID, newSizeBytes
	if f.err != nil {
		return allocations.Allocation{}, f.err
	}
	return allocations.Allocation{ID: allocationID, UserID: userID, SizeBytes: newSizeBytes}, nil
}

func entityRouter(q entityQuerier, token string) http.Handler {
	return entityRouterWithMinter(q, token, (&recordingMinter{}).mint)
}

func entityRouterWithMinter(q entityQuerier, token string, mint enrollTokenMinter) http.Handler {
	return entityRouterWith(q, token, mint, &fakeResizer{})
}

func entityRouterWith(q entityQuerier, token string, mint enrollTokenMinter, resize allocationResizer) http.Handler {
	return entityRouterWithPurger(q, token, mint, resize, nil)
}

func entityRouterWithPurger(q entityQuerier, token string, mint enrollTokenMinter, resize allocationResizer, purge allocationPurger) http.Handler {
	r := chi.NewRouter()
	var purgeAPI allocations.AgentDataPurger
	if purge != nil {
		purgeAPI = fakePurgeAPI{}
	}
	mountEntities(r, RequireServiceToken(token),
		newEntityHandlers(slog.New(slog.NewTextHandler(io.Discard, nil)), q, mint, resize, nil, purge, purgeAPI, agentDiskInitialGrantBytes))
	return r
}

// fakePurgeAPI satisfies allocations.AgentDataPurger; the stub purger ignores
// it, it exists only so handleDelete sees a non-nil pair and runs the inline
// purge.
type fakePurgeAPI struct{}

func (fakePurgeAPI) PurgeAgentData(context.Context, string, string, string) error        { return nil }
func (fakePurgeAPI) UnregisterTenant(context.Context, string, string) error              { return nil }
func (fakePurgeAPI) ClearActiveMountLease(context.Context, string, string, string) error { return nil }

// fakePurger records PurgeAllocation calls.
type fakePurger struct {
	called   bool
	gotAlloc pgtype.UUID
	err      error
}

func (f *fakePurger) PurgeAllocation(_ context.Context, _ allocations.AgentDataPurger, allocationID pgtype.UUID) error {
	f.called = true
	f.gotAlloc = allocationID
	return f.err
}

func doEntity(t *testing.T, h http.Handler, method, path, auth, body string) *httptest.ResponseRecorder {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// --- service-token middleware ---

func TestRequireServiceToken(t *testing.T) {
	const expected = "svc-secret"
	cases := []struct {
		name     string
		expected string
		auth     string
		want     int
	}{
		{"valid", expected, "Bearer svc-secret", http.StatusOK},
		{"invalid", expected, "Bearer wrong", http.StatusUnauthorized},
		{"missing", expected, "", http.StatusUnauthorized},
		{"empty-expected-rejects-valid-looking", "", "Bearer anything", http.StatusUnauthorized},
		{"empty-expected-rejects-missing", "", "", http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := RequireServiceToken(tc.expected)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.auth != "" {
				req.Header.Set("Authorization", tc.auth)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d; want %d", rec.Code, tc.want)
			}
		})
	}
}

// --- provision (POST /v1/entities) ---

func TestProvisionEntity_HappyPath(t *testing.T) {
	q := newFakeEntityQuerier()
	h := entityRouter(q, "svc")
	body := `{"entity_type":"agent","entity_id":"` + testAgentID + `","owner_id":"` + testOwnerID + `"}`
	rec := doEntity(t, h, http.MethodPost, "/v1/entities", "Bearer svc", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	var got entityResponse
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Handle != testHandle {
		t.Errorf("handle = %q; want %q", got.Handle, testHandle)
	}
	if want := "/mnt/orlop/agents/" + testAgentID; got.VirtualPath != want {
		t.Errorf("virtual_path = %q; want %q", got.VirtualPath, want)
	}
	// D3b: the agent's disk gets its OWN tenant "a_" + agent (the last EnsureTenant).
	if q.ensuredTenant.ID != "a_"+testAgentID {
		t.Errorf("agent tenant id = %q; want a_%s", q.ensuredTenant.ID, testAgentID)
	}
	// D3: dg user reuses owner UUID, tenant is the D2 tenant, synthetic email.
	if got := uuidString(q.ensuredUser.ID); got != testOwnerID {
		t.Errorf("user id = %q; want %q", got, testOwnerID)
	}
	if q.ensuredUser.TenantID != "u_"+testOwnerID {
		t.Errorf("user tenant = %q", q.ensuredUser.TenantID)
	}
	if want := testOwnerID + "@agents.orlop.internal"; q.ensuredUser.Email != want {
		t.Errorf("user email = %q; want %q", q.ensuredUser.Email, want)
	}
	// D4: upsert keyed on agent_id, with the small initial elastic grant (1 GiB),
	// not the 10 GiB ceiling.
	if q.upserted.AgentID.String != testAgentID {
		t.Errorf("upsert agent_id = %q", q.upserted.AgentID.String)
	}
	if q.upserted.SizeBytes != agentDiskInitialGrantBytes {
		t.Errorf("upsert size = %d; want %d", q.upserted.SizeBytes, agentDiskInitialGrantBytes)
	}
	if q.upserted.SizeBytes != 1*1024*1024*1024 {
		t.Errorf("initial grant = %d; want 1 GiB", q.upserted.SizeBytes)
	}
	// The allocation is stamped with the per-agent tenant so a re-parent never moves data.
	if q.upserted.TenantID.String != "a_"+testAgentID {
		t.Errorf("upsert tenant_id = %q; want a_%s", q.upserted.TenantID.String, testAgentID)
	}
}

// TestProvisionEntity_GrantBytesField checks the X3 rename: grant_bytes sets the
// allocation's size_bytes (the grant), and the legacy quota_bytes name still works
// as an alias for back-compat (grant_bytes wins when both are present).
func TestProvisionEntity_GrantBytesField(t *testing.T) {
	cases := []struct {
		name string
		body string
		want int64
	}{
		{"grant_bytes", `{"entity_type":"agent","entity_id":"` + testAgentID + `","owner_id":"` + testOwnerID + `","grant_bytes":2147483648}`, 2 << 30},
		{"legacy quota_bytes", `{"entity_type":"agent","entity_id":"` + testAgentID + `","owner_id":"` + testOwnerID + `","quota_bytes":134217728}`, 128 << 20},
		{"grant_bytes wins", `{"entity_type":"agent","entity_id":"` + testAgentID + `","owner_id":"` + testOwnerID + `","grant_bytes":2147483648,"quota_bytes":134217728}`, 2 << 30},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			q := newFakeEntityQuerier()
			h := entityRouter(q, "svc")
			rec := doEntity(t, h, http.MethodPost, "/v1/entities", "Bearer svc", tc.body)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d; want 200 (body: %s)", rec.Code, rec.Body.String())
			}
			if q.upserted.SizeBytes != tc.want {
				t.Errorf("size_bytes = %d; want %d", q.upserted.SizeBytes, tc.want)
			}
		})
	}
}

func TestProvisionEntity_Auth(t *testing.T) {
	q := newFakeEntityQuerier()
	h := entityRouter(q, "svc")
	body := `{"entity_type":"agent","entity_id":"` + testAgentID + `","owner_id":"` + testOwnerID + `"}`
	rec := doEntity(t, h, http.MethodPost, "/v1/entities", "Bearer nope", body)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d; want 401", rec.Code)
	}
}

func TestProvisionEntity_Validation(t *testing.T) {
	cases := []struct {
		name string
		body string
		want int
	}{
		{"malformed", `{`, http.StatusBadRequest},
		{"wrong-type", `{"entity_type":"user","entity_id":"a","owner_id":"` + testOwnerID + `"}`, http.StatusBadRequest},
		{"missing-entity-id", `{"entity_type":"agent","owner_id":"` + testOwnerID + `"}`, http.StatusBadRequest},
		{"missing-owner", `{"entity_type":"agent","entity_id":"a"}`, http.StatusBadRequest},
		{"bad-owner-uuid", `{"entity_type":"agent","entity_id":"a","owner_id":"not-a-uuid"}`, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := entityRouter(newFakeEntityQuerier(), "svc")
			rec := doEntity(t, h, http.MethodPost, "/v1/entities", "Bearer svc", tc.body)
			if rec.Code != tc.want {
				t.Fatalf("status = %d; want %d (body: %s)", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

// --- resolve (GET /v1/entities/{type}/{id}) ---

func TestResolveEntity(t *testing.T) {
	q := newFakeEntityQuerier()
	h := entityRouter(q, "svc")

	// Provision first so there is a row to resolve.
	body := `{"entity_type":"agent","entity_id":"` + testAgentID + `","owner_id":"` + testOwnerID + `"}`
	if rec := doEntity(t, h, http.MethodPost, "/v1/entities", "Bearer svc", body); rec.Code != http.StatusOK {
		t.Fatalf("provision status = %d", rec.Code)
	}

	rec := doEntity(t, h, http.MethodGet, "/v1/entities/agent/"+testAgentID, "Bearer svc", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200", rec.Code)
	}
	var got entityResponse
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Handle != testHandle || got.VirtualPath != "/mnt/orlop/agents/"+testAgentID {
		t.Errorf("resolve = %+v", got)
	}
}

func TestResolveEntity_NotFound(t *testing.T) {
	h := entityRouter(newFakeEntityQuerier(), "svc")
	rec := doEntity(t, h, http.MethodGet, "/v1/entities/agent/"+testAgentID, "Bearer svc", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d; want 404", rec.Code)
	}
}

func TestResolveEntity_WrongType(t *testing.T) {
	h := entityRouter(newFakeEntityQuerier(), "svc")
	rec := doEntity(t, h, http.MethodGet, "/v1/entities/user/x", "Bearer svc", "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400", rec.Code)
	}
}

func TestResolveEntity_Auth(t *testing.T) {
	h := entityRouter(newFakeEntityQuerier(), "svc")
	rec := doEntity(t, h, http.MethodGet, "/v1/entities/agent/"+testAgentID, "", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d; want 401", rec.Code)
	}
}

// --- set quota (PATCH /v1/entities/{type}/{id}) ---

// provisionAgent registers an agent so GetAllocationByAgent(testAgentID) resolves
// to a row with ID=testHandle, UserID=testOwnerID.
func provisionAgent(t *testing.T, q entityQuerier) {
	t.Helper()
	body := `{"entity_type":"agent","entity_id":"` + testAgentID + `","owner_id":"` + testOwnerID + `"}`
	if rec := doEntity(t, entityRouter(q, "svc"), http.MethodPost, "/v1/entities", "Bearer svc", body); rec.Code != http.StatusOK {
		t.Fatalf("provision: status = %d", rec.Code)
	}
}

func TestSetQuota_RoutesThroughResize(t *testing.T) {
	q := newFakeEntityQuerier()
	provisionAgent(t, q)

	resize := &fakeResizer{}
	h := entityRouterWith(q, "svc", (&recordingMinter{}).mint, resize)
	rec := doEntity(t, h, http.MethodPatch, "/v1/entities/agent/"+testAgentID, "Bearer svc", `{"quota_bytes":1073741824}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	if !resize.called {
		t.Fatal("handleSetQuota did not route through resize")
	}
	if resize.gotSize != 1073741824 {
		t.Errorf("resize size = %d; want 1073741824", resize.gotSize)
	}
	if uuidString(resize.gotAlloc) != testHandle {
		t.Errorf("resize allocation = %q; want %q", uuidString(resize.gotAlloc), testHandle)
	}
}

func TestSetQuota_NoCapacityIsConflict(t *testing.T) {
	q := newFakeEntityQuerier()
	provisionAgent(t, q)

	resize := &fakeResizer{err: allocations.ErrNoCapacity}
	h := entityRouterWith(q, "svc", (&recordingMinter{}).mint, resize)
	rec := doEntity(t, h, http.MethodPatch, "/v1/entities/agent/"+testAgentID, "Bearer svc", `{"quota_bytes":1073741824}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d body = %s; want 409", rec.Code, rec.Body.String())
	}
}

func TestSetQuota_UnknownAgentIs404(t *testing.T) {
	q := newFakeEntityQuerier()
	h := entityRouterWith(q, "svc", (&recordingMinter{}).mint, &fakeResizer{})
	rec := doEntity(t, h, http.MethodPatch, "/v1/entities/agent/"+testAgentID, "Bearer svc", `{"quota_bytes":1073741824}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d; want 404", rec.Code)
	}
}

func TestSetQuota_InvalidBody(t *testing.T) {
	q := newFakeEntityQuerier()
	h := entityRouterWith(q, "svc", (&recordingMinter{}).mint, &fakeResizer{})
	rec := doEntity(t, h, http.MethodPatch, "/v1/entities/agent/"+testAgentID, "Bearer svc", `{"quota_bytes":0}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400", rec.Code)
	}
}

// --- enroll-token (POST /v1/agents/{id}/enroll-token) ---

// seedAllocationAndUser wires the querier so GetAllocationByAgent(agent) returns
// an allocation owned by testOwnerID, and GetUser(owner) returns a user in
// testTenant — the chain the enroll-token handler walks.
func seedAllocationAndUser(q *fakeEntityQuerier) {
	var ownerID, allocID pgtype.UUID
	_ = ownerID.Scan(testOwnerID)
	_ = allocID.Scan(testHandle)
	q.allocByAgent[testAgentID] = sqlcdb.DiskAllocation{
		ID:      allocID,
		UserID:  ownerID,
		AgentID: pgtype.Text{String: testAgentID, Valid: true},
	}
	q.usersByID[testOwnerID] = sqlcdb.User{ID: ownerID, TenantID: testTenant}
}

func TestEnrollToken_HappyPath(t *testing.T) {
	q := newFakeEntityQuerier()
	seedAllocationAndUser(q)
	minter := &recordingMinter{token: "enroll-abc", expiresAt: time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)}
	h := entityRouterWithMinter(q, "svc", minter.mint)

	rec := doEntity(t, h, http.MethodPost, "/v1/agents/"+testAgentID+"/enroll-token", "Bearer svc", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	var got enrollTokenResponse
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Token != "enroll-abc" {
		t.Errorf("token = %q; want enroll-abc", got.Token)
	}
	if want := "2026-06-04T12:00:00Z"; got.ExpiresAt != want {
		t.Errorf("expires_at = %q; want %q", got.ExpiresAt, want)
	}
	// The minter must be called with the allocation's owner/tenant/id.
	if !minter.called {
		t.Fatal("minter was not called")
	}
	if uuidString(minter.gotUserID) != testOwnerID {
		t.Errorf("mint user = %q; want %q", uuidString(minter.gotUserID), testOwnerID)
	}
	if minter.gotTenant != testTenant {
		t.Errorf("mint tenant = %q; want %q", minter.gotTenant, testTenant)
	}
	if uuidString(minter.gotAllocID) != testHandle {
		t.Errorf("mint allocation = %q; want %q", uuidString(minter.gotAllocID), testHandle)
	}
}

func TestEnrollToken_NoAllocation(t *testing.T) {
	minter := &recordingMinter{token: "x"}
	h := entityRouterWithMinter(newFakeEntityQuerier(), "svc", minter.mint)
	rec := doEntity(t, h, http.MethodPost, "/v1/agents/"+testAgentID+"/enroll-token", "Bearer svc", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d; want 404 (body: %s)", rec.Code, rec.Body.String())
	}
	if minter.called {
		t.Error("minter must not be called when there is no allocation")
	}
}

func TestEnrollToken_Auth(t *testing.T) {
	q := newFakeEntityQuerier()
	seedAllocationAndUser(q)
	h := entityRouter(q, "svc")
	cases := []struct {
		name string
		auth string
	}{
		{"missing", ""},
		{"wrong", "Bearer nope"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := doEntity(t, h, http.MethodPost, "/v1/agents/"+testAgentID+"/enroll-token", tc.auth, "")
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d; want 401", rec.Code)
			}
		})
	}
}

// --- DELETE /v1/entities/agent/{id}: revoke + inline purge ---

func TestEntityDeleteRevokesAndPurgesInline(t *testing.T) {
	q := newFakeEntityQuerier()
	var allocID pgtype.UUID
	_ = allocID.Scan(testHandle)
	q.allocByAgent[testAgentID] = sqlcdb.DiskAllocation{ID: allocID}

	purger := &fakePurger{}
	h := entityRouterWithPurger(q, "svc-secret", (&recordingMinter{}).mint, &fakeResizer{}, purger)

	rec := doEntity(t, h, http.MethodDelete, "/v1/entities/agent/"+testAgentID, "Bearer svc-secret", "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	if !purger.called {
		t.Fatalf("inline purge was not invoked")
	}
	if uuidString(purger.gotAlloc) != testHandle {
		t.Errorf("purged allocation = %s, want %s", uuidString(purger.gotAlloc), testHandle)
	}
}

func TestEntityDeletePurgeFailureStill204(t *testing.T) {
	q := newFakeEntityQuerier()
	var allocID pgtype.UUID
	_ = allocID.Scan(testHandle)
	q.allocByAgent[testAgentID] = sqlcdb.DiskAllocation{ID: allocID}

	purger := &fakePurger{err: context.DeadlineExceeded}
	h := entityRouterWithPurger(q, "svc-secret", (&recordingMinter{}).mint, &fakeResizer{}, purger)

	rec := doEntity(t, h, http.MethodDelete, "/v1/entities/agent/"+testAgentID, "Bearer svc-secret", "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 (purge failure must not fail the revoke)", rec.Code)
	}
	if !purger.called {
		t.Fatalf("inline purge was not invoked")
	}
}

func TestEntityDeleteUnknownAgentSkipsPurge(t *testing.T) {
	purger := &fakePurger{}
	h := entityRouterWithPurger(newFakeEntityQuerier(), "svc-secret", (&recordingMinter{}).mint, &fakeResizer{}, purger)

	rec := doEntity(t, h, http.MethodDelete, "/v1/entities/agent/"+testAgentID, "Bearer svc-secret", "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	if purger.called {
		t.Errorf("purge invoked for an agent with no allocation")
	}
}
