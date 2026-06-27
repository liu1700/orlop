package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/allocations"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/ca"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/db/sqlcdb"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/devauth"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/secrets"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage/postgres"
)

func TestAgentEnrollHappyPath(t *testing.T) {
	pool := httpOpenTestPool(t)
	q := sqlcdb.New(pool)
	token, userID := seedEnrollTenant(t, q, "acme", "active", false)
	srv := startEnrollServer(t, pool, newEnrollCA(t, "acme"), nil)

	resp := postEnroll(t, srv.URL, token)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	var body struct {
		ClientCertPEM string `json:"client_cert_pem"`
		ClientKeyPEM  string `json:"client_key_pem"`
		CAChainPEM    string `json:"ca_chain_pem"`
		ServerAddr    string `json:"server_addr"`
		ExpiresAt     string `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.ClientKeyPEM == "" || body.ServerAddr != "tenant-acme.orlop.example.com" {
		t.Fatalf("bad enroll body: %#v", body)
	}
	leaf := mustParseLeaf(t, []byte(body.ClientCertPEM))
	roots, intermediates := mustParseChain(t, []byte(body.CAChainPEM))
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		CurrentTime:   time.Now(),
	}); err != nil {
		t.Fatalf("cert verify: %v", err)
	}
	// Every enroll is agent-scoped: the leaf carries the tenant SAN plus the
	// per-agent SAN (the single isolation policy, issue #9). seedEnrollTenant
	// provisions agent "agent-<tenant>".
	if len(leaf.URIs) != 2 ||
		leaf.URIs[0].String() != "spiffe://test.example/tenant/acme" ||
		leaf.URIs[1].String() != "spiffe://test.example/agent/agent-acme" {
		t.Fatalf("leaf URI SANs = %v", leaf.URIs)
	}
	if got := leaf.NotAfter.UTC().Format(time.RFC3339); body.ExpiresAt != got {
		t.Fatalf("expires_at = %q, want %q", body.ExpiresAt, got)
	}
	rows, err := q.ListActiveEnrollmentsForUser(context.Background(), userID)
	if err != nil {
		t.Fatal(err)
	}
	expectedSerial := strings.ToUpper(hex.EncodeToString(leaf.SerialNumber.Bytes()))
	if len(rows) != 1 || rows[0].CertSerial != expectedSerial {
		t.Fatalf("enrollments = %#v, expected serial = %s", rows, expectedSerial)
	}
}

func TestAgentEnrollReturnsAllocation(t *testing.T) {
	pool := httpOpenTestPool(t)
	q := sqlcdb.New(pool)
	_, userID := seedEnrollTenant(t, q, "acme", "active", false)
	allocation := seedAgentAllocation(t, q, userID, "acme", "agent-acme-alloc")
	token := "allocation-token"
	if _, err := q.CreateAccessToken(context.Background(), sqlcdb.CreateAccessTokenParams{
		TokenHash:    sha256Hex(token),
		Purpose:      devauth.PurposeDevice,
		UserID:       userID,
		TenantID:     "acme",
		ExpiresAt:    pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true},
		AllocationID: allocation.ID,
	}); err != nil {
		t.Fatal(err)
	}
	srv := startEnrollServer(t, pool, newEnrollCA(t, "acme"), nil)

	resp := postEnroll(t, srv.URL, token)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}
	var body struct {
		AllocationID string `json:"allocation_id"`
		SizeBytes    int64  `json:"size_bytes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.AllocationID != uuidString(allocation.ID) {
		t.Fatalf("allocation_id = %q, want %q", body.AllocationID, uuidString(allocation.ID))
	}
	if body.SizeBytes != allocation.SizeBytes {
		t.Fatalf("size_bytes = %d, want %d", body.SizeBytes, allocation.SizeBytes)
	}
}

// TestAgentEnrollTokenSingleUse covers issue #6: a per-pod agent-enroll token
// mints exactly one cert. The first /agent/enroll succeeds; replaying the same
// token is rejected because it was consumed on first use.
func TestAgentEnrollTokenSingleUse(t *testing.T) {
	pool := httpOpenTestPool(t)
	q := sqlcdb.New(pool)
	ctx := context.Background()
	_, userID := seedEnrollTenant(t, q, "acme", "active", false)

	alloc := seedAgentAllocation(t, q, userID, "acme", "agent-acme-enroll")
	const token = "single-use-enroll-token"
	if _, err := q.CreateAccessToken(ctx, sqlcdb.CreateAccessTokenParams{
		TokenHash:    sha256Hex(token),
		Purpose:      devauth.PurposeAgentEnroll,
		UserID:       userID,
		TenantID:     "acme",
		ExpiresAt:    pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true},
		AllocationID: alloc.ID,
	}); err != nil {
		t.Fatal(err)
	}

	srv := startEnrollServer(t, pool, newEnrollCA(t, "acme"), nil)

	first := postEnroll(t, srv.URL, token)
	defer first.Body.Close()
	if first.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(first.Body)
		t.Fatalf("first enroll status = %d, want 200; body = %s", first.StatusCode, b)
	}

	second := postEnroll(t, srv.URL, token)
	defer second.Body.Close()
	if second.StatusCode != http.StatusUnauthorized {
		b, _ := io.ReadAll(second.Body)
		t.Fatalf("replayed enroll status = %d, want 401; body = %s", second.StatusCode, b)
	}

	row, err := q.GetAccessTokenByHash(ctx, sha256Hex(token))
	if err != nil {
		t.Fatal(err)
	}
	if !row.ConsumedAt.Valid {
		t.Fatal("expected consumed_at to be set after first enroll")
	}
}

// TestAgentEnrollDeviceTokenMultiUse guards the other side of issue #6: a
// device-flow access token is a multi-use session, so enrolling with it must
// NOT consume it. Only PurposeAgentEnroll tokens are single-use.
func TestAgentEnrollDeviceTokenMultiUse(t *testing.T) {
	pool := httpOpenTestPool(t)
	q := sqlcdb.New(pool)
	token, _ := seedEnrollTenant(t, q, "acme", "active", false) // PurposeDevice token
	srv := startEnrollServer(t, pool, newEnrollCA(t, "acme"), nil)

	for i := 1; i <= 2; i++ {
		resp := postEnroll(t, srv.URL, token)
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("device-token enroll #%d status = %d, want 200; body = %s", i, resp.StatusCode, b)
		}
		resp.Body.Close()
	}

	row, err := q.GetAccessTokenByHash(context.Background(), sha256Hex(token))
	if err != nil {
		t.Fatal(err)
	}
	if row.ConsumedAt.Valid {
		t.Fatal("device-flow token must not be consumed by /agent/enroll")
	}
}

// TestAgentEnrollRejectsDisallowedTenant covers issue #8: an enroll whose tenant
// is not permitted by the CA bootstrap policy is rejected with 403, not lazily
// self-onboarded.
func TestAgentEnrollRejectsDisallowedTenant(t *testing.T) {
	pool := httpOpenTestPool(t)
	q := sqlcdb.New(pool)
	seedEnrollTenant(t, q, "evilcorp", "active", false) // exists in DB, not pre-bootstrapped

	denyAll := newEnrollCAWithPolicy(t, func(string) bool { return false })
	srv := startEnrollServer(t, pool, denyAll, nil)

	resp := postEnroll(t, srv.URL, "test-token-evilcorp")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 403; body = %s", resp.StatusCode, b)
	}
	var body struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Error != "access_denied" || body.ErrorDescription != "tenant_not_allowed" {
		t.Fatalf("body = %+v, want access_denied / tenant_not_allowed", body)
	}
	if denyAll.HasTenant("evilcorp") {
		t.Fatal("disallowed tenant must not have been bootstrapped")
	}
}

// TestAgentEnrollAllowsDynamicTenant confirms the #8 gate does NOT break the
// legitimate server-derived dynamic (u_/a_) tenant flow under the default policy.
func TestAgentEnrollAllowsDynamicTenant(t *testing.T) {
	pool := httpOpenTestPool(t)
	q := sqlcdb.New(pool)
	seedEnrollTenant(t, q, "u_owner123", "active", false) // dynamic per-user tenant

	policy := buildCATenantPolicy(config{CAAllowDynamicTenants: true})
	caDyn := newEnrollCAWithPolicy(t, policy)
	srv := startEnrollServer(t, pool, caDyn, nil)

	resp := postEnroll(t, srv.URL, "test-token-u_owner123")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body = %s", resp.StatusCode, b)
	}
	if !caDyn.HasTenant("u_owner123") {
		t.Fatal("dynamic tenant should have been lazily bootstrapped")
	}
}

func TestAgentEnrollRejectsInvalidToken(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv := startEnrollServer(t, pool, newEnrollCA(t, "acme"), nil)

	resp := postEnroll(t, srv.URL, "bogus")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestAgentEnrollRejectsSuspendedTenant(t *testing.T) {
	pool := httpOpenTestPool(t)
	q := sqlcdb.New(pool)
	token, _ := seedEnrollTenant(t, q, "acme", "active", true)
	srv := startEnrollServer(t, pool, newEnrollCA(t, "acme"), nil)

	resp := postEnroll(t, srv.URL, token)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	// Regression for #153: 403 must include error_description so the CLI can
	// surface a precise message (suspension vs. allocation revoke vs. unknown
	// tenant). Without this the user sees "tenant or user suspended" for
	// every 403 cause, even a revoked allocation.
	var body struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode 403 body: %v", err)
	}
	if body.Error != "access_denied" {
		t.Errorf("error = %q, want access_denied", body.Error)
	}
	if body.ErrorDescription != "tenant_suspended" {
		t.Errorf("error_description = %q, want tenant_suspended", body.ErrorDescription)
	}
}

func TestAgentEnrollReturns503WhenServerVMInactive(t *testing.T) {
	pool := httpOpenTestPool(t)
	q := sqlcdb.New(pool)
	token, _ := seedEnrollTenant(t, q, "acme", "provisioning", false)
	srv := startEnrollServer(t, pool, newEnrollCA(t, "acme"), nil)

	resp := postEnroll(t, srv.URL, token)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
	if got := resp.Header.Get("Retry-After"); got == "" {
		t.Fatal("Retry-After header missing")
	}
}

func TestAgentEnrollRateLimit(t *testing.T) {
	pool := httpOpenTestPool(t)
	q := sqlcdb.New(pool)
	token, _ := seedEnrollTenant(t, q, "acme", "active", false)
	srv := startEnrollServer(t, pool, newEnrollCA(t, "acme"), newAgentEnrollLimiter(1, time.Hour))

	resp := postEnroll(t, srv.URL, token)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first status = %d, want 200", resp.StatusCode)
	}
	resp = postEnroll(t, srv.URL, token)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second status = %d, want 429", resp.StatusCode)
	}
}

func startEnrollServer(t *testing.T, pool *pgxpool.Pool, agentCA *ca.CA, limit *agentEnrollLimiter) *httptest.Server {
	t.Helper()
	return startEnrollServerWithAdmin(t, pool, agentCA, limit, nil)
}

func startEnrollServerWithAdmin(t *testing.T, pool *pgxpool.Pool, agentCA *ca.CA, limit *agentEnrollLimiter, serverAdmin allocations.ServerAdmin) *httptest.Server {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := devauth.NewService(postgres.New(pool), logger)
	allocSvc := allocations.NewService(postgres.New(pool), nil)
	router := newRouter(logger, runtimeDeps{
		devAuth:     svc,
		store:       postgres.New(pool),
		agentCA:     agentCA,
		enrollLimit: limit,
		allocations: allocSvc,
		serverAdmin: serverAdmin,
	}, config{})
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	return srv
}

func seedEnrollTenant(t *testing.T, q *sqlcdb.Queries, tenantID, serverStatus string, suspended bool) (string, pgtype.UUID) {
	t.Helper()
	ctx := context.Background()
	if _, err := q.CreateTenant(ctx, sqlcdb.CreateTenantParams{ID: tenantID, Name: "Acme"}); err != nil {
		t.Fatal(err)
	}
	user, err := q.CreateUser(ctx, sqlcdb.CreateUserParams{Email: "alice@" + tenantID + ".example", TenantID: tenantID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.CreateServerVM(ctx, sqlcdb.CreateServerVMParams{
		TenantID: tenantID,
		DataAddr: "tenant-" + tenantID + ".orlop.example.com",
		Status:   serverStatus,
	}); err != nil {
		t.Fatal(err)
	}
	if suspended {
		if err := q.SuspendTenant(ctx, tenantID); err != nil {
			t.Fatal(err)
		}
	}
	// Every cert is bound to a specific agent via a SPIFFE /agent/<id> SAN, so an
	// enroll without a provisioned agent disk gets no cert (the single isolation
	// policy in agent_enroll_handlers.go). Seed an agent-scoped allocation and
	// point the token at it so the happy paths actually mint.
	alloc := seedAgentAllocation(t, q, user.ID, tenantID, "agent-"+tenantID)
	token := "test-token-" + tenantID
	if _, err := q.CreateAccessToken(ctx, sqlcdb.CreateAccessTokenParams{
		TokenHash:    sha256Hex(token),
		Purpose:      devauth.PurposeDevice,
		UserID:       user.ID,
		TenantID:     tenantID,
		ExpiresAt:    pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true},
		AllocationID: alloc.ID,
	}); err != nil {
		t.Fatal(err)
	}
	return token, user.ID
}

// seedAgentAllocation provisions an agent-scoped disk allocation (agent_id set),
// the shape the enroll handler requires before it will mint a per-agent cert.
func seedAgentAllocation(t *testing.T, q *sqlcdb.Queries, userID pgtype.UUID, tenantID, agentID string) sqlcdb.DiskAllocation {
	t.Helper()
	alloc, err := q.UpsertAgentAllocation(context.Background(), sqlcdb.UpsertAgentAllocationParams{
		UserID:    userID,
		AgentID:   pgtype.Text{String: agentID, Valid: true},
		TenantID:  pgtype.Text{String: tenantID, Valid: true},
		SizeBytes: 5 * 1024 * 1024 * 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	return alloc
}

func newEnrollCA(t *testing.T, tenants ...string) *ca.CA {
	t.Helper()
	c, err := ca.LoadOrInit(context.Background(), secrets.NewMemory(), ca.Env{
		TrustDomain: "test.example",
		OrgName:     "Test",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, tenant := range tenants {
		if err := c.BootstrapTenant(context.Background(), tenant); err != nil {
			t.Fatal(err)
		}
	}
	return c
}

// newEnrollCAWithPolicy builds a CA whose lazy-bootstrap is gated by allow
// (issue #8). No tenants are pre-bootstrapped, so the policy governs whether an
// enroll's tenant gets an intermediate.
func newEnrollCAWithPolicy(t *testing.T, allow func(string) bool) *ca.CA {
	t.Helper()
	c, err := ca.LoadOrInit(context.Background(), secrets.NewMemory(), ca.Env{
		TrustDomain:    "test.example",
		OrgName:        "Test",
		AllowBootstrap: allow,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func postEnroll(t *testing.T, baseURL, token string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, baseURL+"/agent/enroll", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func mustParseLeaf(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("missing leaf certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func mustParseChain(t *testing.T, chainPEM []byte) (*x509.CertPool, *x509.CertPool) {
	t.Helper()
	var certs []*x509.Certificate
	rest := chainPEM
	for len(bytes.TrimSpace(rest)) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" {
			t.Fatal("bad CA chain PEM")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		certs = append(certs, cert)
	}
	if len(certs) < 2 {
		t.Fatalf("chain has %d certs, want intermediate and root", len(certs))
	}
	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()
	for i, cert := range certs {
		if i == len(certs)-1 {
			roots.AddCert(cert)
		} else {
			intermediates.AddCert(cert)
		}
	}
	return roots, intermediates
}

// enrollFakeAdmin is a test ServerAdmin that records calls and returns success.
type enrollFakeAdmin struct {
	calls []enrollAdminCall
}

type enrollAdminCall struct {
	OpsAddr   string
	TenantID  string
	Name      string
	SizeBytes int64
}

func (f *enrollFakeAdmin) RegisterTenant(_ context.Context, opsAddr, tenantID, ownerTenantID, name string, sizeBytes int64) (uint32, error) {
	f.calls = append(f.calls, enrollAdminCall{OpsAddr: opsAddr, TenantID: tenantID, Name: name, SizeBytes: sizeBytes})
	return 1, nil
}

// UnregisterTenant: not exercised by enroll tests, but required so
// *enrollFakeAdmin satisfies runtimeDeps.serverAdmin's wider interface.
func (f *enrollFakeAdmin) UnregisterTenant(_ context.Context, _, _ string) error {
	return nil
}

func TestEnrollPlacesTenantWhenServerVMMissing(t *testing.T) {
	pool := httpOpenTestPool(t)
	q := sqlcdb.New(pool)
	ctx := context.Background()

	// Seed tenant + user + server_pool, but NO server_vms row.
	tenantID := "acme-place"
	if _, err := q.CreateTenant(ctx, sqlcdb.CreateTenantParams{ID: tenantID, Name: "Acme Place"}); err != nil {
		t.Fatal(err)
	}
	user, err := q.CreateUser(ctx, sqlcdb.CreateUserParams{Email: "alice@" + tenantID + ".example", TenantID: tenantID})
	if err != nil {
		t.Fatal(err)
	}
	// Server pool row with enough capacity.
	const poolDataAddr = "data-srv-place.orlop.example.com"
	const poolOpsAddr = "ops-srv-place.orlop.example.com"
	if _, err := q.UpsertServerPool(ctx, sqlcdb.UpsertServerPoolParams{
		DataAddr:   poolDataAddr,
		OpsAddr:    poolOpsAddr,
		TotalBytes: 10 * int64(1<<30),
		FreeBytes:  10 * int64(1<<30),
		Status:     "available",
	}); err != nil {
		t.Fatal(err)
	}
	// Agent-scoped allocation for the user (agent_id set so the enroll mints).
	const allocSize = int64(2 * (1 << 30))
	alloc, err := q.UpsertAgentAllocation(ctx, sqlcdb.UpsertAgentAllocationParams{
		UserID:    user.ID,
		AgentID:   pgtype.Text{String: "agent-" + tenantID, Valid: true},
		TenantID:  pgtype.Text{String: tenantID, Valid: true},
		SizeBytes: allocSize,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Access token with AllocationID set.
	token := "place-token"
	if _, err := q.CreateAccessToken(ctx, sqlcdb.CreateAccessTokenParams{
		TokenHash:    sha256Hex(token),
		Purpose:      devauth.PurposeDevice,
		UserID:       user.ID,
		TenantID:     tenantID,
		ExpiresAt:    pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true},
		AllocationID: alloc.ID,
	}); err != nil {
		t.Fatal(err)
	}

	fakeAdmin := &enrollFakeAdmin{}
	agentCA := newEnrollCA(t, tenantID)
	srv := startEnrollServerWithAdmin(t, pool, agentCA, nil, fakeAdmin)

	resp := postEnroll(t, srv.URL, token)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}

	var body struct {
		ServerAddr string `json:"server_addr"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.ServerAddr != poolDataAddr {
		t.Fatalf("server_addr = %q, want %q", body.ServerAddr, poolDataAddr)
	}

	// RegisterTenant called once with the ops_addr (not the data_addr).
	if len(fakeAdmin.calls) != 1 {
		t.Fatalf("RegisterTenant called %d times, want 1", len(fakeAdmin.calls))
	}
	call := fakeAdmin.calls[0]
	if call.TenantID != tenantID || call.SizeBytes != allocSize || call.OpsAddr != poolOpsAddr {
		t.Fatalf("unexpected admin call: %+v", call)
	}

	// server_vms row inserted with the data_addr (FUSE clients use this).
	vm, err := q.GetServerVMByTenant(ctx, tenantID)
	if err != nil {
		t.Fatalf("GetServerVMByTenant: %v", err)
	}
	if vm.DataAddr != poolDataAddr {
		t.Fatalf("vm.DataAddr = %q, want %q", vm.DataAddr, poolDataAddr)
	}

	// server_pool free_bytes decremented.
	updatedPool, err := q.GetServerPoolByDataAddr(ctx, poolDataAddr)
	if err != nil {
		t.Fatalf("GetServerPoolByDataAddr: %v", err)
	}
	if updatedPool.FreeBytes != 10*int64(1<<30)-allocSize {
		t.Fatalf("free_bytes = %d, want %d", updatedPool.FreeBytes, 10*int64(1<<30)-allocSize)
	}
}
