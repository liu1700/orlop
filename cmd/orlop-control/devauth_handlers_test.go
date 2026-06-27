package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/allocations"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/devauth"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage/postgres"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage/postgres/db"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage/postgres/db/sqlcdb"
)

func httpTestDatabaseURL() string { return os.Getenv("TEST_DATABASE_URL") }

var (
	httpMigrateOnce sync.Once
	httpMigrateErr  error
)

func httpOpenTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	u := httpTestDatabaseURL()
	if u == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping HTTP integration test")
	}
	httpMigrateOnce.Do(func() {
		httpMigrateErr = db.MigrateUp(context.Background(), u)
	})
	if httpMigrateErr != nil {
		t.Fatalf("migrate up: %v", httpMigrateErr)
	}
	pool, err := pgxpool.New(context.Background(), u)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// CASCADE handles FK cleanup; sessions_anonymous and disk_allocations
		// are listed explicitly so tests that only touch them (Phase 2
		// anonymous sandbox flow) still get a clean slate, since the older
		// tables they descend from may not be referenced.
		_, _ = pool.Exec(context.Background(),
			"TRUNCATE TABLE sessions_anonymous, disk_allocations, server_pool, refresh_tokens, access_tokens, device_authorizations, agent_enrollments, cert_revocations, server_vms, users, tenants RESTART IDENTITY CASCADE")
		pool.Close()
	})
	return pool
}

func httpStartServer(t *testing.T, pool *pgxpool.Pool) (*httptest.Server, *devauth.Service) {
	t.Helper()
	return httpStartServerWithFencer(t, pool, nil)
}

func httpStartServerWithFencer(t *testing.T, pool *pgxpool.Pool, fencer mountLeaseFencer) (*httptest.Server, *devauth.Service) {
	t.Helper()
	svc := devauth.NewService(postgres.New(pool), slog.New(slog.NewTextHandler(io.Discard, nil)))
	router := newRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), runtimeDeps{
		devAuth:          svc,
		store:            postgres.New(pool),
		allocations:      allocations.NewService(postgres.New(pool), nil),
		mountLeaseFencer: fencer,
	}, config{})
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	return srv, svc
}

// httpSeedAdminCounter ensures repeated calls within the same test create
// distinct users (different email) under the shared "acme" tenant. Without
// this the cross-user tests double-call this helper and trip the unique
// users.email / tenants.id constraints.
var httpSeedAdminCounter atomic.Int32

func httpSeedAdmin(t *testing.T, pool *pgxpool.Pool, svc *devauth.Service) (cookie *http.Cookie, tenantID string) {
	t.Helper()
	ctx := context.Background()
	q := sqlcdb.New(pool)
	// Idempotent tenant create: only the first call inserts; subsequent
	// calls inside the same test pick up the existing row.
	if _, err := pool.Exec(ctx,
		`INSERT INTO tenants (id, name) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING`,
		"acme", "Acme"); err != nil {
		t.Fatal(err)
	}
	seq := httpSeedAdminCounter.Add(1)
	email := fmt.Sprintf("alice-%d@acme.example", seq)
	user, err := q.CreateUser(ctx, sqlcdb.CreateUserParams{Email: email, TenantID: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	tok, _, err := svc.IssueAdminSession(ctx, user.ID, "acme")
	if err != nil {
		t.Fatal(err)
	}
	return &http.Cookie{Name: devauth.AdminSessionCookie, Value: tok}, "acme"
}

// TestHTTPAdminSessionRouteSetsCookie covers the admin-session cookie bootstrap:
// GET /admin/session?token=TOK (the URL printed by `orlop-control user seed`)
// validates the seed admin_session token, sets the HttpOnly cookie, and
// redirects to the dashboard root.
func TestHTTPAdminSessionRouteSetsCookie(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv, svc := httpStartServer(t, pool)
	cookie, _ := httpSeedAdmin(t, pool, svc)

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(srv.URL + "/admin/session?token=" + url.QueryEscape(cookie.Value))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/" {
		t.Fatalf("redirect location = %q, want /", loc)
	}
	found := false
	for _, c := range resp.Cookies() {
		if c.Name == devauth.AdminSessionCookie && c.Value == cookie.Value && c.HttpOnly {
			found = true
		}
	}
	if !found {
		t.Fatalf("HttpOnly admin cookie not set; cookies=%v", resp.Cookies())
	}
}

// TestHTTPAdminSessionRouteRejectsBadToken proves an unknown token is refused
// (401) and no cookie is set.
func TestHTTPAdminSessionRouteRejectsBadToken(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv, _ := httpStartServer(t, pool)

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(srv.URL + "/admin/session?token=not-a-real-token")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name == devauth.AdminSessionCookie && c.Value != "" {
			t.Fatalf("admin cookie should not be set for a bad token; got %v", c)
		}
	}
}
