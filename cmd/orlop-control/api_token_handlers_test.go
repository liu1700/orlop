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

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/db/sqlcdb"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/devauth"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/tokens"
)

// postTokenRequest issues POST /v1/tokens with the given admin cookie
// and JSON body. Caller is responsible for closing the response body.
func postTokenRequest(t *testing.T, srvURL string, cookie *http.Cookie, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, srvURL+"/v1/tokens", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestPostAPIToken_HappyPath(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv, svc := httpStartServer(t, pool)
	cookie, _ := httpSeedAdmin(t, pool, svc)

	resp := postTokenRequest(t, srv.URL, cookie, `{"name":"ci-bot"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d; want 201", resp.StatusCode)
	}
	var got struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		Prefix string `json:"prefix"`
		Token  string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Name != "ci-bot" {
		t.Errorf("name = %q; want ci-bot", got.Name)
	}
	if !strings.HasPrefix(got.Token, "orlop_") {
		t.Errorf("token = %q; want orlop_ prefix", got.Token)
	}
	if !strings.HasPrefix(got.Token, got.Prefix) {
		t.Errorf("token %q does not start with prefix %q", got.Token, got.Prefix)
	}

	// Sanity: the row exists in the DB and stores the SHA-256 hash of the
	// raw token, never the raw value itself.
	q := sqlcdb.New(pool)
	row, err := q.GetAPITokenByID(context.Background(), mustParseUUID(t, got.ID))
	if err != nil {
		t.Fatalf("GetAPITokenByID: %v", err)
	}
	if row.Name != "ci-bot" {
		t.Errorf("DB name = %q; want ci-bot", row.Name)
	}
	if row.Prefix != got.Prefix {
		t.Errorf("DB prefix = %q; want %q", row.Prefix, got.Prefix)
	}
	// Verify the raw token authenticates against the stored hash via the
	// canonical hash-by-hash lookup. Confirms persistence is hash-only.
	byHash, err := q.GetAPITokenByHash(context.Background(), tokens.Hash(got.Token))
	if err != nil {
		t.Fatalf("GetAPITokenByHash: %v", err)
	}
	if uuidString(byHash.ID) != got.ID {
		t.Errorf("hash lookup id = %q; want %q", uuidString(byHash.ID), got.ID)
	}
}

func TestPostAPIToken_RejectsEmptyName(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv, svc := httpStartServer(t, pool)
	cookie, _ := httpSeedAdmin(t, pool, svc)

	resp := postTokenRequest(t, srv.URL, cookie, `{"name":""}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400", resp.StatusCode)
	}
}

func TestPostAPIToken_Unauthenticated(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv, _ := httpStartServer(t, pool)

	resp := postTokenRequest(t, srv.URL, nil /* no cookie */, `{"name":"x"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d; want 401", resp.StatusCode)
	}
}

// mustParseUUID converts a UUID string (e.g. from a JSON response) into
// the pgtype.UUID shape sqlc-generated queries expect.
func mustParseUUID(t *testing.T, s string) pgtype.UUID {
	t.Helper()
	var u pgtype.UUID
	if err := u.Scan(s); err != nil {
		t.Fatalf("parse uuid %q: %v", s, err)
	}
	return u
}

func TestGetAPITokens_ReturnsActiveTokens(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv, svc := httpStartServer(t, pool)
	cookie, _ := httpSeedAdmin(t, pool, svc)
	q := sqlcdb.New(pool)
	ctx := context.Background()

	// Resolve the seeded user's id so we can write rows directly.
	uid := dashGetUserID(t, cookie, srv.URL)

	// Seed: two active tokens, one revoked.
	for _, name := range []string{"active1", "active2"} {
		raw := "orlop_seed_" + name
		_, err := q.CreateAPIToken(ctx, sqlcdb.CreateAPITokenParams{
			UserID:    uid,
			Name:      name,
			TokenHash: tokens.Hash(raw),
			Prefix:    raw[:12],
		})
		if err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}
	revokedRaw := "orlop_seed_revoked"
	revokedRow, err := q.CreateAPIToken(ctx, sqlcdb.CreateAPITokenParams{
		UserID:    uid,
		Name:      "revoked",
		TokenHash: tokens.Hash(revokedRaw),
		Prefix:    revokedRaw[:12],
	})
	if err != nil {
		t.Fatalf("seed revoked: %v", err)
	}
	if err := q.RevokeAPIToken(ctx, sqlcdb.RevokeAPITokenParams{ID: revokedRow.ID, UserID: uid}); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// GET /v1/tokens
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/tokens", nil)
	req.AddCookie(cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	var got []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("len = %d; want 2 (only active tokens listed)", len(got))
	}
	for _, row := range got {
		if _, ok := row["name"]; !ok {
			t.Errorf("missing name field")
		}
		if _, ok := row["prefix"]; !ok {
			t.Errorf("missing prefix field")
		}
		for _, banned := range []string{"token", "token_hash", "hash", "revoked_at"} {
			if _, ok := row[banned]; ok {
				t.Errorf("list response must NOT include %q (leak): %v", banned, row)
			}
		}
	}
}

func TestGetAPITokens_EmptyReturnsEmptyArray(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv, svc := httpStartServer(t, pool)
	cookie, _ := httpSeedAdmin(t, pool, svc)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/tokens", nil)
	req.AddCookie(cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	trimmed := strings.TrimSpace(string(body))
	if trimmed != "[]" {
		t.Errorf("body = %q; want \"[]\" (empty list, not null)", trimmed)
	}
}

func TestGetAPITokens_Unauthenticated(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv, _ := httpStartServer(t, pool)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/tokens", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d; want 401", resp.StatusCode)
	}
}

func TestDeleteAPIToken_Revokes(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv, svc := httpStartServer(t, pool)
	cookie, _ := httpSeedAdmin(t, pool, svc)
	q := sqlcdb.New(pool)
	ctx := context.Background()

	uid := dashGetUserID(t, cookie, srv.URL)
	created, err := q.CreateAPIToken(ctx, sqlcdb.CreateAPITokenParams{
		UserID:    uid,
		Name:      "to-revoke",
		TokenHash: tokens.Hash("orlop_to_revoke"),
		Prefix:    "orlop_to_rev",
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	resp := deleteToken(t, srv.URL, cookie, uuidString(created.ID))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d body = %s", resp.StatusCode, body)
	}

	row, err := q.GetAPITokenByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("post-revoke get: %v", err)
	}
	if !row.RevokedAt.Valid {
		t.Errorf("expected revoked_at set; got %+v", row.RevokedAt)
	}
}

func TestDeleteAPIToken_OtherUserCannotRevoke(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv, svc := httpStartServer(t, pool)
	cookie, _ := httpSeedAdmin(t, pool, svc)
	q := sqlcdb.New(pool)
	ctx := context.Background()

	// Seed a second tenant + user; create a token owned by them.
	if _, err := q.CreateTenant(ctx, sqlcdb.CreateTenantParams{ID: "victim-co", Name: "Victim Co"}); err != nil {
		t.Fatalf("create victim tenant: %v", err)
	}
	other, err := q.CreateUser(ctx, sqlcdb.CreateUserParams{Email: "victim@victim-co.example", TenantID: "victim-co"})
	if err != nil {
		t.Fatalf("create victim user: %v", err)
	}

	created, err := q.CreateAPIToken(ctx, sqlcdb.CreateAPITokenParams{
		UserID:    other.ID,
		Name:      "victim",
		TokenHash: tokens.Hash("orlop_victim_token"),
		Prefix:    "orlop_victim",
	})
	if err != nil {
		t.Fatalf("seed victim token: %v", err)
	}

	// Auth context is the *first* admin (alice). She tries to revoke victim's token.
	resp := deleteToken(t, srv.URL, cookie, uuidString(created.ID))
	defer resp.Body.Close()
	// Idempotent / not-found semantics: 404 (do not leak existence).
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d; want 404", resp.StatusCode)
	}

	row, err := q.GetAPITokenByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if row.RevokedAt.Valid {
		t.Errorf("victim's token was revoked by other user — privilege escalation")
	}
}

func TestDeleteAPIToken_Idempotent(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv, svc := httpStartServer(t, pool)
	cookie, _ := httpSeedAdmin(t, pool, svc)
	q := sqlcdb.New(pool)
	ctx := context.Background()

	uid := dashGetUserID(t, cookie, srv.URL)
	created, err := q.CreateAPIToken(ctx, sqlcdb.CreateAPITokenParams{
		UserID:    uid,
		Name:      "x",
		TokenHash: tokens.Hash("orlop_x_idempo"),
		Prefix:    "orlop_x_idem",
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	for i := 0; i < 2; i++ {
		resp := deleteToken(t, srv.URL, cookie, uuidString(created.ID))
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("iter %d: status = %d", i, resp.StatusCode)
		}
	}
}

func deleteToken(t *testing.T, srvURL string, cookie *http.Cookie, id string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodDelete, srvURL+"/v1/tokens/"+id, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// requireBearerProbe wraps RequireBearer with a tiny handler that echoes
// {tenant_id, purpose} from the request context as JSON. Used by the
// API-token middleware tests below. Driving the middleware directly is
// cleaner than going through /agent/enroll, which depends on the agent CA
// being wired up.
func requireBearerProbe(t *testing.T, pool *pgxpool.Pool) *httptest.Server {
	t.Helper()
	svc := devauth.NewService(pool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	q := sqlcdb.New(pool)
	h := RequireBearer(svc, q)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ident, ok := IdentityFromRequest(r)
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"tenant_id": ident.TenantID,
			"purpose":   ident.Purpose,
		})
	}))
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

// TestRequireBearer_AcceptsAPIToken verifies the API-token branch of the
// middleware: a valid orlop_ token must pass through to the next handler
// with the user's tenant_id and PurposeAPIToken.
func TestRequireBearer_AcceptsAPIToken(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv := requireBearerProbe(t, pool)
	q := sqlcdb.New(pool)
	ctx := context.Background()

	if _, err := q.CreateTenant(ctx, sqlcdb.CreateTenantParams{ID: "bear-test", Name: "BearTest"}); err != nil {
		t.Fatalf("tenant: %v", err)
	}
	user, err := q.CreateUser(ctx, sqlcdb.CreateUserParams{Email: "bear@bear-test.example", TenantID: "bear-test"})
	if err != nil {
		t.Fatalf("user: %v", err)
	}

	tok, err := tokens.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if _, err := q.CreateAPIToken(ctx, sqlcdb.CreateAPITokenParams{
		UserID:    user.ID,
		Name:      "auth-test",
		TokenHash: tok.Hash,
		Prefix:    tok.Prefix,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	req.Header.Set("Authorization", "Bearer "+tok.Raw)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d body = %s; want 200", resp.StatusCode, body)
	}
	var got struct {
		TenantID string `json:"tenant_id"`
		Purpose  string `json:"purpose"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.TenantID != "bear-test" {
		t.Errorf("tenant_id = %q; want bear-test", got.TenantID)
	}
	if got.Purpose != devauth.PurposeAPIToken {
		t.Errorf("purpose = %q; want %q", got.Purpose, devauth.PurposeAPIToken)
	}
}

// TestRequireBearer_RejectsRevokedAPIToken verifies that a token with
// revoked_at set produces a 401, even if the token bytes are otherwise
// well-formed and the user is healthy.
func TestRequireBearer_RejectsRevokedAPIToken(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv := requireBearerProbe(t, pool)
	q := sqlcdb.New(pool)
	ctx := context.Background()

	if _, err := q.CreateTenant(ctx, sqlcdb.CreateTenantParams{ID: "rev-test", Name: "RevTest"}); err != nil {
		t.Fatalf("tenant: %v", err)
	}
	user, err := q.CreateUser(ctx, sqlcdb.CreateUserParams{Email: "rev@rev-test.example", TenantID: "rev-test"})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := tokens.Generate()
	if err != nil {
		t.Fatal(err)
	}
	row, err := q.CreateAPIToken(ctx, sqlcdb.CreateAPITokenParams{
		UserID: user.ID, Name: "rev",
		TokenHash: tok.Hash, Prefix: tok.Prefix,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := q.RevokeAPIToken(ctx, sqlcdb.RevokeAPITokenParams{ID: row.ID, UserID: user.ID}); err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	req.Header.Set("Authorization", "Bearer "+tok.Raw)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d; want 401 (revoked token)", resp.StatusCode)
	}
}

// TestRequireBearer_RejectsUnknownAPIToken verifies that a well-formed
// orlop_ token with no matching DB row produces 401, not a 5xx.
func TestRequireBearer_RejectsUnknownAPIToken(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv := requireBearerProbe(t, pool)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	req.Header.Set("Authorization", "Bearer orlop_neverissuednever_zzzzzzzzzzzzzzzzzzzzz")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d; want 401 (unknown token)", resp.StatusCode)
	}
}

// TestRequireBearer_RejectsSuspendedUserAPIToken verifies that a healthy
// token belonging to a suspended user produces 403 (access_denied), not
// 401 — matches the OAuth branch's suspension semantics.
func TestRequireBearer_RejectsSuspendedUserAPIToken(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv := requireBearerProbe(t, pool)
	q := sqlcdb.New(pool)
	ctx := context.Background()

	if _, err := q.CreateTenant(ctx, sqlcdb.CreateTenantParams{ID: "susp-test", Name: "SuspTest"}); err != nil {
		t.Fatal(err)
	}
	user, err := q.CreateUser(ctx, sqlcdb.CreateUserParams{Email: "susp@susp-test.example", TenantID: "susp-test"})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := tokens.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.CreateAPIToken(ctx, sqlcdb.CreateAPITokenParams{
		UserID: user.ID, Name: "susp",
		TokenHash: tok.Hash, Prefix: tok.Prefix,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE users SET suspended_at = now() WHERE id = $1`, user.ID); err != nil {
		t.Fatalf("suspend: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	req.Header.Set("Authorization", "Bearer "+tok.Raw)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d; want 403 (suspended user)", resp.StatusCode)
	}
}

// TestRequireBearer_RejectsSuspendedTenantAPIToken verifies that a healthy
// token belonging to a healthy user under a suspended tenant produces 403
// (access_denied). Without the tenants join in GetAPITokenByHash, a
// tenant-level suspension would silently allow orlop_ tokens through —
// matches the OAuth branch's tenant-suspension semantics.
func TestRequireBearer_RejectsSuspendedTenantAPIToken(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv := requireBearerProbe(t, pool)
	q := sqlcdb.New(pool)
	ctx := context.Background()

	if _, err := q.CreateTenant(ctx, sqlcdb.CreateTenantParams{ID: "susp-tenant", Name: "SuspTenant"}); err != nil {
		t.Fatal(err)
	}
	user, err := q.CreateUser(ctx, sqlcdb.CreateUserParams{Email: "u@susp-tenant.example", TenantID: "susp-tenant"})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := tokens.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.CreateAPIToken(ctx, sqlcdb.CreateAPITokenParams{
		UserID: user.ID, Name: "susp-tenant",
		TokenHash: tok.Hash, Prefix: tok.Prefix,
	}); err != nil {
		t.Fatal(err)
	}
	if err := q.SuspendTenant(ctx, "susp-tenant"); err != nil {
		t.Fatalf("suspend tenant: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	req.Header.Set("Authorization", "Bearer "+tok.Raw)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d; want 403 (suspended tenant)", resp.StatusCode)
	}
}
