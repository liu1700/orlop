package main

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage/postgres/db/sqlcdb"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/tokens"
)

// mintToken creates a tenant + user + an API token with the given expiry and
// returns the raw token to present as a bearer.
func mintToken(t *testing.T, q *sqlcdb.Queries, tenantID, email string, expiresAt pgtype.Timestamptz) string {
	t.Helper()
	ctx := context.Background()
	if _, err := q.CreateTenant(ctx, sqlcdb.CreateTenantParams{ID: tenantID, Name: tenantID}); err != nil {
		t.Fatalf("tenant: %v", err)
	}
	user, err := q.CreateUser(ctx, sqlcdb.CreateUserParams{Email: email, TenantID: tenantID})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := tokens.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.CreateAPIToken(ctx, sqlcdb.CreateAPITokenParams{
		UserID: user.ID, Name: "k", TokenHash: tok.Hash, Prefix: tok.Prefix, ExpiresAt: expiresAt,
	}); err != nil {
		t.Fatal(err)
	}
	return tok.Raw
}

func bearerStatus(t *testing.T, url, raw string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url+"/", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func TestRequireBearer_RejectsExpiredAPIToken(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv := requireBearerProbe(t, pool)
	raw := mintToken(t, sqlcdb.New(pool), "exp-test", "exp@exp-test.example",
		pgtype.Timestamptz{Time: time.Now().Add(-time.Hour), Valid: true})
	if got := bearerStatus(t, srv.URL, raw); got != http.StatusUnauthorized {
		t.Errorf("status = %d; want 401 (expired token)", got)
	}
}

func TestRequireBearer_AcceptsFutureExpiryAPIToken(t *testing.T) {
	pool := httpOpenTestPool(t)
	srv := requireBearerProbe(t, pool)
	raw := mintToken(t, sqlcdb.New(pool), "fut-test", "fut@fut-test.example",
		pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true})
	if got := bearerStatus(t, srv.URL, raw); got != http.StatusOK {
		t.Errorf("status = %d; want 200 (unexpired token)", got)
	}
}
