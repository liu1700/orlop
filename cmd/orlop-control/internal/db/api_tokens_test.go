package db_test

import (
	"context"
	"testing"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/db/sqlcdb"
)

func TestAPITokens_CreateGetListRevoke(t *testing.T) {
	pool := openTestPool(t)
	q := sqlcdb.New(pool)
	ctx := context.Background()

	// Seed tenant + user inline (same pattern as agent_enroll_handlers_test.go).
	const tenantID = "apitokens"
	if _, err := q.CreateTenant(ctx, sqlcdb.CreateTenantParams{ID: tenantID, Name: "ApiTokens"}); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	user, err := q.CreateUser(ctx, sqlcdb.CreateUserParams{
		Email:    "alice@apitokens.example",
		TenantID: tenantID,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	const tokenHash = "deadbeefcafebabe1234567890abcdef1234567890abcdef1234567890abcdef"

	created, err := q.CreateAPIToken(ctx, sqlcdb.CreateAPITokenParams{
		UserID:    user.ID,
		Name:      "test-token",
		TokenHash: tokenHash,
		Prefix:    "orlop_abcdef",
	})
	if err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}
	if created.Name != "test-token" {
		t.Errorf("name = %q; want test-token", created.Name)
	}

	byHash, err := q.GetAPITokenByHash(ctx, tokenHash)
	if err != nil {
		t.Fatalf("GetAPITokenByHash: %v", err)
	}
	if byHash.ID != created.ID {
		t.Errorf("hash lookup returned wrong id")
	}
	if byHash.RevokedAt.Valid {
		t.Errorf("expected non-revoked")
	}

	list, err := q.ListAPITokensByUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListAPITokensByUser: %v", err)
	}
	if len(list) != 1 || list[0].ID != created.ID {
		t.Errorf("list = %+v; want one element with our id", list)
	}

	if err := q.RevokeAPIToken(ctx, sqlcdb.RevokeAPITokenParams{ID: created.ID, UserID: user.ID}); err != nil {
		t.Fatalf("RevokeAPIToken: %v", err)
	}

	listAfter, _ := q.ListAPITokensByUser(ctx, user.ID)
	if len(listAfter) != 0 {
		t.Errorf("list after revoke should be empty, got %d", len(listAfter))
	}

	// Hash lookup still works post-revoke (so middleware can return a clear "revoked" error).
	byHashAfter, err := q.GetAPITokenByHash(ctx, tokenHash)
	if err != nil {
		t.Fatalf("GetAPITokenByHash post-revoke: %v", err)
	}
	if !byHashAfter.RevokedAt.Valid {
		t.Errorf("expected revoked_at to be set post-revoke")
	}

	if err := q.TouchAPITokenLastUsed(ctx, created.ID); err != nil {
		t.Fatalf("TouchAPITokenLastUsed: %v", err)
	}
	row, _ := q.GetAPITokenByID(ctx, created.ID)
	if !row.LastUsedAt.Valid {
		t.Errorf("expected last_used_at to be set")
	}
}
