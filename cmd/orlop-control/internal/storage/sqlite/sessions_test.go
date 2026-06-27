package sqlite

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
)

func TestAccessTokensAndConsume(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	u := seedUser(t, s, "acme", "a@acme.test")
	future := time.Now().Add(time.Hour)

	if err := s.CreateAccessToken(ctx, storage.NewAccessToken{TokenHash: "atok", Purpose: "admin_session", UserID: u.ID, TenantID: "acme", ExpiresAt: future}); err != nil {
		t.Fatalf("create access token: %v", err)
	}
	auth, err := s.GetAccessTokenByHash(ctx, "atok")
	if err != nil || auth.Purpose != "admin_session" || auth.UserID != u.ID || auth.TenantID != "acme" || auth.Revoked || auth.Consumed {
		t.Fatalf("auth = %+v, err %v", auth, err)
	}
	if _, err := s.GetAccessTokenByHash(ctx, "missing"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("missing token err = %v", err)
	}

	// Single-use agent-enroll consumption.
	if err := s.CreateAccessToken(ctx, storage.NewAccessToken{TokenHash: "etok", Purpose: "agent_enroll", UserID: u.ID, TenantID: "acme", ExpiresAt: future}); err != nil {
		t.Fatalf("create enroll token: %v", err)
	}
	if ok, err := s.ConsumeAgentEnrollToken(ctx, "etok"); err != nil || !ok {
		t.Fatalf("first consume = %v, %v; want true", ok, err)
	}
	if ok, err := s.ConsumeAgentEnrollToken(ctx, "etok"); err != nil || ok {
		t.Fatalf("replay consume = %v, %v; want false", ok, err)
	}
	// Purpose filter: a non-enroll token is never consumed here.
	if ok, err := s.ConsumeAgentEnrollToken(ctx, "atok"); err != nil || ok {
		t.Fatalf("consume admin token = %v, %v; want false", ok, err)
	}
}

func TestGetUserAndSum(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	u := seedUser(t, s, "acme", "a@acme.test")

	got, err := s.GetUser(ctx, u.ID)
	if err != nil || got.Email != "a@acme.test" || got.TenantID != "acme" {
		t.Fatalf("get user = %+v, err %v", got, err)
	}
	if _, err := s.GetUser(ctx, uuid.New()); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("missing user err = %v", err)
	}
	if sum, err := s.SumActiveAllocationBytes(ctx, u.ID); err != nil || sum != 0 {
		t.Fatalf("sum = %d, err %v; want 0", sum, err)
	}
}
