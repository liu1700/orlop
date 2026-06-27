package sqlite

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
)

func TestDeviceAuthApproveAndDeny(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	u := seedUser(t, s, "acme", "a@acme.test")
	future := time.Now().Add(time.Hour)

	mkPending := func(dh, uh string) storage.DeviceAuthorization {
		if err := s.CreateDeviceAuthorization(ctx, storage.NewDeviceAuthorization{DeviceCodeHash: dh, UserCodeHash: uh, ExpiresAt: future}); err != nil {
			t.Fatalf("create device auth: %v", err)
		}
		da, err := s.GetDeviceAuthorizationByDeviceCodeHash(ctx, dh)
		if err != nil || da.Status != "pending" {
			t.Fatalf("get device auth = %+v, err %v", da, err)
		}
		return da
	}

	// Approve: conditional on pending; a second approve loses with ErrNotFound.
	da := mkPending("dh1", "uh1")
	res := storage.ResolveDeviceAuthorization{ID: da.ID, TenantID: "acme", UserID: u.ID}
	if err := s.ApproveDeviceAuthorization(ctx, res); err != nil {
		t.Fatalf("approve: %v", err)
	}
	got, _ := s.GetDeviceAuthorizationByUserCodeHash(ctx, "uh1")
	if got.Status != "approved" || got.UserID == nil || *got.UserID != u.ID || got.TenantID != "acme" {
		t.Fatalf("approved row = %+v", got)
	}
	if err := s.ApproveDeviceAuthorization(ctx, res); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("re-approve err = %v, want ErrNotFound", err)
	}

	// Deny: same conditional semantics.
	da2 := mkPending("dh2", "uh2")
	res2 := storage.ResolveDeviceAuthorization{ID: da2.ID, TenantID: "acme", UserID: u.ID}
	if err := s.DenyDeviceAuthorization(ctx, res2); err != nil {
		t.Fatalf("deny: %v", err)
	}
	if got, _ := s.GetDeviceAuthorizationByDeviceCodeHash(ctx, "dh2"); got.Status != "denied" {
		t.Fatalf("denied status = %q", got.Status)
	}
	if err := s.DenyDeviceAuthorization(ctx, res2); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("re-deny err = %v, want ErrNotFound", err)
	}
}

func TestDeviceAuthExpireAndPoll(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	future := time.Now().Add(time.Hour)

	if err := s.CreateDeviceAuthorization(ctx, storage.NewDeviceAuthorization{DeviceCodeHash: "dh", UserCodeHash: "uh", ExpiresAt: future}); err != nil {
		t.Fatalf("create: %v", err)
	}
	da, _ := s.GetDeviceAuthorizationByDeviceCodeHash(ctx, "dh")

	when := time.Now().Add(-time.Minute)
	if err := s.TouchDeviceAuthorizationPoll(ctx, da.ID, when); err != nil {
		t.Fatalf("touch: %v", err)
	}
	if got, _ := s.GetDeviceAuthorizationByDeviceCodeHash(ctx, "dh"); got.LastPolledAt == nil {
		t.Fatalf("last_polled_at not set")
	}

	// MarkExpired is conditional on pending but :exec — repeats and misses are no-ops.
	if err := s.MarkDeviceAuthorizationExpired(ctx, da.ID); err != nil {
		t.Fatalf("expire: %v", err)
	}
	if got, _ := s.GetDeviceAuthorizationByDeviceCodeHash(ctx, "dh"); got.Status != "expired" {
		t.Fatalf("status = %q, want expired", got.Status)
	}
	if err := s.MarkDeviceAuthorizationExpired(ctx, da.ID); err != nil {
		t.Fatalf("re-expire (now non-pending) should be a no-op: %v", err)
	}
	if err := s.MarkDeviceAuthorizationExpired(ctx, uuid.New()); err != nil {
		t.Fatalf("expire missing should be a no-op: %v", err)
	}
}

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

func TestRefreshTokens(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	u := seedUser(t, s, "acme", "a@acme.test")
	family := uuid.New()
	future := time.Now().Add(time.Hour)

	if err := s.CreateRefreshToken(ctx, storage.NewRefreshToken{TokenHash: "rt1", FamilyID: family, UserID: u.ID, TenantID: "acme", ExpiresAt: future}); err != nil {
		t.Fatalf("create: %v", err)
	}
	rt, err := s.GetRefreshTokenByHash(ctx, "rt1")
	if err != nil || rt.FamilyID != family || rt.Revoked || rt.Rotated {
		t.Fatalf("rt = %+v, err %v", rt, err)
	}
	if err := s.MarkRefreshTokenRotated(ctx, rt.ID); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if got, _ := s.GetRefreshTokenByHash(ctx, "rt1"); !got.Rotated {
		t.Fatalf("not rotated")
	}
	if err := s.RevokeRefreshTokenFamily(ctx, family); err != nil {
		t.Fatalf("revoke family: %v", err)
	}
	if got, _ := s.GetRefreshTokenByHash(ctx, "rt1"); !got.Revoked {
		t.Fatalf("not revoked after family revoke")
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
