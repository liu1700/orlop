package sqlite

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
)

// newTestStore opens a fresh file-backed SQLite store in a temp dir (the schema
// is applied on Open) and closes it at test end.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(context.Background(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// seedUser creates a tenant + user and returns the user, the common fixture for
// the FK-bound stores.
func seedUser(t *testing.T, s *Store, tenant, email string) storage.User {
	t.Helper()
	ctx := context.Background()
	if err := s.CreateTenant(ctx, tenant, tenant); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	u, err := s.CreateUser(ctx, email, tenant)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	return u
}

func TestTenantsAndUsers(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if err := s.CreateTenant(ctx, "acme", "Acme Inc"); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	ten, err := s.GetTenant(ctx, "acme")
	if err != nil || ten.Name != "Acme Inc" || ten.Suspended {
		t.Fatalf("get tenant = %+v, err %v", ten, err)
	}
	if _, err := s.GetTenant(ctx, "missing"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("missing tenant err = %v, want ErrNotFound", err)
	}
	if err := s.CreateTenant(ctx, "acme", "dup"); !errors.Is(err, storage.ErrAlreadyExists) {
		t.Fatalf("dup tenant err = %v, want ErrAlreadyExists", err)
	}

	u, err := s.CreateUser(ctx, "a@acme.test", "acme")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if u.Role != "admin" || u.QuotaBytes != 10737418240 || u.Suspended || u.TenantID != "acme" {
		t.Fatalf("user defaults = %+v", u)
	}
	got, err := s.GetUserByEmail(ctx, "a@acme.test")
	if err != nil || got.ID != u.ID {
		t.Fatalf("get by email = %+v, err %v (want id %s)", got, err, u.ID)
	}
	if err := s.SuspendUser(ctx, u.ID); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	if got, _ := s.GetUserByEmail(ctx, "a@acme.test"); !got.Suspended {
		t.Fatalf("user not suspended after SuspendUser")
	}
	if _, err := s.CreateUser(ctx, "a@acme.test", "acme"); !errors.Is(err, storage.ErrAlreadyExists) {
		t.Fatalf("dup email err = %v, want ErrAlreadyExists", err)
	}
}

func TestServerPoolUpsert(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	got, err := s.RegisterServerPool(ctx, storage.ServerPool{
		DataAddr: "data:1", OpsAddr: "ops:1", TotalBytes: 1000, FreeBytes: 1000,
	})
	if err != nil || got.Status != "available" || got.FreeBytes != 1000 {
		t.Fatalf("register = %+v, err %v", got, err)
	}
	// Re-register the same data_addr: upsert updates ops/capacity/status.
	got, err = s.RegisterServerPool(ctx, storage.ServerPool{
		DataAddr: "data:1", OpsAddr: "ops:2", TotalBytes: 2000, FreeBytes: 1500, Status: "draining",
	})
	if err != nil || got.OpsAddr != "ops:2" || got.TotalBytes != 2000 || got.Status != "draining" {
		t.Fatalf("upsert = %+v, err %v", got, err)
	}
}

func TestCertRevocations(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	future := time.Now().Add(time.Hour)

	if err := s.AddCertRevocation(ctx, storage.CertRevocation{Serial: "AABB", TenantID: "acme", ExpiresAt: future, Reason: "test"}); err != nil {
		t.Fatalf("add: %v", err)
	}
	// Idempotent on the serial.
	if err := s.AddCertRevocation(ctx, storage.CertRevocation{Serial: "AABB", ExpiresAt: future}); err != nil {
		t.Fatalf("idempotent add: %v", err)
	}
	// An already-expired revocation is excluded from the active list.
	if err := s.AddCertRevocation(ctx, storage.CertRevocation{Serial: "DEAD", ExpiresAt: time.Now().Add(-time.Hour)}); err != nil {
		t.Fatalf("add expired: %v", err)
	}
	active, err := s.ListActiveCertRevocations(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(active) != 1 || active[0].Serial != "AABB" {
		t.Fatalf("active = %+v, want only AABB", active)
	}
	addrs, err := s.ListActiveServerOpsAddrs(ctx)
	if err != nil || len(addrs) != 0 {
		t.Fatalf("ops addrs = %v, err %v (want empty — no placements)", addrs, err)
	}
}

func TestAgentEnrollments(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	u := seedUser(t, s, "acme", "a@acme.test")
	future := time.Now().Add(time.Hour)

	if err := s.CreateAgentEnrollment(ctx, storage.NewAgentEnrollment{UserID: u.ID, CertSerial: "AABBCC", CertNotAfter: future}); err != nil {
		t.Fatalf("create enrollment: %v", err)
	}
	// Case-insensitive fingerprint match.
	e, err := s.GetActiveEnrollmentByFingerprint(ctx, "aabbcc")
	if err != nil || e.UserID != u.ID || e.CertSerial != "AABBCC" {
		t.Fatalf("get enrollment = %+v, err %v", e, err)
	}
	if _, err := s.GetActiveEnrollmentByFingerprint(ctx, "nope"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("missing fingerprint err = %v, want ErrNotFound", err)
	}
	// Expired enrollment is not "active".
	if err := s.CreateAgentEnrollment(ctx, storage.NewAgentEnrollment{UserID: u.ID, CertSerial: "EXPIRED", CertNotAfter: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatalf("create expired: %v", err)
	}
	if _, err := s.GetActiveEnrollmentByFingerprint(ctx, "expired"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expired fingerprint err = %v, want ErrNotFound", err)
	}
}

func TestAPITokens(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	u := seedUser(t, s, "acme", "a@acme.test")

	tok, err := s.CreateAPIToken(ctx, storage.NewAPIToken{UserID: u.ID, Name: "ci", TokenHash: "hash1", Prefix: "orlop_ci"})
	if err != nil || tok.ID == uuid.Nil || tok.Name != "ci" {
		t.Fatalf("create token = %+v, err %v", tok, err)
	}
	auth, err := s.GetAPITokenByHash(ctx, "hash1")
	if err != nil || auth.UserID != u.ID || auth.TenantID != "acme" || auth.Revoked {
		t.Fatalf("auth = %+v, err %v", auth, err)
	}
	byID, err := s.GetAPITokenByID(ctx, tok.ID)
	if err != nil || byID.UserID != u.ID || byID.LastUsedAt != nil {
		t.Fatalf("by id = %+v, err %v", byID, err)
	}
	list, err := s.ListAPITokensByUser(ctx, u.ID)
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %+v, err %v", list, err)
	}
	if err := s.TouchAPITokenLastUsed(ctx, tok.ID); err != nil {
		t.Fatalf("touch: %v", err)
	}
	if byID, _ := s.GetAPITokenByID(ctx, tok.ID); byID.LastUsedAt == nil {
		t.Fatalf("last_used not set after touch")
	}
	if err := s.RevokeAPIToken(ctx, tok.ID, u.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if list, _ := s.ListAPITokensByUser(ctx, u.ID); len(list) != 0 {
		t.Fatalf("revoked token still listed: %+v", list)
	}
	if auth, _ := s.GetAPITokenByHash(ctx, "hash1"); !auth.Revoked {
		t.Fatalf("token not marked revoked")
	}
}
