package ca

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/secrets"
)

func newTestCA(t *testing.T) (*CA, secrets.Backend) {
	t.Helper()
	backend := secrets.NewMemory()
	c, err := LoadOrInit(context.Background(), backend, Env{
		TrustDomain: "test.example",
		OrgName:     "Test",
	})
	if err != nil {
		t.Fatal(err)
	}
	return c, backend
}

func parseAllCertsPEM(t *testing.T, b []byte) []*x509.Certificate {
	t.Helper()
	var certs []*x509.Certificate
	for {
		block, rest := pem.Decode(b)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			t.Fatalf("unexpected PEM type %q", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		certs = append(certs, cert)
		b = rest
	}
	return certs
}

func TestMintAgentCertVerifiesAgainstChain(t *testing.T) {
	ctx := context.Background()
	c, _ := newTestCA(t)
	if err := c.BootstrapTenant(ctx, "acme"); err != nil {
		t.Fatal(err)
	}

	certPEM, _, chainPEM, serial, err := c.MintAgentCert("acme", "alice@example.com", "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if serial == "" {
		t.Fatal("serial empty")
	}

	chain := parseAllCertsPEM(t, chainPEM)
	if len(chain) != 2 {
		t.Fatalf("chain len = %d, want 2 (intermediate + root)", len(chain))
	}
	leafs := parseAllCertsPEM(t, certPEM)
	if len(leafs) != 1 {
		t.Fatalf("leaf parse len = %d, want 1", len(leafs))
	}
	leaf := leafs[0]

	roots := x509.NewCertPool()
	roots.AddCert(chain[1])
	intermediates := x509.NewCertPool()
	intermediates.AddCert(chain[0])

	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("verify against chain: %v", err)
	}

	if got := leaf.Subject.CommonName; got != "alice@example.com" {
		t.Fatalf("CN = %q, want %q", got, "alice@example.com")
	}
	if len(leaf.URIs) != 1 {
		t.Fatalf("URIs = %v, want 1 entry", leaf.URIs)
	}
	if got, want := leaf.URIs[0].String(), "spiffe://test.example/tenant/acme"; got != want {
		t.Fatalf("URI SAN = %q, want %q", got, want)
	}
}

// TestIntermediateCarriesTrustDomainConstraint covers issue #7: tenant
// intermediates are constrained to the deployment trust domain, and a leaf
// minted under the constrained intermediate must still verify against the root
// (i.e. the constraint does not break the legitimate chain).
func TestIntermediateCarriesTrustDomainConstraint(t *testing.T) {
	ctx := context.Background()
	c, _ := newTestCA(t)
	if err := c.BootstrapTenant(ctx, "acme"); err != nil {
		t.Fatal(err)
	}

	certPEM, _, chainPEM, _, err := c.MintAgentCert("acme", "alice@example.com", "agent-1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	chain := parseAllCertsPEM(t, chainPEM)
	if len(chain) != 2 {
		t.Fatalf("chain len = %d, want 2", len(chain))
	}
	intermediate := chain[0]

	// The intermediate constrains issuance to the trust-domain host.
	if got := intermediate.PermittedURIDomains; len(got) != 1 || got[0] != "test.example" {
		t.Fatalf("intermediate PermittedURIDomains = %v, want [test.example]", got)
	}

	// The legitimate leaf (SANs under spiffe://test.example/...) still verifies
	// against the root through the constrained intermediate — exactly the path
	// validation orlop-server runs at handshake.
	leaf := parseAllCertsPEM(t, certPEM)[0]
	roots := x509.NewCertPool()
	roots.AddCert(chain[1])
	intermediates := x509.NewCertPool()
	intermediates.AddCert(intermediate)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("constrained chain must still verify: %v", err)
	}
}

// TestBootstrapTenantAllowlist covers issue #8: BootstrapTenant refuses a
// tenant the Env.AllowBootstrap predicate rejects, and an idempotent re-bootstrap
// of an already-loaded tenant is unaffected by the gate.
func TestBootstrapTenantAllowlist(t *testing.T) {
	ctx := context.Background()
	backend := secrets.NewMemory()
	c, err := LoadOrInit(ctx, backend, Env{
		TrustDomain: "test.example",
		OrgName:     "Test",
		AllowBootstrap: func(tenantID string) bool {
			return tenantID == "allowed"
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := c.BootstrapTenant(ctx, "denied"); !errors.Is(err, ErrTenantNotAllowed) {
		t.Fatalf("BootstrapTenant(denied) error = %v, want ErrTenantNotAllowed", err)
	}
	if c.HasTenant("denied") {
		t.Fatal("denied tenant must not be created")
	}

	if err := c.BootstrapTenant(ctx, "allowed"); err != nil {
		t.Fatalf("BootstrapTenant(allowed) = %v, want nil", err)
	}
	// Idempotent re-bootstrap of an already-loaded tenant is allowed even if the
	// predicate would now reject it (the gate only blocks creating NEW material).
	if err := c.BootstrapTenant(ctx, "allowed"); err != nil {
		t.Fatalf("idempotent re-bootstrap = %v, want nil", err)
	}
}

// TestBootstrapTenantNilPredicateAllowsAll confirms the operator-CLI path (no
// predicate) bootstraps any tenant id.
func TestBootstrapTenantNilPredicateAllowsAll(t *testing.T) {
	ctx := context.Background()
	c, _ := newTestCA(t) // newTestCA sets no AllowBootstrap
	if err := c.BootstrapTenant(ctx, "any-operator-tenant"); err != nil {
		t.Fatalf("nil predicate must allow all: %v", err)
	}
}

func TestMintAgentCertEncodesAgentSAN(t *testing.T) {
	ctx := context.Background()
	c, _ := newTestCA(t)
	if err := c.BootstrapTenant(ctx, "acme"); err != nil {
		t.Fatal(err)
	}

	// With an agent id the leaf carries BOTH the tenant SAN and an
	// /agent/<id> SAN so orlop-server can authorize per-agent (Phase 3).
	certPEM, _, _, _, err := c.MintAgentCert("acme", "alice@example.com", "agent-123", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf := parseAllCertsPEM(t, certPEM)[0]
	got := make([]string, 0, len(leaf.URIs))
	for _, u := range leaf.URIs {
		got = append(got, u.String())
	}
	want := []string{
		"spiffe://test.example/tenant/acme",
		"spiffe://test.example/agent/agent-123",
	}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("URI SANs = %v, want %v", got, want)
	}

	// Empty agent id stays tenant-only — backward compatible with anonymous
	// sessions and pre-agent enrolls.
	certPEM2, _, _, _, err := c.MintAgentCert("acme", "alice@example.com", "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf2 := parseAllCertsPEM(t, certPEM2)[0]
	if len(leaf2.URIs) != 1 || leaf2.URIs[0].String() != "spiffe://test.example/tenant/acme" {
		t.Fatalf("tenant-only URIs = %v, want 1 tenant SAN", leaf2.URIs)
	}
}

func TestCrossTenantCertDoesNotVerify(t *testing.T) {
	// Acceptance criterion: a cert minted by tenant-A's intermediate
	// must NOT verify against tenant-B's intermediate, even though both
	// chain up to the same org root. This mirrors the server-side check
	// where each tenant VM only trusts its own intermediate.
	ctx := context.Background()
	c, _ := newTestCA(t)
	for _, id := range []string{"alpha", "beta"} {
		if err := c.BootstrapTenant(ctx, id); err != nil {
			t.Fatal(err)
		}
	}

	certPEM, _, _, _, err := c.MintAgentCert("alpha", "user-1", "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf := parseAllCertsPEM(t, certPEM)[0]

	betaChain, ok := c.TenantChainPEM("beta")
	if !ok {
		t.Fatal("expected beta chain")
	}
	betaCerts := parseAllCertsPEM(t, betaChain)

	// Server-side trust pool for tenant beta: only beta's intermediate.
	// (Equivalent to tls.Config.ClientCAs on tenant beta's orlop-server.)
	betaTrust := x509.NewCertPool()
	betaTrust.AddCert(betaCerts[0])

	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     betaTrust,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err == nil {
		t.Fatal("alpha-issued cert verified against beta intermediate; cross-tenant isolation broken")
	}
}

func TestMintAgentCertTTLAndClockSkew(t *testing.T) {
	ctx := context.Background()
	fixed := time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)
	backend := secrets.NewMemory()
	c, err := LoadOrInit(ctx, backend, Env{
		TrustDomain: "test.example",
		OrgName:     "Test",
		Now:         func() time.Time { return fixed },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.BootstrapTenant(ctx, "acme"); err != nil {
		t.Fatal(err)
	}

	ttl := 90 * time.Minute
	certPEM, _, _, _, err := c.MintAgentCert("acme", "user-1", "", ttl)
	if err != nil {
		t.Fatal(err)
	}
	leaf := parseAllCertsPEM(t, certPEM)[0]

	if !leaf.NotAfter.Equal(fixed.Add(ttl)) {
		t.Fatalf("NotAfter = %s, want %s (now+ttl)", leaf.NotAfter, fixed.Add(ttl))
	}
	if !leaf.NotBefore.Equal(fixed.Add(-ClockSkew)) {
		t.Fatalf("NotBefore = %s, want %s (now-skew)", leaf.NotBefore, fixed.Add(-ClockSkew))
	}
}

func TestLoadOrInitIdempotent(t *testing.T) {
	ctx := context.Background()
	backend := secrets.NewMemory()
	env := Env{TrustDomain: "test.example", OrgName: "Test"}

	c1, err := LoadOrInit(ctx, backend, env)
	if err != nil {
		t.Fatal(err)
	}
	if err := c1.BootstrapTenant(ctx, "acme"); err != nil {
		t.Fatal(err)
	}
	root1 := c1.RootPEM()
	chain1, _ := c1.TenantChainPEM("acme")

	c2, err := LoadOrInit(ctx, backend, env)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c2.RootPEM(), root1) {
		t.Fatal("root cert changed across LoadOrInit calls")
	}
	chain2, ok := c2.TenantChainPEM("acme")
	if !ok {
		t.Fatal("tenant intermediate lost on reload")
	}
	if !bytes.Equal(chain1, chain2) {
		t.Fatal("intermediate cert changed across reloads")
	}

	// Second BootstrapTenant must be a no-op.
	if err := c2.BootstrapTenant(ctx, "acme"); err != nil {
		t.Fatal(err)
	}
	chain3, _ := c2.TenantChainPEM("acme")
	if !bytes.Equal(chain1, chain3) {
		t.Fatal("BootstrapTenant on existing tenant rotated the cert")
	}
}

func TestLoadOrInitWithoutRootKey(t *testing.T) {
	// Server-side load: only the root cert and the tenant intermediate
	// (cert+key) are present. This must succeed and Mint must work, but
	// BootstrapTenant must refuse.
	ctx := context.Background()
	bootstrap := secrets.NewMemory()
	env := Env{TrustDomain: "test.example", OrgName: "Test"}
	full, err := LoadOrInit(ctx, bootstrap, env)
	if err != nil {
		t.Fatal(err)
	}
	if err := full.BootstrapTenant(ctx, "acme"); err != nil {
		t.Fatal(err)
	}

	// Build a "server view" backend: copy the root cert and tenant
	// data, but withhold the root key.
	server := secrets.NewMemory()
	for _, k := range []string{
		rootCertKey,
		tenantCertKey("acme"),
		tenantKeyKey("acme"),
	} {
		v, ok, err := bootstrap.Get(ctx, k)
		if err != nil || !ok {
			t.Fatalf("source missing %q", k)
		}
		if err := server.Put(ctx, k, v); err != nil {
			t.Fatal(err)
		}
	}

	srv, err := LoadOrInit(ctx, server, env)
	if err != nil {
		t.Fatalf("server load: %v", err)
	}
	if srv.HasRootKey() {
		t.Fatal("server should not hold root key")
	}
	if !srv.HasTenant("acme") {
		t.Fatal("server lost tenant intermediate")
	}
	if _, _, _, _, err := srv.MintAgentCert("acme", "user-1", "", time.Hour); err != nil {
		t.Fatalf("mint without root key should still work: %v", err)
	}
	err = srv.BootstrapTenant(ctx, "new-tenant")
	if err == nil || !strings.Contains(err.Error(), "root key") {
		t.Fatalf("BootstrapTenant without root key: err=%v, want 'root key' error", err)
	}
}

func TestMintAgentCertUnknownTenant(t *testing.T) {
	c, _ := newTestCA(t)
	_, _, _, _, err := c.MintAgentCert("ghost", "u", "", time.Hour)
	if err == nil || !strings.Contains(err.Error(), "unknown tenant") {
		t.Fatalf("err = %v, want unknown tenant", err)
	}
}

func TestMintAgentCertRejectsBadInputs(t *testing.T) {
	ctx := context.Background()
	c, _ := newTestCA(t)
	if err := c.BootstrapTenant(ctx, "acme"); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		tenant string
		ttl    time.Duration
	}{
		{"empty tenant", "", time.Hour},
		{"zero ttl", "acme", 0},
		{"negative ttl", "acme", -time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, _, _, err := c.MintAgentCert(tc.tenant, "u", "", tc.ttl); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestMintServerCertVerifiesAsServerAuth(t *testing.T) {
	ctx := context.Background()
	c, _ := newTestCA(t)
	if err := c.BootstrapTenant(ctx, "acme"); err != nil {
		t.Fatal(err)
	}

	const fqdn = "tenant-acme.example.test"
	certPEM, _, chainPEM, serial, err := c.MintServerCert("acme", fqdn, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if serial == "" {
		t.Fatal("serial empty")
	}

	chain := parseAllCertsPEM(t, chainPEM)
	if len(chain) != 2 {
		t.Fatalf("chain len = %d, want 2 (intermediate + root)", len(chain))
	}
	leafs := parseAllCertsPEM(t, certPEM)
	if len(leafs) != 1 {
		t.Fatalf("leaf parse len = %d, want 1", len(leafs))
	}
	leaf := leafs[0]

	roots := x509.NewCertPool()
	roots.AddCert(chain[1])
	intermediates := x509.NewCertPool()
	intermediates.AddCert(chain[0])

	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSName:       fqdn,
	}); err != nil {
		t.Fatalf("verify against chain: %v", err)
	}

	if got := leaf.Subject.CommonName; got != fqdn {
		t.Fatalf("CN = %q, want %q", got, fqdn)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != fqdn {
		t.Fatalf("DNSNames = %v, want [%q]", leaf.DNSNames, fqdn)
	}
	if len(leaf.URIs) != 0 {
		t.Fatalf("URIs = %v, want none on a server cert", leaf.URIs)
	}
}

func TestMintServerCertHostnameMismatch(t *testing.T) {
	ctx := context.Background()
	c, _ := newTestCA(t)
	if err := c.BootstrapTenant(ctx, "acme"); err != nil {
		t.Fatal(err)
	}
	certPEM, _, chainPEM, _, err := c.MintServerCert("acme", "tenant-acme.example.test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	chain := parseAllCertsPEM(t, chainPEM)
	leaf := parseAllCertsPEM(t, certPEM)[0]

	roots := x509.NewCertPool()
	roots.AddCert(chain[1])
	intermediates := x509.NewCertPool()
	intermediates.AddCert(chain[0])

	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSName:       "wrong.example.test",
	})
	if err == nil {
		t.Fatal("expected hostname mismatch error")
	}
	var hostErr x509.HostnameError
	if !errors.As(err, &hostErr) {
		t.Fatalf("err = %v (%T), want x509.HostnameError", err, err)
	}
}

func TestMintServerCertUnknownTenant(t *testing.T) {
	c, _ := newTestCA(t)
	_, _, _, _, err := c.MintServerCert("ghost", "tenant-ghost.example.test", time.Hour)
	if err == nil || !strings.Contains(err.Error(), "unknown tenant") {
		t.Fatalf("err = %v, want unknown tenant", err)
	}
}

func TestMintServerCertRejectsBadInputs(t *testing.T) {
	ctx := context.Background()
	c, _ := newTestCA(t)
	if err := c.BootstrapTenant(ctx, "acme"); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		tenant string
		fqdn   string
		ttl    time.Duration
	}{
		{"empty tenant", "", "host.example.test", time.Hour},
		{"empty fqdn", "acme", "", time.Hour},
		{"zero ttl", "acme", "host.example.test", 0},
		{"negative ttl", "acme", "host.example.test", -time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, _, _, err := c.MintServerCert(tc.tenant, tc.fqdn, tc.ttl); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestRootCAIsSelfSigned(t *testing.T) {
	c, _ := newTestCA(t)
	roots := parseAllCertsPEM(t, c.RootPEM())
	if len(roots) != 1 {
		t.Fatalf("RootPEM len=%d", len(roots))
	}
	root := roots[0]
	if !root.IsCA {
		t.Fatal("root must have IsCA=true")
	}
	if err := root.CheckSignatureFrom(root); err != nil {
		t.Fatalf("root self-sig: %v", err)
	}
}

func TestMintControlPlaneCertHasSpiffeURIControl(t *testing.T) {
	c, _ := newTestCA(t)
	certPEM, _, _, err := c.MintControlPlaneCert(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf := parseAllCertsPEM(t, certPEM)[0]
	if len(leaf.URIs) != 1 {
		t.Fatalf("URIs = %v, want 1 entry", leaf.URIs)
	}
	want := "spiffe://test.example/control"
	if got := leaf.URIs[0].String(); got != want {
		t.Fatalf("URI SAN = %q, want %q", got, want)
	}
	if got := leaf.Subject.CommonName; got != "orlop-control" {
		t.Fatalf("CN = %q, want %q", got, "orlop-control")
	}
}

func TestMintControlPlaneCertVerifiesAgainstRoot(t *testing.T) {
	c, _ := newTestCA(t)
	certPEM, _, serial, err := c.MintControlPlaneCert(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if serial == "" {
		t.Fatal("serial empty")
	}
	leaf := parseAllCertsPEM(t, certPEM)[0]

	rootPool := x509.NewCertPool()
	rootPool.AddCert(parseAllCertsPEM(t, c.RootPEM())[0])

	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     rootPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("verify against root: %v", err)
	}
}

func TestMintControlPlaneCertWithoutRootKey(t *testing.T) {
	// Reproduce the server-side case where only the root cert (no key) is loaded.
	ctx := context.Background()
	bootstrap := secrets.NewMemory()
	full, err := LoadOrInit(ctx, bootstrap, Env{TrustDomain: "test.example", OrgName: "Test"})
	if err != nil {
		t.Fatal(err)
	}
	if err := full.BootstrapTenant(ctx, "acme"); err != nil {
		t.Fatal(err)
	}

	server := secrets.NewMemory()
	for _, k := range []string{
		rootCertKey,
		tenantCertKey("acme"),
		tenantKeyKey("acme"),
	} {
		v, ok, err := bootstrap.Get(ctx, k)
		if err != nil || !ok {
			t.Fatalf("source missing %q", k)
		}
		if err := server.Put(ctx, k, v); err != nil {
			t.Fatal(err)
		}
	}

	srv, err := LoadOrInit(ctx, server, Env{TrustDomain: "test.example", OrgName: "Test"})
	if err != nil {
		t.Fatalf("server load: %v", err)
	}
	_, _, _, err = srv.MintControlPlaneCert(time.Hour)
	if err == nil || !strings.Contains(err.Error(), "root key") {
		t.Fatalf("expected root key error, got %v", err)
	}
}

// makeServerCSR builds an ed25519 keypair and a CSR for fqdn, returning the
// CSR DER and the generated public key (for the public-key-match assertion).
func makeServerCSR(t *testing.T, fqdn string) (csrDER []byte, pub ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: fqdn},
		DNSNames: []string{fqdn},
	}
	csrDER, err = x509.CreateCertificateRequest(rand.Reader, tmpl, priv)
	if err != nil {
		t.Fatal(err)
	}
	return csrDER, pub
}

func TestSignServerCSR(t *testing.T) {
	c, _ := newTestCA(t)
	const fqdn = "orlop-server"
	csrDER, pub := makeServerCSR(t, fqdn)

	certPEM, serial, err := c.SignServerCSR(csrDER, fqdn, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if serial == "" {
		t.Fatal("serial empty")
	}

	leafs := parseAllCertsPEM(t, certPEM)
	if len(leafs) != 1 {
		t.Fatalf("leaf parse len = %d, want 1", len(leafs))
	}
	leaf := leafs[0]

	if got := leaf.Subject.CommonName; got != fqdn {
		t.Fatalf("CN = %q, want %q", got, fqdn)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != fqdn {
		t.Fatalf("DNSNames = %v, want [%q]", leaf.DNSNames, fqdn)
	}
	// The server keeps its private key; the signed cert must carry the CSR's
	// public key, NOT a CA-generated one.
	leafPub, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("leaf public key type = %T, want ed25519.PublicKey", leaf.PublicKey)
	}
	if !leafPub.Equal(pub) {
		t.Fatal("leaf public key does not match the CSR public key")
	}

	// Server-auth EKU and chains to the org root — every tenant's agent trusts
	// the root via the chain it gets at /agent/enroll, so this one cert works
	// for all of them.
	rootPool := x509.NewCertPool()
	rootPool.AddCert(parseAllCertsPEM(t, c.RootPEM())[0])
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     rootPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSName:   fqdn,
	}); err != nil {
		t.Fatalf("verify against root as server-auth: %v", err)
	}
}

func TestSignServerCSRRejectsBadInputs(t *testing.T) {
	c, _ := newTestCA(t)
	goodCSR, _ := makeServerCSR(t, "orlop-server")

	t.Run("empty fqdn", func(t *testing.T) {
		if _, _, err := c.SignServerCSR(goodCSR, "", time.Hour); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("zero ttl", func(t *testing.T) {
		if _, _, err := c.SignServerCSR(goodCSR, "orlop-server", 0); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("garbage csr", func(t *testing.T) {
		if _, _, err := c.SignServerCSR([]byte("not a csr"), "orlop-server", time.Hour); err == nil {
			t.Fatal("expected parse error")
		}
	})
	t.Run("tampered csr signature", func(t *testing.T) {
		tampered := append([]byte(nil), goodCSR...)
		tampered[len(tampered)-1] ^= 0xff // corrupt the signature bytes
		if _, _, err := c.SignServerCSR(tampered, "orlop-server", time.Hour); err == nil {
			t.Fatal("expected signature verification error")
		}
	})
}

func TestSignServerCSRWithoutRootKey(t *testing.T) {
	// Server-side load (root cert, no root key): signing must refuse, because
	// the control plane that fronts SignServerCSR is the only holder of the key.
	ctx := context.Background()
	bootstrap := secrets.NewMemory()
	full, err := LoadOrInit(ctx, bootstrap, Env{TrustDomain: "test.example", OrgName: "Test"})
	if err != nil {
		t.Fatal(err)
	}

	server := secrets.NewMemory()
	v, ok, err := bootstrap.Get(ctx, rootCertKey)
	if err != nil || !ok {
		t.Fatalf("source missing %q", rootCertKey)
	}
	if err := server.Put(ctx, rootCertKey, v); err != nil {
		t.Fatal(err)
	}
	_ = full

	srv, err := LoadOrInit(ctx, server, Env{TrustDomain: "test.example", OrgName: "Test"})
	if err != nil {
		t.Fatalf("server load: %v", err)
	}
	csrDER, _ := makeServerCSR(t, "orlop-server")
	if _, _, err := srv.SignServerCSR(csrDER, "orlop-server", time.Hour); err == nil || !strings.Contains(err.Error(), "root key") {
		t.Fatalf("expected root key error, got %v", err)
	}
}
