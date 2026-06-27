// Package ca implements the per-tenant private CA used by orlop-control
// to mint short-lived agent client certs for mTLS authentication against
// orlop-server. See docs/design-auth.md for the architecture and
// docs/control-plane-runbook.md for the operator workflow.
//
// Trust hierarchy:
//
//	org root (10y, ed25519)        ← bootstrapped offline; key never on the server VM
//	  └── tenant intermediate (1y) ← one per tenant; lives in the control-plane secret store
//	        └── agent leaf (1h)    ← minted on every /agent/enroll
//
// Tenant identity is encoded as a SPIFFE URI SAN
// (`spiffe://<trust-domain>/tenant/<id>`); the userID is recorded in the
// Subject CommonName for audit display.
package ca

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/secrets"
)

// ClockSkew is the leeway granted to NotBefore so agents whose local
// clocks lag the control plane by up to ClockSkew can still present a
// freshly-minted cert without TLS handshake failures.
const ClockSkew = 5 * time.Minute

// Default validity periods for the long-lived CA certs. Agent leaf TTLs
// are passed in by the caller of MintAgentCert.
const (
	DefaultRootValidity         = 10 * 365 * 24 * time.Hour
	DefaultIntermediateValidity = 365 * 24 * time.Hour
)

// Secret store key layout. Forward-slash separators; the Filesystem
// backend translates these to native paths.
const (
	rootCertKey  = "ca/root/cert.pem"
	rootKeyKey   = "ca/root/key.pem"
	tenantPrefix = "ca/tenant/"
)

// ErrTenantNotAllowed is returned by BootstrapTenant when Env.AllowBootstrap
// rejects the tenant id — the operator allowlist gate (issue #8).
var ErrTenantNotAllowed = errors.New("ca: tenant not allowed for bootstrap")

// Env carries CA-wide configuration. Now and Rand are injectable for
// deterministic tests; both fall back to the standard sources.
type Env struct {
	TrustDomain string
	OrgName     string
	Now         func() time.Time
	Rand        io.Reader
	// AllowBootstrap, when non-nil, gates BootstrapTenant: it must return true
	// for a tenant id before any new intermediate is minted for it (issue #8).
	// A nil predicate allows all bootstraps — used by the operator CLI
	// (`orlop-control ca init`), where the tenant id is operator-chosen, not
	// claim-derived. The runtime control plane supplies a predicate so a
	// verified-but-attacker-influenced tenant claim cannot self-onboard.
	AllowBootstrap func(tenantID string) bool
}

func (e Env) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now().UTC()
}

func (e Env) randR() io.Reader {
	if e.Rand != nil {
		return e.Rand
	}
	return rand.Reader
}

type tenantCA struct {
	cert     *x509.Certificate
	key      ed25519.PrivateKey
	chainPEM []byte // intermediate || root
}

// CA is a loaded, ready-to-use private CA. Safe for concurrent use.
type CA struct {
	env     Env
	backend secrets.Backend

	mu       sync.RWMutex
	rootCert *x509.Certificate
	rootKey  ed25519.PrivateKey // may be nil on hosts that hold only the root cert
	rootPEM  []byte
	tenants  map[string]*tenantCA
}

// LoadOrInit reads the org root and any tenant intermediates from
// backend. If the org root is absent it is generated and persisted (the
// "init" half). Loading a backend that has the root cert but not the
// root key (the prod server VM case) succeeds; BootstrapTenant will
// then refuse because intermediate signing requires the root key.
func LoadOrInit(ctx context.Context, backend secrets.Backend, env Env) (*CA, error) {
	if env.TrustDomain == "" {
		return nil, errors.New("ca: Env.TrustDomain is required")
	}
	if env.OrgName == "" {
		env.OrgName = "ORL"
	}
	c := &CA{env: env, backend: backend, tenants: map[string]*tenantCA{}}
	if err := c.loadOrBootstrapRoot(ctx); err != nil {
		return nil, err
	}
	if err := c.loadTenants(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *CA) loadOrBootstrapRoot(ctx context.Context) error {
	certPEM, hasCert, err := c.backend.Get(ctx, rootCertKey)
	if err != nil {
		return fmt.Errorf("read root cert: %w", err)
	}
	keyPEM, hasKey, err := c.backend.Get(ctx, rootKeyKey)
	if err != nil {
		return fmt.Errorf("read root key: %w", err)
	}

	if !hasCert {
		cert, key, err := c.generateRoot()
		if err != nil {
			return err
		}
		certPEM = encodeCertPEM(cert)
		keyPEM, err = encodeEd25519KeyPEM(key)
		if err != nil {
			return err
		}
		if err := c.backend.Put(ctx, rootCertKey, certPEM); err != nil {
			return fmt.Errorf("write root cert: %w", err)
		}
		if err := c.backend.Put(ctx, rootKeyKey, keyPEM); err != nil {
			return fmt.Errorf("write root key: %w", err)
		}
		c.rootCert = cert
		c.rootKey = key
		c.rootPEM = certPEM
		return nil
	}

	cert, err := DecodeCertPEM(certPEM)
	if err != nil {
		return fmt.Errorf("parse root cert: %w", err)
	}
	c.rootCert = cert
	c.rootPEM = certPEM
	if hasKey {
		key, err := decodeEd25519KeyPEM(keyPEM)
		if err != nil {
			return fmt.Errorf("parse root key: %w", err)
		}
		c.rootKey = key
	}
	return nil
}

func (c *CA) loadTenants(ctx context.Context) error {
	keys, err := c.backend.List(ctx, tenantPrefix)
	if err != nil {
		return fmt.Errorf("list tenants: %w", err)
	}
	seen := map[string]struct{}{}
	for _, k := range keys {
		rest := strings.TrimPrefix(k, tenantPrefix)
		slash := strings.IndexByte(rest, '/')
		if slash <= 0 {
			continue
		}
		id := rest[:slash]
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		if err := c.loadTenant(ctx, id); err != nil {
			return fmt.Errorf("load tenant %q: %w", id, err)
		}
	}
	return nil
}

func (c *CA) loadTenant(ctx context.Context, id string) error {
	certPEM, hasCert, err := c.backend.Get(ctx, tenantCertKey(id))
	if err != nil {
		return err
	}
	if !hasCert {
		return errors.New("intermediate cert missing")
	}
	keyPEM, hasKey, err := c.backend.Get(ctx, tenantKeyKey(id))
	if err != nil {
		return err
	}
	if !hasKey {
		return errors.New("intermediate key missing")
	}
	cert, err := DecodeCertPEM(certPEM)
	if err != nil {
		return fmt.Errorf("parse cert: %w", err)
	}
	key, err := decodeEd25519KeyPEM(keyPEM)
	if err != nil {
		return fmt.Errorf("parse key: %w", err)
	}
	chain := make([]byte, 0, len(certPEM)+len(c.rootPEM))
	chain = append(chain, certPEM...)
	chain = append(chain, c.rootPEM...)
	c.tenants[id] = &tenantCA{cert: cert, key: key, chainPEM: chain}
	return nil
}

// BootstrapTenant generates a new intermediate for tenantID and persists
// it to the backend. Idempotent — if an intermediate already exists for
// tenantID it is left untouched and nil is returned. Requires the root
// key to be loaded (i.e. the operator workflow, not the server boot
// path).
func (c *CA) BootstrapTenant(ctx context.Context, tenantID string) error {
	if tenantID == "" {
		return errors.New("ca: tenantID is required")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.tenants[tenantID]; ok {
		return nil
	}
	// Operator allowlist gate (issue #8): refuse to mint CA material for a
	// tenant the operator has not permitted. Checked after the idempotent
	// "already loaded" return so an already-provisioned tenant is never broken;
	// it only blocks creating a NEW intermediate for an unrecognized tenant.
	if c.env.AllowBootstrap != nil && !c.env.AllowBootstrap(tenantID) {
		return fmt.Errorf("%w: %q", ErrTenantNotAllowed, tenantID)
	}
	if c.rootKey == nil {
		return errors.New("ca: root key not loaded; cannot sign tenant intermediate")
	}
	cert, key, err := c.generateIntermediate(tenantID)
	if err != nil {
		return err
	}
	certPEM := encodeCertPEM(cert)
	keyPEM, err := encodeEd25519KeyPEM(key)
	if err != nil {
		return err
	}
	if err := c.backend.Put(ctx, tenantCertKey(tenantID), certPEM); err != nil {
		return fmt.Errorf("write intermediate cert: %w", err)
	}
	if err := c.backend.Put(ctx, tenantKeyKey(tenantID), keyPEM); err != nil {
		return fmt.Errorf("write intermediate key: %w", err)
	}
	chain := make([]byte, 0, len(certPEM)+len(c.rootPEM))
	chain = append(chain, certPEM...)
	chain = append(chain, c.rootPEM...)
	c.tenants[tenantID] = &tenantCA{cert: cert, key: key, chainPEM: chain}
	return nil
}

// signer is the parent (issuer) of a leaf cert: either a tenant intermediate
// (agent + server certs) or the org root (control-plane cert).
type signer struct {
	cert *x509.Certificate
	key  ed25519.PrivateKey
}

// signLeaf generates an ed25519 leaf key, fills in SerialNumber, NotBefore
// (now-ClockSkew), and NotAfter (now+ttl) on tmpl, then signs tmpl with
// parent. The caller supplies all other template fields (Subject, KeyUsage,
// ExtKeyUsage, URIs, DNSNames). Returned serial is the leaf's serial in
// uppercase hex, suitable for an audit row.
func (c *CA) signLeaf(parent signer, tmpl *x509.Certificate, ttl time.Duration) (certPEM, keyPEM []byte, serial string, err error) {
	pub, priv, err := ed25519.GenerateKey(c.env.randR())
	if err != nil {
		return nil, nil, "", fmt.Errorf("ca: generate leaf key: %w", err)
	}
	certPEM, serial, err = c.signLeafCert(parent, tmpl, ttl, pub)
	if err != nil {
		return nil, nil, "", err
	}
	keyPEM, err = encodeEd25519KeyPEM(priv)
	if err != nil {
		return nil, nil, "", err
	}
	return certPEM, keyPEM, serial, nil
}

// signLeafCert signs tmpl with parent using the caller-supplied public key (the
// private key never reaches the CA — used by SignServerCSR so a server's key
// stays in its own pod). It fills SerialNumber/NotBefore/NotAfter like signLeaf.
func (c *CA) signLeafCert(parent signer, tmpl *x509.Certificate, ttl time.Duration, pub crypto.PublicKey) (certPEM []byte, serial string, err error) {
	serialNum, err := newSerial(c.env.randR())
	if err != nil {
		return nil, "", fmt.Errorf("ca: generate serial: %w", err)
	}
	now := c.env.now()
	tmpl.SerialNumber = serialNum
	tmpl.NotBefore = now.Add(-ClockSkew)
	tmpl.NotAfter = now.Add(ttl)
	tmpl.BasicConstraintsValid = true
	tmpl.IsCA = false

	der, err := x509.CreateCertificate(c.env.randR(), tmpl, parent.cert, pub, parent.key)
	if err != nil {
		return nil, "", fmt.Errorf("ca: sign leaf: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, "", fmt.Errorf("ca: parse leaf: %w", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return certPEM, formatSerial(leaf.SerialNumber), nil
}

// tenantSigner returns the intermediate cert+key for tenantID. Caller must
// take c.mu.RLock around use of the returned signer's key only if the value
// could change concurrently — the intermediate is loaded once at LoadOrInit
// time and never replaced, so the lock is not required after extraction.
func (c *CA) tenantSigner(tenantID string) (signer, []byte, error) {
	c.mu.RLock()
	t, ok := c.tenants[tenantID]
	c.mu.RUnlock()
	if !ok {
		return signer{}, nil, fmt.Errorf("ca: unknown tenant %q", tenantID)
	}
	return signer{cert: t.cert, key: t.key}, t.chainPEM, nil
}

// MintAgentCert issues a leaf client cert for the given tenant + user, bound to
// a specific agent via a second SPIFFE URI `spiffe://<td>/agent/<agentID>` (the
// single isolation policy — see
// the agent-isolation and cert-bootstrap design). The cert is
// signed by tenantID's own intermediate.
//
// The returned cert chain is intermediate || root (PEM concatenated),
// suitable for the agent to trust the server response chain and for the
// server to verify the client cert against.
//
// NotBefore is set ClockSkew earlier than now to tolerate small clock
// drift between agent and control plane; NotAfter is set exactly ttl in
// the future, so the caller's TTL parameter is the user-perceived
// validity window.
func (c *CA) MintAgentCert(tenantID, userID, agentID string, ttl time.Duration) (certPEM, keyPEM, chainPEM []byte, serial string, err error) {
	if tenantID == "" {
		return nil, nil, nil, "", errors.New("ca: tenantID is required")
	}
	if ttl <= 0 {
		return nil, nil, nil, "", errors.New("ca: ttl must be positive")
	}
	parent, chain, err := c.tenantSigner(tenantID)
	if err != nil {
		return nil, nil, nil, "", err
	}
	uris := []*url.URL{{
		Scheme: "spiffe",
		Host:   c.env.TrustDomain,
		Path:   "/tenant/" + tenantID,
	}}
	// When the cert is for a specific agent, add a second SPIFFE URI
	// `spiffe://<trust-domain>/agent/<agentID>` so orlop-server confines
	// the connection to that agent's disk. orlop always passes a non-empty
	// agentID; an empty one yields a tenant-only cert that the data plane now
	// rejects at the door (single agent-scoped policy).
	if agentID != "" {
		uris = append(uris, &url.URL{
			Scheme: "spiffe",
			Host:   c.env.TrustDomain,
			Path:   "/agent/" + agentID,
		})
	}
	tmpl := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:         userID,
			Organization:       []string{c.env.OrgName},
			OrganizationalUnit: []string{"tenant=" + tenantID},
		},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:        uris,
	}
	certPEM, keyPEM, serial, err = c.signLeaf(parent, tmpl, ttl)
	if err != nil {
		return nil, nil, nil, "", err
	}
	return certPEM, keyPEM, append([]byte(nil), chain...), serial, nil
}

// MintServerCert issues a leaf TLS server cert for the given tenant. The
// returned chainPEM is intermediate || root so the operator can drop it
// next to the cert; orlop-server itself only needs cert.pem + key.pem
// because the agent receives the chain via /agent/enroll and uses it as
// the server trust anchor.
func (c *CA) MintServerCert(tenantID, fqdn string, ttl time.Duration) (certPEM, keyPEM, chainPEM []byte, serial string, err error) {
	if tenantID == "" {
		return nil, nil, nil, "", errors.New("ca: tenantID is required")
	}
	if fqdn == "" {
		return nil, nil, nil, "", errors.New("ca: fqdn is required")
	}
	if ttl <= 0 {
		return nil, nil, nil, "", errors.New("ca: ttl must be positive")
	}
	parent, chain, err := c.tenantSigner(tenantID)
	if err != nil {
		return nil, nil, nil, "", err
	}
	tmpl := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:         fqdn,
			Organization:       []string{c.env.OrgName},
			OrganizationalUnit: []string{"tenant=" + tenantID},
		},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{fqdn},
	}
	certPEM, keyPEM, serial, err = c.signLeaf(parent, tmpl, ttl)
	if err != nil {
		return nil, nil, nil, "", err
	}
	return certPEM, keyPEM, append([]byte(nil), chain...), serial, nil
}

// MintControlPlaneCert issues a leaf client cert for the control plane itself,
// signed directly by the org root. The URI SAN is spiffe://<trust-domain>/control;
// orlop-server accepts requests from this cert on its /control/tenants endpoint.
//
// Requires the root key to be loaded.
func (c *CA) MintControlPlaneCert(ttl time.Duration) (certPEM, keyPEM []byte, serial string, err error) {
	if ttl <= 0 {
		return nil, nil, "", errors.New("ca: ttl must be positive")
	}
	c.mu.RLock()
	rootCert := c.rootCert
	rootKey := c.rootKey
	c.mu.RUnlock()
	if rootKey == nil {
		return nil, nil, "", errors.New("ca: root key not loaded; cannot mint control-plane cert")
	}
	tmpl := &x509.Certificate{
		Subject:     pkix.Name{CommonName: "orlop-control"},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs: []*url.URL{{
			Scheme: "spiffe",
			Host:   c.env.TrustDomain,
			Path:   "/control",
		}},
	}
	return c.signLeaf(signer{cert: rootCert, key: rootKey}, tmpl, ttl)
}

// SignServerCSR signs a orlop-server's CSR into a TLS server cert, signed
// directly by the org root — so EVERY tenant's agent (which trusts the root via
// the chain it receives at /agent/enroll) trusts this one shared server. The
// server keeps its private key; only the CSR (public key) reaches the CA. The
// cert's CN + DNS SAN are set to fqdn. This backs the boot-time self-provision
// flow (no manual `mint-server-cert`, no pre-created TLS secret). The matching
// client CA for the server is the org root ([CA.RootPEM]). Requires the root key.
func (c *CA) SignServerCSR(csrDER []byte, fqdn string, ttl time.Duration) (certPEM []byte, serial string, err error) {
	if fqdn == "" {
		return nil, "", errors.New("ca: fqdn is required")
	}
	if ttl <= 0 {
		return nil, "", errors.New("ca: ttl must be positive")
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, "", fmt.Errorf("ca: parse server CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, "", fmt.Errorf("ca: server CSR signature: %w", err)
	}
	c.mu.RLock()
	rootCert := c.rootCert
	rootKey := c.rootKey
	c.mu.RUnlock()
	if rootKey == nil {
		return nil, "", errors.New("ca: root key not loaded; cannot sign server cert")
	}
	tmpl := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:   fqdn,
			Organization: []string{c.env.OrgName},
		},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{fqdn},
	}
	return c.signLeafCert(signer{cert: rootCert, key: rootKey}, tmpl, ttl, csr.PublicKey)
}

// RootPEM returns the PEM-encoded org root certificate.
func (c *CA) RootPEM() []byte {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]byte(nil), c.rootPEM...)
}

// TenantChainPEM returns the cert chain (intermediate || root) for the
// given tenant, or false if no intermediate exists.
func (c *CA) TenantChainPEM(tenantID string) ([]byte, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	t, ok := c.tenants[tenantID]
	if !ok {
		return nil, false
	}
	return append([]byte(nil), t.chainPEM...), true
}

// HasTenant reports whether an intermediate is loaded for tenantID.
func (c *CA) HasTenant(tenantID string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, ok := c.tenants[tenantID]
	return ok
}

// TenantIDs returns sorted IDs of all loaded intermediates.
func (c *CA) TenantIDs() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	ids := make([]string, 0, len(c.tenants))
	for id := range c.tenants {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// HasRootKey reports whether the loaded CA holds the root signing key.
// False on hosts that should only verify chains (the prod server VM).
func (c *CA) HasRootKey() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.rootKey != nil
}

func (c *CA) generateRoot() (*x509.Certificate, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(c.env.randR())
	if err != nil {
		return nil, nil, err
	}
	serialNum, err := newSerial(c.env.randR())
	if err != nil {
		return nil, nil, err
	}
	now := c.env.now()
	tmpl := &x509.Certificate{
		SerialNumber: serialNum,
		Subject: pkix.Name{
			CommonName:   c.env.OrgName + " Root CA",
			Organization: []string{c.env.OrgName},
		},
		NotBefore:             now.Add(-ClockSkew),
		NotAfter:              now.Add(DefaultRootValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	der, err := x509.CreateCertificate(c.env.randR(), tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, priv, nil
}

func (c *CA) generateIntermediate(tenantID string) (*x509.Certificate, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(c.env.randR())
	if err != nil {
		return nil, nil, err
	}
	serialNum, err := newSerial(c.env.randR())
	if err != nil {
		return nil, nil, err
	}
	now := c.env.now()
	tmpl := &x509.Certificate{
		SerialNumber: serialNum,
		Subject: pkix.Name{
			CommonName:         c.env.OrgName + " Tenant " + tenantID + " Intermediate",
			Organization:       []string{c.env.OrgName},
			OrganizationalUnit: []string{"tenant=" + tenantID},
		},
		NotBefore:             now.Add(-ClockSkew),
		NotAfter:              now.Add(DefaultIntermediateValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		// Constrain issuance to this deployment's trust domain (issue #7): a
		// leaked intermediate key cannot mint a leaf for a DIFFERENT SPIFFE
		// trust domain, because crypto/x509 path validation rejects a URI SAN
		// whose host falls outside PermittedURIDomains. NOTE this does NOT
		// isolate tenants from each other: every tenant's SPIFFE SAN shares this
		// same trust-domain host and differs only by the URI path (/tenant/<id>),
		// which URI name constraints (host-scoped) cannot distinguish. The
		// cross-tenant forgery gate is the data plane's fail-closed
		// checkTenantBinding, which matches the signing intermediate's tenant OU
		// against the leaf's SAN path.
		PermittedURIDomains: []string{c.env.TrustDomain},
	}
	der, err := x509.CreateCertificate(c.env.randR(), tmpl, c.rootCert, pub, c.rootKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, priv, nil
}

func tenantCertKey(id string) string { return tenantPrefix + id + "/cert.pem" }
func tenantKeyKey(id string) string  { return tenantPrefix + id + "/key.pem" }

func newSerial(r io.Reader) (*big.Int, error) {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(r, max)
}

func formatSerial(s *big.Int) string {
	return strings.ToUpper(hex.EncodeToString(s.Bytes()))
}

func encodeCertPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func encodeEd25519KeyPEM(key ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// DecodeCertPEM parses a single PEM-encoded x509 certificate. The block must
// be the only PEM block in b — trailing content is ignored, but a missing or
// non-CERTIFICATE block returns an error.
func DecodeCertPEM(b []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("expected PEM CERTIFICATE block")
	}
	return x509.ParseCertificate(block.Bytes)
}

func decodeEd25519KeyPEM(b []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("expected PEM PRIVATE KEY block")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ed, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("expected ed25519 key")
	}
	return ed, nil
}
