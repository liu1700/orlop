package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Identity is the audited caller resolved from the verified peer certificate.
type Identity struct {
	AgentID     string
	TenantID    string
	CertSerial  string
	CertSubject string
	// ScopedAgentID is the agent id carried in a `spiffe://<td>/agent/<id>` SAN.
	// It is the *authorization* scope for the connection: the cert may operate
	// ONLY on paths under `/<ScopedAgentID>`. Every data-plane cert carries one —
	// identifyV2Peer rejects a data-plane cert with no agent SAN at the door, so
	// there is no tenant-wide path (single isolation policy; see
	// the agent-isolation and cert-bootstrap design). An empty
	// value therefore only occurs for an injected test Identity, never real
	// traffic.
	//
	// This is distinct from AgentID, which is the cert CN (the user id) used
	// for the audit trail — do not conflate the two.
	ScopedAgentID string
}

// Identifier resolves a request's caller. Production wiring reads the verified
// mTLS client certificate; tests inject a stub via IdentityFromContext.
type Identifier interface {
	Identify(r *http.Request) (Identity, error)
}

// ErrNoIdentity is returned by an Identifier when it cannot resolve the
// caller. The router translates this into 401.
var ErrNoIdentity = errors.New("no caller identity")

var ErrNoTenantIdentity = errors.New("client certificate is missing tenant identity")

type ctxKey struct{}

// WithIdentity attaches an Identity to the request context. Used by tests to
// drive handlers without a real mTLS listener.
func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// IdentityFromContext returns the injected identity, if any.
func IdentityFromContext(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(ctxKey{}).(Identity)
	return id, ok
}

// contextIdentifier reads identity from the request context. Used in tests
// where handlers have an injected identity rather than a real client cert.
type contextIdentifier struct{}

func (contextIdentifier) Identify(r *http.Request) (Identity, error) {
	if id, ok := IdentityFromContext(r.Context()); ok {
		return id, nil
	}
	return Identity{}, ErrNoIdentity
}

type certIdentifier struct {
	trustDomain string
}

func (c certIdentifier) Identify(r *http.Request) (Identity, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return Identity{}, ErrNoIdentity
	}
	cert := r.TLS.PeerCertificates[0]
	agentID := certAgentID(cert)
	if agentID == "" {
		return Identity{}, ErrNoIdentity
	}
	tenantID, err := certTenantID(cert, c.trustDomain)
	ident := Identity{
		AgentID:     agentID,
		TenantID:    tenantID,
		CertSubject: cert.Subject.String(),
	}
	if cert.SerialNumber != nil {
		ident.CertSerial = cert.SerialNumber.String()
	}
	if err != nil {
		return ident, err
	}
	return ident, nil
}

func certAgentID(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}
	if len(cert.URIs) > 0 {
		return cert.URIs[0].String()
	}
	if len(cert.EmailAddresses) > 0 {
		return cert.EmailAddresses[0]
	}
	if len(cert.DNSNames) > 0 {
		return cert.DNSNames[0]
	}
	if cert.SerialNumber != nil {
		return cert.SerialNumber.String()
	}
	return cert.Subject.String()
}

// controlPlaneSPIFFE returns the URI SAN that orlop-control uses when calling
// /admin endpoints for the given trust domain. It is not a tenant ID —
// controlPlaneOnlyMiddleware checks for it explicitly.
func controlPlaneSPIFFE(trustDomain string) string {
	return "spiffe://" + trustDomain + "/control"
}

// isControlPlaneCert returns true when the certificate carries the
// control-plane URI SAN for the given trust domain.
func isControlPlaneCert(cert *x509.Certificate, trustDomain string) bool {
	if cert == nil {
		return false
	}
	expected := controlPlaneSPIFFE(trustDomain)
	for _, uri := range cert.URIs {
		if uri != nil && uri.String() == expected {
			return true
		}
	}
	return false
}

func certTenantID(cert *x509.Certificate, trustDomain string) (string, error) {
	if cert == nil {
		return "", ErrNoTenantIdentity
	}
	for _, uri := range cert.URIs {
		if uri == nil || uri.Scheme != "spiffe" {
			continue
		}
		// Only accept URIs from our trust domain.
		if uri.Host != trustDomain {
			continue
		}
		// Control-plane cert is not a tenant cert; skip it here.
		if uri.String() == controlPlaneSPIFFE(trustDomain) {
			return "", fmt.Errorf("%w: control-plane cert has no tenant identity", ErrNoTenantIdentity)
		}
		tenantID, ok := tenantIDFromSPIFFE(uri, trustDomain)
		if !ok {
			return "", fmt.Errorf("%w: malformed SPIFFE URI SAN", ErrNoTenantIdentity)
		}
		return tenantID, nil
	}
	return "", ErrNoTenantIdentity
}

func tenantIDFromSPIFFE(uri *url.URL, trustDomain string) (string, bool) {
	if uri.Host != trustDomain {
		return "", false
	}
	parts := strings.Split(strings.Trim(uri.Path, "/"), "/")
	if len(parts) != 2 || parts[0] != "tenant" || parts[1] == "" {
		return "", false
	}
	return parts[1], true
}

// agentIDFromSPIFFE parses a `spiffe://<td>/agent/<id>` SAN path and returns
// the agent id. It mirrors tenantIDFromSPIFFE: the path must be exactly two
// segments, the first being the literal "agent" and the second non-empty.
func agentIDFromSPIFFE(uri *url.URL, trustDomain string) (string, bool) {
	if uri.Host != trustDomain {
		return "", false
	}
	parts := strings.Split(strings.Trim(uri.Path, "/"), "/")
	if len(parts) != 2 || parts[0] != "agent" || parts[1] == "" {
		return "", false
	}
	return parts[1], true
}

// certScopedAgentID returns the agent id from the first
// `spiffe://<trustDomain>/agent/<id>` SAN on the cert, or "" when the cert
// carries no such SAN. URIs that are not spiffe, are from a different trust
// domain, are the control-plane URI, or are tenant URIs are skipped so a
// tenant-only cert returns "" (and stays tenant-scoped). Returning "" on a
// cert with only a malformed `/agent/...` SAN is intentional: an unparseable
// agent SAN must not silently widen access — callers treat "" as
// "no per-agent scope", i.e. the existing tenant-wide behaviour.
func certScopedAgentID(cert *x509.Certificate, trustDomain string) string {
	if cert == nil {
		return ""
	}
	controlURI := controlPlaneSPIFFE(trustDomain)
	for _, uri := range cert.URIs {
		if uri == nil || uri.Scheme != "spiffe" {
			continue
		}
		if uri.Host != trustDomain {
			continue
		}
		if uri.String() == controlURI {
			continue
		}
		// Tenant URIs are not agent scopes; skip them.
		if _, ok := tenantIDFromSPIFFE(uri, trustDomain); ok {
			continue
		}
		if agentID, ok := agentIDFromSPIFFE(uri, trustDomain); ok {
			return agentID
		}
	}
	return ""
}
