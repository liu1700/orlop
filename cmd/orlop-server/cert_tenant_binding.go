package main

import (
	"crypto/x509"
	"log/slog"
	"strings"
)

// checkTenantBinding is the data-plane gate against cross-tenant cert forgery.
//
// The data plane trusts the tenant carried in the leaf's SPIFFE SAN
// (certTenantID) and accepts any leaf that chains to the shared org root. URI
// X.509 name constraints cannot isolate tenants here — every SPIFFE SAN shares
// the trust-domain *host* and tenants differ only by the URI *path*, which
// crypto/x509 path validation does not constrain (it is host-scoped). So a
// LEAKED tenant-intermediate private key could otherwise mint a leaf bearing
// ANOTHER tenant's SAN that still validates against the root. (Not exploitable
// today: agents only ever receive their own short-lived leaf, never an
// intermediate key.) This check is therefore the enforcing gate for that path,
// not mere defense-in-depth.
//
// It confirms the intermediate that actually signed the leaf is scoped to the
// SAME tenant — its Subject carries OU "tenant=<id>", set by the control-plane
// CA's generateIntermediate — so a forged cross-tenant SAN is rejected even if
// an intermediate key leaks.
//
// It fails CLOSED. Every legitimate agent leaf is minted by a tenant
// intermediate (MintAgentCert → tenantSigner) and presented WITH that
// intermediate: the server's ClientCAs is the org root alone, so a successful
// RequireAndVerifyClientCert handshake cannot complete unless the client
// supplied the intermediate. By the time this runs, VerifiedChains[0] is always
// [leaf, intermediate, root] with a "tenant=<id>" OU. An unrecognized chain
// shape or a missing tenant OU is therefore not a legitimate connection — it is
// an attack or a misconfiguration — and is rejected rather than waved through.
func checkTenantBinding(logger *slog.Logger, leafTenant string, chains [][]*x509.Certificate) bool {
	signer, ok := signingIntermediate(chains)
	if !ok {
		logger.Warn("tenant binding: no verified intermediate in chain; rejecting connection")
		return false
	}
	signerTenant := tenantFromOU(signer.Subject.OrganizationalUnit)
	if signerTenant == "" {
		logger.Warn("tenant binding: signing intermediate has no tenant OU; rejecting connection")
		return false
	}
	if signerTenant != leafTenant {
		logger.Warn("tenant binding mismatch; rejecting connection",
			"leaf_tenant", leafTenant, "signer_tenant", signerTenant)
		return false
	}
	return true
}

// signingIntermediate returns the certificate in the primary verified chain
// ([leaf, intermediate, root]) that issued the leaf.
func signingIntermediate(chains [][]*x509.Certificate) (*x509.Certificate, bool) {
	if len(chains) == 0 || len(chains[0]) < 2 {
		return nil, false
	}
	chain := chains[0]
	leaf := chain[0]
	for _, c := range chain[1:] {
		if c.Subject.String() == leaf.Issuer.String() {
			return c, true
		}
	}
	return nil, false
}

// tenantFromOU extracts the tenant id from a Subject's OU values, where the
// control-plane CA encodes it as "tenant=<id>".
func tenantFromOU(ou []string) string {
	const prefix = "tenant="
	for _, v := range ou {
		if strings.HasPrefix(v, prefix) {
			return strings.TrimPrefix(v, prefix)
		}
	}
	return ""
}
