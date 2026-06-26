package main

import (
	"crypto/x509"
	"log/slog"
	"strings"
)

// checkTenantBinding is a defense-in-depth gate on the data plane.
//
// The data plane trusts the tenant carried in the leaf's SPIFFE SAN
// (certTenantID) and accepts any leaf that chains to the shared org root. The
// per-tenant intermediates carry no X.509 name constraints, so a LEAKED tenant
// intermediate private key could mint a leaf bearing ANOTHER tenant's SAN that
// still validates — full cross-tenant access. (Not exploitable today: agents
// only ever receive their own short-lived leaf, never an intermediate key.)
//
// This confirms the intermediate that actually signed the leaf is scoped to the
// SAME tenant — its Subject carries OU "tenant=<id>", set by the control-plane
// CA's generateIntermediate — so a forged cross-tenant SAN is rejected even if
// an intermediate key leaks.
//
// It fails CLOSED only on a DEFINITE mismatch (the forgery signal). An
// unexpected or unrecognized chain shape fails OPEN with a warning: a false
// reject here would drop every legitimate mount, and this is hardening, not the
// primary isolation gate (which is the SAN-scoped path authz in checkAgentPath).
func checkTenantBinding(logger *slog.Logger, leafTenant string, chains [][]*x509.Certificate) bool {
	signer, ok := signingIntermediate(chains)
	if !ok {
		logger.Warn("tenant binding: no verified intermediate in chain; skipping check (allow)")
		return true
	}
	signerTenant := tenantFromOU(signer.Subject.OrganizationalUnit)
	if signerTenant == "" {
		logger.Warn("tenant binding: signing intermediate has no tenant OU; skipping check (allow)")
		return true
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
