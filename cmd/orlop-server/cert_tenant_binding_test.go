package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
)

// chainFor builds a [leaf, intermediate, root] verified chain where the
// intermediate's Subject (carrying OU tenant=<interTenant>) is the leaf's
// Issuer, mirroring a real control-plane-minted chain.
func chainFor(interTenant string) [][]*x509.Certificate {
	interSubject := pkix.Name{CommonName: "tenant-int", OrganizationalUnit: []string{"tenant=" + interTenant}}
	leaf := &x509.Certificate{
		Subject: pkix.Name{CommonName: "user@example.com"},
		Issuer:  interSubject,
	}
	intermediate := &x509.Certificate{Subject: interSubject}
	root := &x509.Certificate{Subject: pkix.Name{CommonName: "org-root"}}
	return [][]*x509.Certificate{{leaf, intermediate, root}}
}

func TestTenantBindingAllowsMatchingChain(t *testing.T) {
	if !checkTenantBinding(discardLogger(), "a_demo", chainFor("a_demo")) {
		t.Fatal("a leaf signed by its own tenant intermediate must be allowed")
	}
}

func TestTenantBindingRejectsForgedCrossTenantSAN(t *testing.T) {
	// Leaf claims tenant a_victim but was signed by tenant a_attacker's
	// intermediate — the leaked-intermediate-key forgery. Must be rejected.
	if checkTenantBinding(discardLogger(), "a_victim", chainFor("a_attacker")) {
		t.Fatal("a cross-tenant forged SAN must be rejected")
	}
}

func TestTenantBindingFailsClosedOnUnexpectedChain(t *testing.T) {
	// No intermediate (leaf only): a legitimate agent leaf is always presented
	// with its tenant intermediate (the server's ClientCAs is the org root
	// alone, so the handshake cannot verify without it). A chain with no
	// intermediate is therefore an attack or misconfiguration — reject it.
	leafOnly := [][]*x509.Certificate{{&x509.Certificate{Subject: pkix.Name{CommonName: "x"}}}}
	if checkTenantBinding(discardLogger(), "a_demo", leafOnly) {
		t.Fatal("a chain with no intermediate must fail closed (reject)")
	}
	if checkTenantBinding(discardLogger(), "a_demo", nil) {
		t.Fatal("a nil chain must fail closed (reject)")
	}

	// Intermediate present but without a tenant OU: every real intermediate
	// carries OU "tenant=<id>", so a missing OU is not a legitimate chain — reject.
	noOU := [][]*x509.Certificate{{
		&x509.Certificate{Subject: pkix.Name{CommonName: "leaf"}, Issuer: pkix.Name{CommonName: "int"}},
		&x509.Certificate{Subject: pkix.Name{CommonName: "int"}},
	}}
	if checkTenantBinding(discardLogger(), "a_demo", noOU) {
		t.Fatal("an intermediate without a tenant OU must fail closed (reject)")
	}
}

func TestTenantFromOU(t *testing.T) {
	if got := tenantFromOU([]string{"foo", "tenant=a_demo", "bar"}); got != "a_demo" {
		t.Fatalf("tenantFromOU = %q, want a_demo", got)
	}
	if got := tenantFromOU([]string{"no", "tenant", "here"}); got != "" {
		t.Fatalf("tenantFromOU = %q, want empty", got)
	}
}
