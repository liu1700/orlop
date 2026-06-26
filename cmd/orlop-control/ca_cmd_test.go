package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunCAInitRootIdempotent(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	t.Setenv("ORLOP_SECRETS_DIR", dir)
	t.Setenv("ORLOP_TRUST_DOMAIN", "test.example")

	var out bytes.Buffer
	if err := runCA(ctx, &out, []string{"init", "--root"}); err != nil {
		t.Fatal(err)
	}
	rootCert, err := os.ReadFile(filepath.Join(dir, "ca", "root", "cert.pem"))
	if err != nil {
		t.Fatal(err)
	}

	out.Reset()
	if err := runCA(ctx, &out, []string{"init", "--root"}); err != nil {
		t.Fatal(err)
	}
	rootCert2, err := os.ReadFile(filepath.Join(dir, "ca", "root", "cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rootCert, rootCert2) {
		t.Fatal("ca init --root rotated the root cert on second run")
	}
}

func TestRunCAInitTenantIdempotent(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	t.Setenv("ORLOP_SECRETS_DIR", dir)
	t.Setenv("ORLOP_TRUST_DOMAIN", "test.example")

	var out bytes.Buffer
	if err := runCA(ctx, &out, []string{"init", "--tenant", "acme"}); err != nil {
		t.Fatal(err)
	}
	intCert, err := os.ReadFile(filepath.Join(dir, "ca", "tenant", "acme", "cert.pem"))
	if err != nil {
		t.Fatal(err)
	}

	out.Reset()
	if err := runCA(ctx, &out, []string{"init", "--tenant", "acme"}); err != nil {
		t.Fatal(err)
	}
	intCert2, err := os.ReadFile(filepath.Join(dir, "ca", "tenant", "acme", "cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(intCert, intCert2) {
		t.Fatal("ca init --tenant rotated the intermediate on second run")
	}

	block, _ := pem.Decode(intCert)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("intermediate is not a PEM CERTIFICATE")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !cert.IsCA {
		t.Fatal("intermediate must have IsCA=true")
	}
	if !strings.Contains(cert.Subject.CommonName, "acme") {
		t.Fatalf("intermediate CN = %q, want contains tenant id", cert.Subject.CommonName)
	}
}

func TestRunCAInitRejectsBadFlags(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	t.Setenv("ORLOP_SECRETS_DIR", dir)

	cases := [][]string{
		{"init"},
		{"init", "--root", "--tenant", "x"},
	}
	for _, args := range cases {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			if err := runCA(ctx, new(bytes.Buffer), args); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestRunCAInitRequiresSecretsDir(t *testing.T) {
	ctx := context.Background()
	t.Setenv("ORLOP_SECRETS_DIR", "")
	if err := runCA(ctx, new(bytes.Buffer), []string{"init", "--root"}); err == nil {
		t.Fatal("expected error when secrets dir is unset")
	}
}

func TestRunCAList(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	t.Setenv("ORLOP_SECRETS_DIR", dir)
	t.Setenv("ORLOP_TRUST_DOMAIN", "test.example")

	if err := runCA(ctx, new(bytes.Buffer), []string{"init", "--tenant", "alpha"}); err != nil {
		t.Fatal(err)
	}
	if err := runCA(ctx, new(bytes.Buffer), []string{"init", "--tenant", "beta"}); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := runCA(ctx, &out, []string{"list"}); err != nil {
		t.Fatal(err)
	}
	got := strings.TrimSpace(out.String())
	if got != "alpha\nbeta" {
		t.Fatalf("list = %q, want alpha\\nbeta", got)
	}
}

func TestRunCAUnknownSubcommand(t *testing.T) {
	if err := runCA(context.Background(), new(bytes.Buffer), []string{"frobnicate"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestCAMintServerCert(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	t.Setenv("ORLOP_SECRETS_DIR", dir)
	t.Setenv("ORLOP_TRUST_DOMAIN", "test.example")

	if err := runCA(ctx, new(bytes.Buffer), []string{"init", "--root"}); err != nil {
		t.Fatal(err)
	}
	if err := runCA(ctx, new(bytes.Buffer), []string{"init", "--tenant", "acme"}); err != nil {
		t.Fatal(err)
	}

	outDir := filepath.Join(dir, "out")
	var out bytes.Buffer
	if err := runCA(ctx, &out, []string{
		"mint-server-cert",
		"--tenant", "acme",
		"--fqdn", "tenant-acme.test",
		"--out-dir", outDir,
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "wrote server cert:") {
		t.Fatalf("stdout = %q, want progress line", out.String())
	}

	for _, name := range []string{"cert.pem", "key.pem", "chain.pem"} {
		path := filepath.Join(outDir, name)
		st, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if perm := st.Mode().Perm(); perm != 0o600 {
			t.Fatalf("%s mode = %o, want 0600", name, perm)
		}
	}

	certBytes, err := os.ReadFile(filepath.Join(outDir, "cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("cert.pem is not a PEM CERTIFICATE")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "tenant-acme.test" {
		t.Fatalf("CN = %q, want %q", cert.Subject.CommonName, "tenant-acme.test")
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "tenant-acme.test" {
		t.Fatalf("DNSNames = %v, want [tenant-acme.test]", cert.DNSNames)
	}
}

func TestCAMintServerCertUnknownTenant(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	t.Setenv("ORLOP_SECRETS_DIR", dir)
	t.Setenv("ORLOP_TRUST_DOMAIN", "test.example")

	if err := runCA(ctx, new(bytes.Buffer), []string{"init", "--root"}); err != nil {
		t.Fatal(err)
	}
	err := runCA(ctx, new(bytes.Buffer), []string{
		"mint-server-cert",
		"--tenant", "ghost",
		"--fqdn", "tenant-ghost.test",
		"--out-dir", filepath.Join(dir, "out"),
	})
	if err == nil {
		t.Fatal("expected error for unloaded tenant")
	}
}
