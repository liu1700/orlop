package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/ca"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/secrets"
)

const caUsage = `usage:
  orlop-control ca init --root [--secrets-dir DIR]              bootstrap the org root CA
  orlop-control ca init --tenant ID [--secrets-dir DIR]         bootstrap a tenant intermediate
  orlop-control ca list [--secrets-dir DIR]                     list loaded tenant intermediates
  orlop-control ca mint-server-cert --tenant ID --fqdn HOST --out-dir DIR [--ttl DURATION]
                                                              mint a TLS server cert for orlop-server

init subcommands are idempotent. --root must be run on an offline operator
machine; the resulting root key never leaves that machine for the MVP.
mint-server-cert always issues a fresh leaf; rotate by re-running it and
reloading orlop-server. See docs/control-plane-runbook.md for the full
operator workflow.
`

func runCA(ctx context.Context, out io.Writer, args []string) error {
	if len(args) == 0 {
		return errors.New(caUsage)
	}
	switch args[0] {
	case "init":
		return runCAInit(ctx, out, args[1:])
	case "list":
		return runCAList(ctx, out, args[1:])
	case "mint-server-cert":
		return runCAMintServerCert(ctx, out, args[1:])
	case "-h", "--help", "help":
		_, _ = fmt.Fprint(out, caUsage)
		return nil
	default:
		return fmt.Errorf("unknown ca subcommand %q\n%s", args[0], caUsage)
	}
}

func runCAInit(ctx context.Context, out io.Writer, args []string) error {
	fs := flag.NewFlagSet("ca init", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var (
		root        = fs.Bool("root", false, "bootstrap the org root CA (offline operator workflow)")
		tenant      = fs.String("tenant", "", "bootstrap a tenant intermediate for the given ID")
		secretsDir  = fs.String("secrets-dir", os.Getenv("ORLOP_SECRETS_DIR"), "filesystem secrets directory")
		trustDomain = fs.String("trust-domain", getenv("ORLOP_TRUST_DOMAIN", "orlop.example"), "SPIFFE trust domain")
		org         = fs.String("org", getenv("ORLOP_ORG_NAME", "ORL"), "X.509 Organization name")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *secretsDir == "" {
		return errors.New("--secrets-dir or ORLOP_SECRETS_DIR is required")
	}
	switch {
	case *root && *tenant != "":
		return errors.New("specify exactly one of --root or --tenant")
	case !*root && *tenant == "":
		return errors.New("specify exactly one of --root or --tenant")
	}

	backend := secrets.NewFilesystem(*secretsDir)
	c, err := ca.LoadOrInit(ctx, backend, ca.Env{
		TrustDomain: *trustDomain,
		OrgName:     *org,
	})
	if err != nil {
		return err
	}

	if *root {
		fmt.Fprintf(out, "root CA ready at %s\n", filepath.Join(*secretsDir, "ca", "root", "cert.pem"))
		return nil
	}

	if err := c.BootstrapTenant(ctx, *tenant); err != nil {
		return fmt.Errorf("bootstrap tenant %q: %w", *tenant, err)
	}
	fmt.Fprintf(out, "tenant %q intermediate ready at %s\n", *tenant, filepath.Join(*secretsDir, "ca", "tenant", *tenant, "cert.pem"))
	return nil
}

func runCAList(ctx context.Context, out io.Writer, args []string) error {
	fs := flag.NewFlagSet("ca list", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var (
		secretsDir  = fs.String("secrets-dir", os.Getenv("ORLOP_SECRETS_DIR"), "filesystem secrets directory")
		trustDomain = fs.String("trust-domain", getenv("ORLOP_TRUST_DOMAIN", "orlop.example"), "SPIFFE trust domain")
		org         = fs.String("org", getenv("ORLOP_ORG_NAME", "ORL"), "X.509 Organization name")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *secretsDir == "" {
		return errors.New("--secrets-dir or ORLOP_SECRETS_DIR is required")
	}
	backend := secrets.NewFilesystem(*secretsDir)
	c, err := ca.LoadOrInit(ctx, backend, ca.Env{
		TrustDomain: *trustDomain,
		OrgName:     *org,
	})
	if err != nil {
		return err
	}
	ids := c.TenantIDs()
	if len(ids) == 0 {
		fmt.Fprintln(out, "no tenant intermediates")
		return nil
	}
	for _, id := range ids {
		fmt.Fprintln(out, id)
	}
	return nil
}

func runCAMintServerCert(ctx context.Context, out io.Writer, args []string) error {
	fs := flag.NewFlagSet("ca mint-server-cert", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var (
		tenant      = fs.String("tenant", "", "tenant ID to mint under (required)")
		fqdn        = fs.String("fqdn", "", "server DNS name to embed as CN + SAN (required)")
		outDir      = fs.String("out-dir", "", "directory to write cert.pem/key.pem/chain.pem (required)")
		ttl         = fs.Duration("ttl", 90*24*time.Hour, "leaf validity duration")
		secretsDir  = fs.String("secrets-dir", os.Getenv("ORLOP_SECRETS_DIR"), "filesystem secrets directory")
		trustDomain = fs.String("trust-domain", getenv("ORLOP_TRUST_DOMAIN", "orlop.example"), "SPIFFE trust domain")
		org         = fs.String("org", getenv("ORLOP_ORG_NAME", "ORL"), "X.509 Organization name")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *secretsDir == "" {
		return errors.New("--secrets-dir or ORLOP_SECRETS_DIR is required")
	}
	if *tenant == "" {
		return errors.New("--tenant is required")
	}
	if *fqdn == "" {
		return errors.New("--fqdn is required")
	}
	if *outDir == "" {
		return errors.New("--out-dir is required")
	}
	if *ttl <= 0 {
		return errors.New("--ttl must be positive")
	}

	backend := secrets.NewFilesystem(*secretsDir)
	c, err := ca.LoadOrInit(ctx, backend, ca.Env{
		TrustDomain: *trustDomain,
		OrgName:     *org,
	})
	if err != nil {
		return err
	}
	if !c.HasTenant(*tenant) {
		return fmt.Errorf("tenant %q intermediate not loaded; run `ca init --tenant %s` against the operator vault first", *tenant, *tenant)
	}

	certPEM, keyPEM, chainPEM, serial, err := c.MintServerCert(*tenant, *fqdn, *ttl)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(*outDir, 0o700); err != nil {
		return fmt.Errorf("create out-dir: %w", err)
	}
	files := []struct {
		name string
		data []byte
	}{
		{"cert.pem", certPEM},
		{"key.pem", keyPEM},
		{"chain.pem", chainPEM},
	}
	for _, f := range files {
		path := filepath.Join(*outDir, f.name)
		// O_TRUNC|O_CREATE with 0600 ensures rotation overwrites stale
		// material in place without widening perms.
		fh, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return fmt.Errorf("open %s: %w", path, err)
		}
		if _, err := fh.Write(f.data); err != nil {
			_ = fh.Close()
			return fmt.Errorf("write %s: %w", path, err)
		}
		if err := fh.Close(); err != nil {
			return fmt.Errorf("close %s: %w", path, err)
		}
		// Re-chmod in case the file pre-existed with looser perms.
		if err := os.Chmod(path, 0o600); err != nil {
			return fmt.Errorf("chmod %s: %w", path, err)
		}
	}

	expires := time.Now().UTC().Add(*ttl).UTC().Format(time.RFC3339)
	fmt.Fprintf(out, "wrote server cert: %s (serial=%s, expires=%s)\n",
		filepath.Join(*outDir, "cert.pem"), serial, expires)
	return nil
}
