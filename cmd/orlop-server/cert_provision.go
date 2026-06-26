package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// defaultServerFQDN is the in-cluster Service name agents and orlop-control
// dial orlop-server at; it must match the cert's DNS SAN. Overridable via
// tls.fqdn for non-default deployments.
const defaultServerFQDN = "orlop-server"

// signServerCertRequest / signServerCertResponse mirror the orlop-control
// POST /control/sign-server-cert contract (server_cert_handlers.go).
type signServerCertRequest struct {
	CSRPEM string `json:"csr_pem"`
	FQDN   string `json:"fqdn,omitempty"`
}

type signServerCertResponse struct {
	CertPEM     string `json:"cert_pem"`
	ClientCAPEM string `json:"client_ca_pem"`
	Serial      string `json:"serial"`
	ExpiresAt   string `json:"expires_at"`
}

// rotatingCert holds the current server leaf, swapped in place on rotation. The
// tls.Config reads it via GetCertificate on every handshake, so a rotation is
// visible to new connections without restarting the listeners.
type rotatingCert struct {
	mu  sync.RWMutex
	cur *tls.Certificate
}

func (rc *rotatingCert) get() *tls.Certificate {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return rc.cur
}

func (rc *rotatingCert) set(c *tls.Certificate) {
	rc.mu.Lock()
	rc.cur = c
	rc.mu.Unlock()
}

// signedCert is one signing round's parsed result.
type signedCert struct {
	tlsCert  tls.Certificate
	clientCA *x509.CertPool
	notAfter time.Time
	serial   string
}

// certProvisioner mints the server's TLS material by sending a CSR to
// orlop-control. The private key is generated per signing round and never
// leaves this process.
type certProvisioner struct {
	logger     *slog.Logger
	controlURL string
	fqdn       string
	token      string
	client     *http.Client

	// tuning knobs (overridable in tests)
	maxBackoff time.Duration
	now        func() time.Time
}

func newCertProvisioner(logger *slog.Logger, cfg Config) (*certProvisioner, error) {
	if cfg.ControlURL == "" {
		return nil, errors.New("tls.control_url is required when tls.self_provision is true")
	}
	if cfg.ServiceToken == "" {
		return nil, errors.New("ORLOP_DATAGW_SERVICE_TOKEN is required when tls.self_provision is true")
	}
	fqdn := cfg.ServerFQDN
	if fqdn == "" {
		fqdn = defaultServerFQDN
	}
	return &certProvisioner{
		logger:     logger,
		controlURL: cfg.ControlURL,
		fqdn:       fqdn,
		token:      cfg.ServiceToken,
		client:     &http.Client{Timeout: 15 * time.Second},
		maxBackoff: 30 * time.Second,
		now:        time.Now,
	}, nil
}

// signOnce generates a fresh keypair, sends one CSR, and returns the signed
// material. Any non-200 (or transport error) is returned so the caller can retry.
func (p *certProvisioner) signOnce(ctx context.Context) (*signedCert, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	_ = pub
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: p.fqdn},
		DNSNames: []string{p.fqdn},
	}, priv)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	// fqdn is dictated by control (omitted here); we send it for clarity so a
	// mismatch with control's allow-list fails loudly rather than silently.
	body, err := json.Marshal(signServerCertRequest{CSRPEM: string(csrPEM), FQDN: p.fqdn})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.controlURL+"/control/sign-server-cert", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+p.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sign request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sign request: status %d: %s", resp.StatusCode, bytes.TrimSpace(respBody))
	}

	var sr signServerCertResponse
	if err := json.Unmarshal(respBody, &sr); err != nil {
		return nil, fmt.Errorf("decode sign response: %w", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	tlsCert, err := tls.X509KeyPair([]byte(sr.CertPEM), keyPEM)
	if err != nil {
		return nil, fmt.Errorf("assemble keypair: %w", err)
	}
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse signed leaf: %w", err)
	}
	tlsCert.Leaf = leaf

	clientCA := x509.NewCertPool()
	if !clientCA.AppendCertsFromPEM([]byte(sr.ClientCAPEM)) {
		return nil, errors.New("client_ca_pem contained no certificates")
	}

	return &signedCert{tlsCert: tlsCert, clientCA: clientCA, notAfter: leaf.NotAfter, serial: sr.Serial}, nil
}

// provision retries signOnce with exponential backoff until it succeeds or ctx
// is cancelled. orlop-control may not be reachable the instant the server
// boots, so this tolerates a cold control plane.
func (p *certProvisioner) provision(ctx context.Context) (*signedCert, error) {
	backoff := 500 * time.Millisecond
	for attempt := 1; ; attempt++ {
		sc, err := p.signOnce(ctx)
		if err == nil {
			return sc, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		p.logger.Warn("server_cert_sign_retry", "attempt", attempt, "error", err, "backoff", backoff)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}
		if backoff < p.maxBackoff {
			backoff *= 2
			if backoff > p.maxBackoff {
				backoff = p.maxBackoff
			}
		}
	}
}

// rotateAfter returns how long to wait before re-signing a cert expiring at
// notAfter: two-thirds of the remaining lifetime, floored at one minute so a
// short-lived cert (or clock skew) cannot spin the rotation loop.
func (p *certProvisioner) rotateAfter(notAfter time.Time) time.Duration {
	remaining := notAfter.Sub(p.now())
	d := remaining * 2 / 3
	if d < time.Minute {
		d = time.Minute
	}
	return d
}

// rotateLoop re-signs the cert before it expires and swaps it into holder. It
// runs until ctx is cancelled. clientCA (the org root) is stable across
// rotations, so only the leaf is swapped.
func (p *certProvisioner) rotateLoop(ctx context.Context, holder *rotatingCert, notAfter time.Time) {
	for {
		wait := p.rotateAfter(notAfter)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		sc, err := p.provision(ctx)
		if err != nil {
			return // ctx cancelled
		}
		holder.set(&sc.tlsCert)
		notAfter = sc.notAfter
		p.logger.Info("server_cert_rotated", "serial", sc.serial, "not_after", notAfter.UTC())
	}
}

// selfProvisionTLSConfig blocks until the first cert is obtained, then returns a
// tls.Config whose leaf is served dynamically (so rotation is live) and starts
// the background rotation loop. ClientAuth/MinVersion match newTLSConfig.
func selfProvisionTLSConfig(ctx context.Context, logger *slog.Logger, cfg Config) (*tls.Config, error) {
	prov, err := newCertProvisioner(logger, cfg)
	if err != nil {
		return nil, err
	}
	logger.Info("server_cert_self_provision_start", "control_url", prov.controlURL, "fqdn", prov.fqdn)
	first, err := prov.provision(ctx)
	if err != nil {
		return nil, fmt.Errorf("obtain initial server cert: %w", err)
	}
	logger.Info("server_cert_self_provisioned", "serial", first.serial, "not_after", first.notAfter.UTC())

	holder := &rotatingCert{}
	holder.set(&first.tlsCert)
	go prov.rotateLoop(ctx, holder, first.notAfter)

	return &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return holder.get(), nil },
		ClientCAs:      first.clientCA,
		ClientAuth:     tls.RequireAndVerifyClientCert,
		MinVersion:     tls.VersionTLS13,
	}, nil
}
