package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadConfigReadsMTLSSettings(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "server.yaml")
	mustWriteFile(t, path, `
audit_log: ./audit.log
store:
  type: local
  root: ./store
routes:
  type: sqlite
  path: ./routes.db
tenant:
  id: tenant-a
server:
  ops_bind: 127.0.0.1:7878
tls:
  cert_file: ./server.crt
  key_file: ./server.key
  client_ca_file: ./client-ca.crt
policy:
  readonly: true
`)

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.OpsBind != "127.0.0.1:7878" {
		t.Errorf("OpsBind = %q", cfg.OpsBind)
	}
	if cfg.TLSCertFile != absOrSelf("./server.crt") {
		t.Errorf("TLSCertFile = %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != absOrSelf("./server.key") {
		t.Errorf("TLSKeyFile = %q", cfg.TLSKeyFile)
	}
	if cfg.TLSClientCA != absOrSelf("./client-ca.crt") {
		t.Errorf("TLSClientCA = %q", cfg.TLSClientCA)
	}
	if cfg.TenantID != "tenant-a" {
		t.Errorf("TenantID = %q", cfg.TenantID)
	}
	if len(cfg.Tenants) != 1 || cfg.Tenants[0].ID != "tenant-a" {
		t.Errorf("Tenants = %#v", cfg.Tenants)
	}
}

func TestNewTLSConfigRequiresClientCerts(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	certFile, keyFile, caFile := writeTestCerts(t, dir)
	cfg := Config{
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
		TLSClientCA: caFile,
	}
	tlsConfig, err := newTLSConfig(cfg)
	if err != nil {
		t.Fatalf("newTLSConfig: %v", err)
	}
	if tlsConfig.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth = %v", tlsConfig.ClientAuth)
	}
	if tlsConfig.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %x", tlsConfig.MinVersion)
	}
	if tlsConfig.ClientCAs == nil {
		t.Errorf("ClientCAs is nil")
	}
	if len(tlsConfig.Certificates) != 1 {
		t.Errorf("Certificates length = %d", len(tlsConfig.Certificates))
	}
}

func TestCertIdentifierUsesPeerCommonName(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{
			Subject:      pkix.Name{CommonName: "agent@example.com"},
			SerialNumber: big.NewInt(42),
			URIs:         []*url.URL{mustParseURL(t, "spiffe://orlop.example/tenant/tenant-a")},
		}},
	}

	id, err := (certIdentifier{trustDomain: "orlop.example"}).Identify(req)
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if id.AgentID != "agent@example.com" {
		t.Errorf("AgentID = %q", id.AgentID)
	}
	if id.TenantID != "tenant-a" {
		t.Errorf("TenantID = %q", id.TenantID)
	}
	if id.CertSerial != "42" {
		t.Errorf("CertSerial = %q", id.CertSerial)
	}
}

func TestCertIdentifierRejectsMissingTenantSAN(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{
			Subject: pkix.Name{CommonName: "agent@example.com"},
		}},
	}

	if _, err := (certIdentifier{trustDomain: "orlop.example"}).Identify(req); err == nil {
		t.Fatalf("Identify error = nil, want tenant identity error")
	}
}

func TestCertIdentifierRejectsMissingPeerCert(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	if _, err := (certIdentifier{trustDomain: "orlop.example"}).Identify(req); err != ErrNoIdentity {
		t.Fatalf("Identify error = %v, want ErrNoIdentity", err)
	}
}

func TestHealthzRequiresIdentity(t *testing.T) {
	state := newTestState(t, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req = req.WithContext(WithIdentity(context.Background(), testIdentity()))
	rr := httptest.NewRecorder()

	newRouter(state).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	if rr.Body.String() != "ok\n" {
		t.Errorf("body = %q", rr.Body.String())
	}
}

func TestTenantCertForConfiguredTenantAllowed(t *testing.T) {
	state := newTestState(t, nil, nil)
	state.identifier = certIdentifier{trustDomain: "orlop.example"}

	rr := doMTLSRequest(t, state, "tenant-a")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
}

func TestTenantCertForDifferentTenantRejectedAndAudited(t *testing.T) {
	state := newTestState(t, nil, nil)
	state.identifier = certIdentifier{trustDomain: "orlop.example"}

	rr := doMTLSRequest(t, state, "tenant-b")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	if err := state.audit.file.Sync(); err != nil {
		t.Fatalf("sync: %v", err)
	}
	events := readAuditEvents(t, state.audit.Path())
	last := events[len(events)-1]
	if last["allowed"] != false {
		t.Errorf("allowed = %v", last["allowed"])
	}
	if last["tenant_id"] != "tenant-b" {
		t.Errorf("tenant_id = %v", last["tenant_id"])
	}
	if last["cert_serial"] != "99" {
		t.Errorf("cert_serial = %v", last["cert_serial"])
	}
}

func TestCertWithoutTenantSANRejected(t *testing.T) {
	state := newTestState(t, nil, nil)
	state.identifier = certIdentifier{trustDomain: "orlop.example"}
	req := httptest.NewRequest(http.MethodGet, "/audit", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{
			Subject:      pkix.Name{CommonName: testAgent},
			SerialNumber: big.NewInt(100),
		}},
	}
	rr := httptest.NewRecorder()

	newRouter(state).ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
}

func doMTLSRequest(t *testing.T, state *serverState, tenantID string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/audit", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{
			Subject:      pkix.Name{CommonName: testAgent},
			SerialNumber: big.NewInt(99),
			URIs:         []*url.URL{mustParseURL(t, "spiffe://orlop.example/tenant/"+tenantID)},
		}},
	}
	rr := httptest.NewRecorder()
	newRouter(state).ServeHTTP(rr, req)
	return rr
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse URL %s: %v", raw, err)
	}
	return u
}

func writeTestCerts(t *testing.T, dir string) (certFile, keyFile, caFile string) {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "tenant-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}

	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caTemplate, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}

	certFile = filepath.Join(dir, "server.crt")
	keyFile = filepath.Join(dir, "server.key")
	caFile = filepath.Join(dir, "client-ca.crt")
	writePEM(t, certFile, "CERTIFICATE", serverDER)
	writePEM(t, caFile, "CERTIFICATE", caDER)
	writePEM(t, keyFile, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(serverKey))
	return certFile, keyFile, caFile
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	defer file.Close()
	if err := pem.Encode(file, &pem.Block{Type: typ, Bytes: der}); err != nil {
		t.Fatalf("write PEM %s: %v", path, err)
	}
}
