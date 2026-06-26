package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/ca"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/secrets"
)

func testServerCertCA(t *testing.T) *ca.CA {
	t.Helper()
	c, err := ca.LoadOrInit(context.Background(), secrets.NewMemory(), ca.Env{
		TrustDomain: "test.example",
		OrgName:     "Test",
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func serverCertRouter(t *testing.T, c *ca.CA, token string) http.Handler {
	t.Helper()
	r := chi.NewRouter()
	mountServerCert(r, RequireServiceToken(token),
		newServerCertHandlers(slog.New(slog.NewTextHandler(io.Discard, nil)), c, "orlop-server", time.Hour))
	return r
}

// makeCSRPEM builds an ed25519 server CSR and returns its PEM plus the public key.
func makeCSRPEM(t *testing.T, cn string) (string, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: []string{cn},
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), pub
}

func doSignServerCert(t *testing.T, h http.Handler, auth, body string) *httptest.ResponseRecorder {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(http.MethodPost, "/control/sign-server-cert", rdr)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestSignServerCertHandlerIssuesServerAuthLeaf(t *testing.T) {
	const token = "svc-secret"
	c := testServerCertCA(t)
	h := serverCertRouter(t, c, token)

	csrPEM, pub := makeCSRPEM(t, "orlop-server")
	body, _ := json.Marshal(signServerCertRequest{CSRPEM: csrPEM})
	rec := doSignServerCert(t, h, "Bearer "+token, string(body))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var resp signServerCertResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Serial == "" || resp.ExpiresAt == "" {
		t.Fatalf("missing serial/expires_at: %+v", resp)
	}

	block, _ := pem.Decode([]byte(resp.CertPEM))
	if block == nil {
		t.Fatal("cert_pem not PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != "orlop-server" {
		t.Fatalf("CN = %q", leaf.Subject.CommonName)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "orlop-server" {
		t.Fatalf("DNSNames = %v", leaf.DNSNames)
	}
	// The server keeps its key — the cert must carry the CSR's public key.
	leafPub, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok || !leafPub.Equal(pub) {
		t.Fatal("leaf public key does not match CSR")
	}

	// client_ca_pem must be the org root and verify the leaf as server-auth.
	if string(c.RootPEM()) != resp.ClientCAPEM {
		t.Fatal("client_ca_pem is not the org root")
	}
	rootPool := x509.NewCertPool()
	if !rootPool.AppendCertsFromPEM([]byte(resp.ClientCAPEM)) {
		t.Fatal("client_ca_pem has no certs")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     rootPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSName:   "orlop-server",
	}); err != nil {
		t.Fatalf("verify leaf as server-auth against client CA: %v", err)
	}
}

func TestSignServerCertHandlerRejects(t *testing.T) {
	const token = "svc-secret"
	c := testServerCertCA(t)
	h := serverCertRouter(t, c, token)
	csrPEM, _ := makeCSRPEM(t, "orlop-server")
	goodBody := func() string {
		b, _ := json.Marshal(signServerCertRequest{CSRPEM: csrPEM})
		return string(b)
	}()

	t.Run("bad token", func(t *testing.T) {
		rec := doSignServerCert(t, h, "Bearer wrong", goodBody)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d", rec.Code)
		}
	})
	t.Run("missing token", func(t *testing.T) {
		rec := doSignServerCert(t, h, "", goodBody)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d", rec.Code)
		}
	})
	t.Run("fqdn not allowed", func(t *testing.T) {
		b, _ := json.Marshal(signServerCertRequest{CSRPEM: csrPEM, FQDN: "evil.example"})
		rec := doSignServerCert(t, h, "Bearer "+token, string(b))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("garbage csr", func(t *testing.T) {
		b, _ := json.Marshal(signServerCertRequest{CSRPEM: "not a pem"})
		rec := doSignServerCert(t, h, "Bearer "+token, string(b))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d", rec.Code)
		}
	})
	t.Run("malformed body", func(t *testing.T) {
		rec := doSignServerCert(t, h, "Bearer "+token, "{not json")
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d", rec.Code)
		}
	})
	t.Run("explicit allowed fqdn ok", func(t *testing.T) {
		b, _ := json.Marshal(signServerCertRequest{CSRPEM: csrPEM, FQDN: "orlop-server"})
		rec := doSignServerCert(t, h, "Bearer "+token, string(b))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}
