package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/identity"
)

var b64url = base64.RawURLEncoding

func mintEd25519JWT(t *testing.T, priv ed25519.PrivateKey, claims map[string]any) string {
	t.Helper()
	hdr, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT"})
	body, _ := json.Marshal(claims)
	signingInput := b64url.EncodeToString(hdr) + "." + b64url.EncodeToString(body)
	sig := ed25519.Sign(priv, []byte(signingInput))
	return signingInput + "." + b64url.EncodeToString(sig)
}

func newWhoamiServer(t *testing.T) (*httptest.Server, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	v, err := identity.NewJWTVerifier(identity.JWTConfig{
		Issuer:          "https://idp.host.example/",
		Audience:        "orlop",
		PublicKeyPEM:    pubPEM,
		TenantClaim:     "tenant",
		TenantAllowlist: []string{"u_acme"},
	})
	if err != nil {
		t.Fatal(err)
	}
	router := newRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), runtimeDeps{hostIdentity: v}, config{})
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	return srv, priv
}

func whoamiGet(t *testing.T, srvURL, bearer string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srvURL+"/v1/whoami", nil)
	if err != nil {
		t.Fatal(err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func validClaims() map[string]any {
	return map[string]any{
		"iss":    "https://idp.host.example/",
		"aud":    "orlop",
		"sub":    "host-user-42",
		"tenant": "u_acme",
		"exp":    float64(time.Now().Add(time.Hour).Unix()),
	}
}

func TestWhoamiAcceptsValidHostJWT(t *testing.T) {
	srv, priv := newWhoamiServer(t)
	resp := whoamiGet(t, srv.URL, mintEd25519JWT(t, priv, validClaims()))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d body = %s, want 200", resp.StatusCode, body)
	}
	var got struct {
		TenantID string `json:"tenant_id"`
		Subject  string `json:"subject"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.TenantID != "u_acme" || got.Subject != "host-user-42" {
		t.Fatalf("whoami = %+v, want tenant u_acme / subject host-user-42", got)
	}
}

func TestWhoamiRejectsMissingToken(t *testing.T) {
	srv, _ := newWhoamiServer(t)
	resp := whoamiGet(t, srv.URL, "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestWhoamiRejectsTenantNotAllowed(t *testing.T) {
	srv, priv := newWhoamiServer(t)
	claims := validClaims()
	claims["tenant"] = "u_stranger"
	resp := whoamiGet(t, srv.URL, mintEd25519JWT(t, priv, claims))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestWhoamiRejectsGarbage(t *testing.T) {
	srv, _ := newWhoamiServer(t)
	resp := whoamiGet(t, srv.URL, "not-a-jwt")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

// TestWhoamiNotMountedWithoutVerifier confirms the route is absent (fail
// closed) when no verifier is configured, rather than open.
func TestWhoamiNotMountedWithoutVerifier(t *testing.T) {
	router := newRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), runtimeDeps{}, config{})
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	resp := whoamiGet(t, srv.URL, "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (route not mounted)", resp.StatusCode)
	}
}
