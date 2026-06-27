package identity

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"
)

// signJWT mints a compact JWS for the given alg/key/claims. Used only by tests
// to stand in for a host IdP.
func signJWT(t *testing.T, alg string, key crypto.Signer, claims map[string]any) string {
	t.Helper()
	hdr, _ := json.Marshal(map[string]string{"alg": alg, "typ": "JWT"})
	body, _ := json.Marshal(claims)
	signingInput := b64.EncodeToString(hdr) + "." + b64.EncodeToString(body)
	var sig []byte
	switch alg {
	case "RS256":
		h := sha256.Sum256([]byte(signingInput))
		s, err := key.Sign(rand.Reader, h[:], crypto.SHA256)
		if err != nil {
			t.Fatal(err)
		}
		sig = s
	case "ES256":
		h := sha256.Sum256([]byte(signingInput))
		r, s, err := ecdsa.Sign(rand.Reader, key.(*ecdsa.PrivateKey), h[:])
		if err != nil {
			t.Fatal(err)
		}
		sig = make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
	case "EdDSA":
		sig = ed25519.Sign(key.(ed25519.PrivateKey), []byte(signingInput))
	default:
		t.Fatalf("unsupported test alg %q", alg)
	}
	return signingInput + "." + b64.EncodeToString(sig)
}

func pubPEM(t *testing.T, pub crypto.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func baseClaims() map[string]any {
	return map[string]any{
		"iss":    "https://idp.host.example/",
		"aud":    "orlop",
		"sub":    "host-user-42",
		"tenant": "u_acme",
		"exp":    float64(time.Now().Add(time.Hour).Unix()),
		"nbf":    float64(time.Now().Add(-time.Minute).Unix()),
	}
}

func newVerifier(t *testing.T, pub crypto.PublicKey) *JWTVerifier {
	t.Helper()
	v, err := NewJWTVerifier(JWTConfig{
		Issuer:          "https://idp.host.example/",
		Audience:        "orlop",
		PublicKeyPEM:    pubPEM(t, pub),
		TenantClaim:     "tenant",
		TenantAllowlist: []string{"u_acme", "u_globex"},
	})
	if err != nil {
		t.Fatalf("NewJWTVerifier: %v", err)
	}
	return v
}

func TestJWTVerifyAcceptsAllThreeAlgs(t *testing.T) {
	ed25519Pub, ed25519Priv, _ := ed25519.GenerateKey(rand.Reader)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	cases := []struct {
		name string
		alg  string
		pub  crypto.PublicKey
		key  crypto.Signer
	}{
		{"EdDSA", "EdDSA", ed25519Pub, ed25519Priv},
		{"ES256", "ES256", &ecKey.PublicKey, ecKey},
		{"RS256", "RS256", &rsaKey.PublicKey, rsaKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := newVerifier(t, tc.pub)
			tok := signJWT(t, tc.alg, tc.key, baseClaims())
			id, err := v.Verify(context.Background(), AuthInfo{Bearer: tok})
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if id.TenantID != "u_acme" {
				t.Fatalf("tenant = %q, want u_acme", id.TenantID)
			}
			if id.Subject != "host-user-42" {
				t.Fatalf("subject = %q, want host-user-42", id.Subject)
			}
		})
	}
}

func TestJWTVerifyRejections(t *testing.T) {
	ed25519Pub, ed25519Priv, _ := ed25519.GenerateKey(rand.Reader)

	cases := []struct {
		name   string
		mutate func(map[string]any)
		want   error
	}{
		{"wrong issuer", func(c map[string]any) { c["iss"] = "https://evil.example/" }, ErrClaimsInvalid},
		{"wrong audience", func(c map[string]any) { c["aud"] = "someone-else" }, ErrClaimsInvalid},
		{"expired", func(c map[string]any) { c["exp"] = float64(time.Now().Add(-time.Hour).Unix()) }, ErrClaimsInvalid},
		{"not yet valid", func(c map[string]any) { c["nbf"] = float64(time.Now().Add(time.Hour).Unix()) }, ErrClaimsInvalid},
		{"missing exp", func(c map[string]any) { delete(c, "exp") }, ErrClaimsInvalid},
		{"tenant not allowed", func(c map[string]any) { c["tenant"] = "u_stranger" }, ErrTenantNotAllowed},
		{"tenant claim missing", func(c map[string]any) { delete(c, "tenant") }, ErrTenantClaimMissing},
		{"tenant claim not string", func(c map[string]any) { c["tenant"] = 42.0 }, ErrTenantClaimMissing},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := newVerifier(t, ed25519Pub)
			claims := baseClaims()
			tc.mutate(claims)
			tok := signJWT(t, "EdDSA", ed25519Priv, claims)
			_, err := v.Verify(context.Background(), AuthInfo{Bearer: tok})
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestJWTVerifyRejectsBadSignature(t *testing.T) {
	ed25519Pub, ed25519Priv, _ := ed25519.GenerateKey(rand.Reader)
	v := newVerifier(t, ed25519Pub)
	tok := signJWT(t, "EdDSA", ed25519Priv, baseClaims())
	// Corrupt a byte near the START of the signature segment. Flipping the
	// trailing base64 chars is unreliable — the final char carries only ~2
	// significant bits, so an Ed25519 signature can survive the change and the
	// token still verifies; mutating the first sig char always alters byte 0.
	b := []byte(tok)
	sigStart := strings.LastIndexByte(tok, '.') + 1
	if b[sigStart] == 'A' {
		b[sigStart] = 'B'
	} else {
		b[sigStart] = 'A'
	}
	tok = string(b)
	if _, err := v.Verify(context.Background(), AuthInfo{Bearer: tok}); !errors.Is(err, ErrBadSignature) && !errors.Is(err, ErrMalformedToken) {
		t.Fatalf("err = %v, want bad signature/malformed", err)
	}
}

// TestJWTVerifyRejectsAlgConfusion pins the defense against the classic JWS
// alg-confusion attack: a token whose header claims a symmetric alg must be
// rejected, never verified by reinterpreting the configured asymmetric key.
func TestJWTVerifyRejectsAlgConfusion(t *testing.T) {
	ed25519Pub, _, _ := ed25519.GenerateKey(rand.Reader)
	v := newVerifier(t, ed25519Pub)

	hdr, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	body, _ := json.Marshal(baseClaims())
	signingInput := b64.EncodeToString(hdr) + "." + b64.EncodeToString(body)
	// Forge an HMAC using the (public) Ed25519 key bytes as the shared secret —
	// the move a confused verifier would fall for.
	forged := "deadbeef"
	tok := signingInput + "." + base64.RawURLEncoding.EncodeToString([]byte(forged))
	if _, err := v.Verify(context.Background(), AuthInfo{Bearer: tok}); !errors.Is(err, ErrUnsupportedAlg) {
		t.Fatalf("err = %v, want ErrUnsupportedAlg", err)
	}
}

func TestJWTVerifyMalformed(t *testing.T) {
	ed25519Pub, _, _ := ed25519.GenerateKey(rand.Reader)
	v := newVerifier(t, ed25519Pub)
	for _, tok := range []string{"", "not-a-jwt", "a.b", "a.b.c.d"} {
		if _, err := v.Verify(context.Background(), AuthInfo{Bearer: tok}); err == nil {
			t.Fatalf("Verify(%q) = nil err, want error", tok)
		}
	}
}

func TestNewJWTVerifierConfigValidation(t *testing.T) {
	ed25519Pub, _, _ := ed25519.GenerateKey(rand.Reader)
	pem := pubPEM(t, ed25519Pub)

	if _, err := NewJWTVerifier(JWTConfig{Audience: "orlop", PublicKeyPEM: pem}); err == nil {
		t.Fatal("want error: empty allowlist must fail closed")
	}
	if _, err := NewJWTVerifier(JWTConfig{PublicKeyPEM: pem, TenantAllowlist: []string{"u_acme"}}); err == nil {
		t.Fatal("want error: missing audience must fail")
	}
	if _, err := NewJWTVerifier(JWTConfig{Audience: "orlop", TenantAllowlist: []string{"u_acme"}}); err == nil {
		t.Fatal("want error: missing public key must fail")
	}
}
