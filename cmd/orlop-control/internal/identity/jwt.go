package identity

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// clockLeeway absorbs small clock skew between the host IdP and orlop when
// checking exp/nbf/iat.
const clockLeeway = 60 * time.Second

// JWTConfig configures the Mode B verifier: verify a host-issued, signed JWT
// and map an allowlisted claim onto the tenant subject. See
// docs/design-identity.md §3 Mode B.
type JWTConfig struct {
	// Issuer, when non-empty, is required to equal the token `iss`.
	Issuer string
	// Audience is required to be present in the token `aud`. Pinning `aud`
	// stops a token minted for another verifier from being accepted here.
	Audience string
	// PublicKeyPEM is the PKIX/SPKI public key the token signature is checked
	// against (RSA, ECDSA P-256, or Ed25519). Required.
	//
	// A static key is the first cut; a `jwks_uri` with rotation is a follow-up
	// (the signing-key plumbing is isolated to parsePublicKey + verifySignature).
	PublicKeyPEM []byte
	// TenantClaim is the claim whose (string) value becomes the tenant subject.
	// Defaults to "tenant".
	TenantClaim string
	// TenantAllowlist is fail-closed: only these tenant ids may be provisioned.
	// A verifier with an empty allowlist rejects every token (construction
	// returns an error) so a misconfiguration cannot self-onboard tenants.
	TenantAllowlist []string
}

// JWTVerifier is the built-in Mode B Verifier.
type JWTVerifier struct {
	issuer      string
	audience    string
	pub         crypto.PublicKey
	tenantClaim string
	allow       map[string]struct{}
	now         func() time.Time
}

var _ Verifier = (*JWTVerifier)(nil)

// NewJWTVerifier builds a JWTVerifier, validating configuration up front.
func NewJWTVerifier(cfg JWTConfig) (*JWTVerifier, error) {
	if cfg.Audience == "" {
		return nil, fmt.Errorf("identity: audience is required (pin aud)")
	}
	if len(cfg.TenantAllowlist) == 0 {
		return nil, fmt.Errorf("identity: tenant allowlist is required (fail-closed)")
	}
	pub, err := parsePublicKey(cfg.PublicKeyPEM)
	if err != nil {
		return nil, err
	}
	allow := make(map[string]struct{}, len(cfg.TenantAllowlist))
	for _, t := range cfg.TenantAllowlist {
		if t = strings.TrimSpace(t); t != "" {
			allow[t] = struct{}{}
		}
	}
	if len(allow) == 0 {
		return nil, fmt.Errorf("identity: tenant allowlist is required (fail-closed)")
	}
	claim := cfg.TenantClaim
	if claim == "" {
		claim = "tenant"
	}
	return &JWTVerifier{
		issuer:      cfg.Issuer,
		audience:    cfg.Audience,
		pub:         pub,
		tenantClaim: claim,
		allow:       allow,
		now:         time.Now,
	}, nil
}

func parsePublicKey(pemBytes []byte) (crypto.PublicKey, error) {
	if len(pemBytes) == 0 {
		return nil, fmt.Errorf("identity: public key is required")
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("identity: public key is not valid PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("identity: parse public key: %w", err)
	}
	switch pub.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
		return pub, nil
	default:
		return nil, fmt.Errorf("identity: unsupported public key type %T", pub)
	}
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// Verify implements Verifier for the JWT (Mode B) path.
func (v *JWTVerifier) Verify(_ context.Context, info AuthInfo) (Identity, error) {
	raw := strings.TrimSpace(info.Bearer)
	if raw == "" {
		return Identity{}, ErrNoCredential
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return Identity{}, ErrMalformedToken
	}
	headerBytes, err := b64.DecodeString(parts[0])
	if err != nil {
		return Identity{}, ErrMalformedToken
	}
	var hdr jwtHeader
	if err := json.Unmarshal(headerBytes, &hdr); err != nil {
		return Identity{}, ErrMalformedToken
	}
	// Bind the accepted algorithm to the configured key type. This is the
	// defense against the JWS algorithm-confusion attack (e.g. a token with
	// alg=HS256 signed using the RSA public key as the HMAC secret): we never
	// pick the verification routine from the attacker-controlled header alone.
	if err := v.checkAlg(hdr.Alg); err != nil {
		return Identity{}, err
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return Identity{}, ErrMalformedToken
	}
	signingInput := []byte(parts[0] + "." + parts[1])
	if err := v.verifySignature(signingInput, sig); err != nil {
		return Identity{}, err
	}

	payload, err := b64.DecodeString(parts[1])
	if err != nil {
		return Identity{}, ErrMalformedToken
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return Identity{}, ErrMalformedToken
	}
	if err := v.validateClaims(claims); err != nil {
		return Identity{}, err
	}

	tenant, ok := claims[v.tenantClaim].(string)
	if !ok || tenant == "" {
		return Identity{}, ErrTenantClaimMissing
	}
	if _, ok := v.allow[tenant]; !ok {
		return Identity{}, ErrTenantNotAllowed
	}
	sub, _ := claims["sub"].(string)
	return Identity{TenantID: tenant, Subject: sub, Claims: claims}, nil
}

func (v *JWTVerifier) checkAlg(alg string) error {
	switch v.pub.(type) {
	case *rsa.PublicKey:
		if alg != "RS256" {
			return ErrUnsupportedAlg
		}
	case *ecdsa.PublicKey:
		if alg != "ES256" {
			return ErrUnsupportedAlg
		}
	case ed25519.PublicKey:
		if alg != "EdDSA" {
			return ErrUnsupportedAlg
		}
	default:
		return ErrUnsupportedAlg
	}
	return nil
}

func (v *JWTVerifier) verifySignature(signingInput, sig []byte) error {
	switch pub := v.pub.(type) {
	case *rsa.PublicKey:
		h := sha256.Sum256(signingInput)
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig); err != nil {
			return ErrBadSignature
		}
		return nil
	case *ecdsa.PublicKey:
		// JWS ES256 signatures are the fixed-width R||S concatenation, not the
		// ASN.1 DER ecdsa.Verify expects, so split and verify the halves.
		if len(sig) != 64 {
			return ErrBadSignature
		}
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		h := sha256.Sum256(signingInput)
		if !ecdsa.Verify(pub, h[:], r, s) {
			return ErrBadSignature
		}
		return nil
	case ed25519.PublicKey:
		if !ed25519.Verify(pub, signingInput, sig) {
			return ErrBadSignature
		}
		return nil
	default:
		return ErrUnsupportedAlg
	}
}

func (v *JWTVerifier) validateClaims(claims map[string]any) error {
	if v.issuer != "" {
		if iss, _ := claims["iss"].(string); iss != v.issuer {
			return ErrClaimsInvalid
		}
	}
	if !audienceContains(claims["aud"], v.audience) {
		return ErrClaimsInvalid
	}
	now := v.now()
	if exp, ok := numericDate(claims["exp"]); ok {
		if now.After(exp.Add(clockLeeway)) {
			return ErrClaimsInvalid
		}
	} else {
		// exp is required: a token with no expiry is not acceptable.
		return ErrClaimsInvalid
	}
	if nbf, ok := numericDate(claims["nbf"]); ok {
		if now.Add(clockLeeway).Before(nbf) {
			return ErrClaimsInvalid
		}
	}
	return nil
}

// audienceContains handles the `aud` claim, which RFC 7519 allows to be either
// a string or an array of strings.
func audienceContains(aud any, want string) bool {
	switch a := aud.(type) {
	case string:
		return a == want
	case []any:
		for _, item := range a {
			if s, ok := item.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

// numericDate parses a JWT NumericDate (seconds since the epoch, JSON number).
func numericDate(v any) (time.Time, bool) {
	f, ok := v.(float64)
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(int64(f), 0), true
}

var b64 = base64.RawURLEncoding
