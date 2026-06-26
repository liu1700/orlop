// Package tokens generates and hashes Orlop API tokens.
//
// Tokens have the shape "orlop_" + base32(24 random bytes), no padding,
// lowercase. The "orlop_" prefix is intentionally grep-able so leaked
// tokens can be detected in logs and commits. Tokens are stored in the
// database as their SHA-256 hex hash; the raw value is shown to the
// user only once on creation.
package tokens

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"strings"
)

const (
	rawBytes  = 24
	prefixLen = 12
)

// Prefix is the literal "orlop_" prefix that every API token starts with.
// Exported so callers (e.g. middleware) don't have to hardcode the string.
const Prefix = "orlop_"

// RawToken bundles a freshly generated token with its derived storage fields.
type RawToken struct {
	Raw    string // "orlop_..." — show to user once, never store
	Hash   string // SHA-256 hex of Raw — what the database stores
	Prefix string // first 12 chars of Raw — for display
}

// lowerNoPad is base32 without padding, lowercased on output. Standard
// base32 is uppercase; we lower-case for visual consistency with other
// modern API tokens (`sk_*`, `ghp_*`, etc.).
var lowerNoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

// Generate produces a new RawToken using crypto/rand.
func Generate() (RawToken, error) {
	buf := make([]byte, rawBytes)
	if _, err := rand.Read(buf); err != nil {
		return RawToken{}, err
	}
	body := strings.ToLower(lowerNoPad.EncodeToString(buf))
	raw := Prefix + body
	return RawToken{
		Raw:    raw,
		Hash:   Hash(raw),
		Prefix: raw[:prefixLen],
	}, nil
}

// Hash returns the SHA-256 hex digest of raw. It is the only form that
// should be persisted.
func Hash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
