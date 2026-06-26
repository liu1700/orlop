package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// Encrypted wraps a Backend, sealing values at rest with AES-256-GCM. It exists
// so the CA root key + tenant intermediate keys are never stored in plaintext in
// the underlying store (e.g. Postgres). Only VALUES are encrypted; the keys (the
// slash-path strings) stay clear so List/prefix scans still work. The stored
// blob layout is: version(1) || nonce(12) || GCM ciphertext+tag. The version
// byte lets a future key rotation distinguish formats.
type Encrypted struct {
	inner Backend
	aead  cipher.AEAD
}

// encVersion tags the on-disk format. Bump if the layout/cipher changes.
const encVersion byte = 0x01

// NewEncrypted wraps inner so values are AES-256-GCM sealed with key (exactly 32
// bytes). The same key must be supplied on every boot or existing values cannot
// be read.
func NewEncrypted(inner Backend, key []byte) (*Encrypted, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("secrets: encryption key must be 32 bytes (AES-256), got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Encrypted{inner: inner, aead: aead}, nil
}

func (e *Encrypted) Get(ctx context.Context, key string) ([]byte, bool, error) {
	blob, ok, err := e.inner.Get(ctx, key)
	if err != nil || !ok {
		return nil, ok, err
	}
	pt, err := e.open(blob)
	if err != nil {
		return nil, false, fmt.Errorf("secrets decrypt %q: %w", key, err)
	}
	return pt, true, nil
}

func (e *Encrypted) Put(ctx context.Context, key string, value []byte) error {
	sealed, err := e.seal(value)
	if err != nil {
		return err
	}
	return e.inner.Put(ctx, key, sealed)
}

// List passes through: keys are not encrypted.
func (e *Encrypted) List(ctx context.Context, prefix string) ([]string, error) {
	return e.inner.List(ctx, prefix)
}

func (e *Encrypted) seal(pt []byte) ([]byte, error) {
	nonce := make([]byte, e.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	// out starts with version||nonce; Seal appends ciphertext+tag to it.
	out := make([]byte, 0, 1+len(nonce)+len(pt)+e.aead.Overhead())
	out = append(out, encVersion)
	out = append(out, nonce...)
	return e.aead.Seal(out, nonce, pt, nil), nil
}

func (e *Encrypted) open(blob []byte) ([]byte, error) {
	ns := e.aead.NonceSize()
	if len(blob) < 1+ns {
		return nil, errors.New("ciphertext too short")
	}
	if blob[0] != encVersion {
		return nil, fmt.Errorf("unknown secret version 0x%02x", blob[0])
	}
	nonce := blob[1 : 1+ns]
	return e.aead.Open(nil, nonce, blob[1+ns:], nil)
}
