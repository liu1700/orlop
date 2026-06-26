package secrets

import (
	"bytes"
	"context"
	"testing"
)

func key32(b byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b
	}
	return k
}

func TestEncrypted_RoundTrip(t *testing.T) {
	ctx := context.Background()
	mem := NewMemory()
	enc, err := NewEncrypted(mem, key32(0x11))
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("-----BEGIN EC PRIVATE KEY----- secret root key")
	if err := enc.Put(ctx, "ca/root/key.pem", plain); err != nil {
		t.Fatal(err)
	}

	// Stored bytes must NOT be the plaintext (sealed at rest).
	raw, ok, _ := mem.Get(ctx, "ca/root/key.pem")
	if !ok || bytes.Contains(raw, plain) {
		t.Fatalf("value not encrypted at rest: ok=%v raw=%q", ok, raw)
	}
	if raw[0] != encVersion {
		t.Fatalf("missing version byte, got 0x%02x", raw[0])
	}

	// Reading back through the wrapper decrypts.
	got, ok, err := enc.Get(ctx, "ca/root/key.pem")
	if err != nil || !ok {
		t.Fatalf("get: ok=%v err=%v", ok, err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round-trip mismatch: %q != %q", got, plain)
	}
}

func TestEncrypted_WrongKeyFails(t *testing.T) {
	ctx := context.Background()
	mem := NewMemory()
	enc, _ := NewEncrypted(mem, key32(0x11))
	_ = enc.Put(ctx, "k", []byte("v"))

	other, _ := NewEncrypted(mem, key32(0x22))
	if _, _, err := other.Get(ctx, "k"); err == nil {
		t.Fatal("expected decrypt failure with the wrong key")
	}
}

func TestEncrypted_ListPassThrough(t *testing.T) {
	ctx := context.Background()
	mem := NewMemory()
	enc, _ := NewEncrypted(mem, key32(0x33))
	_ = enc.Put(ctx, "ca/tenant/a1/key.pem", []byte("x"))
	_ = enc.Put(ctx, "ca/tenant/a2/key.pem", []byte("y"))
	keys, err := enc.List(ctx, "ca/tenant/")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("want 2 keys, got %v", keys)
	}
}

func TestNewEncrypted_BadKeyLen(t *testing.T) {
	if _, err := NewEncrypted(NewMemory(), make([]byte, 16)); err == nil {
		t.Fatal("expected error for non-32-byte key")
	}
}
