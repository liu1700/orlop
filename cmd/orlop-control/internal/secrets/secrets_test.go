package secrets

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestMemoryRoundTrip(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()

	if _, ok, err := m.Get(ctx, "missing"); err != nil || ok {
		t.Fatalf("missing key: ok=%v err=%v", ok, err)
	}
	if err := m.Put(ctx, "a/b", []byte("hello")); err != nil {
		t.Fatal(err)
	}
	v, ok, err := m.Get(ctx, "a/b")
	if err != nil || !ok || string(v) != "hello" {
		t.Fatalf("roundtrip: ok=%v v=%q err=%v", ok, v, err)
	}

	v[0] = 'X'
	v2, _, _ := m.Get(ctx, "a/b")
	if string(v2) != "hello" {
		t.Fatalf("Get must return a copy; got %q", v2)
	}
}

func TestMemoryListByPrefix(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	for _, k := range []string{"ca/root/cert.pem", "ca/root/key.pem", "ca/tenant/a/cert.pem", "other/x"} {
		if err := m.Put(ctx, k, []byte("v")); err != nil {
			t.Fatal(err)
		}
	}
	got, err := m.List(ctx, "ca/")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"ca/root/cert.pem", "ca/root/key.pem", "ca/tenant/a/cert.pem"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("List: got %v want %v", got, want)
	}
}

func TestFilesystemRoundTrip(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	f := NewFilesystem(dir)

	if _, ok, err := f.Get(ctx, "missing"); err != nil || ok {
		t.Fatalf("missing: ok=%v err=%v", ok, err)
	}
	if err := f.Put(ctx, "ca/root/cert.pem", []byte("PEM")); err != nil {
		t.Fatal(err)
	}
	v, ok, err := f.Get(ctx, "ca/root/cert.pem")
	if err != nil || !ok || string(v) != "PEM" {
		t.Fatalf("roundtrip: ok=%v v=%q err=%v", ok, v, err)
	}

	info, err := os.Stat(filepath.Join(dir, "ca", "root", "cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("file mode = %o, want 0600", mode)
	}
}

func TestFilesystemList(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	f := NewFilesystem(dir)
	for _, k := range []string{
		"ca/root/cert.pem",
		"ca/root/key.pem",
		"ca/tenant/a/cert.pem",
		"ca/tenant/a/key.pem",
		"ca/tenant/b/cert.pem",
	} {
		if err := f.Put(ctx, k, []byte("v")); err != nil {
			t.Fatal(err)
		}
	}
	got, err := f.List(ctx, "ca/tenant/")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"ca/tenant/a/cert.pem",
		"ca/tenant/a/key.pem",
		"ca/tenant/b/cert.pem",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("List: got %v want %v", got, want)
	}

	if got, err := f.List(ctx, "missing-prefix/"); err != nil || got != nil {
		t.Fatalf("missing prefix: got=%v err=%v", got, err)
	}
}
