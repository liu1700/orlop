package usage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDirSize_MissingRootIsZero(t *testing.T) {
	got, err := DirSize(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatalf("DirSize: %v", err)
	}
	if got != 0 {
		t.Fatalf("got %d, want 0", got)
	}
}

func TestDirSize_EmptyDirIsZero(t *testing.T) {
	got, err := DirSize(t.TempDir())
	if err != nil {
		t.Fatalf("DirSize: %v", err)
	}
	if got != 0 {
		t.Fatalf("got %d, want 0", got)
	}
}

func TestDirSize_SumsNestedRegularFiles(t *testing.T) {
	root := t.TempDir()
	mkfile(t, filepath.Join(root, "a.bin"), 100)
	mkfile(t, filepath.Join(root, "sub", "b.bin"), 200)
	mkfile(t, filepath.Join(root, "sub", "deeper", "c.bin"), 50)
	if err := os.Symlink(filepath.Join(root, "a.bin"), filepath.Join(root, "link")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	got, err := DirSize(root)
	if err != nil {
		t.Fatalf("DirSize: %v", err)
	}
	const want = 350
	if got != want {
		t.Fatalf("got %d, want %d", got, want)
	}
}

func mkfile(t *testing.T, path string, size int) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, make([]byte, size), 0o644); err != nil {
		t.Fatal(err)
	}
}
