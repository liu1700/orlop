// Package secrets is a tiny key-value abstraction over the deploy target's
// secret store. It exists so the CA package can stay agnostic of where root
// and tenant intermediate keys live (filesystem on the operator's offline
// machine, Fly secrets / GCP Secret Manager mounted as files in production).
package secrets

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Backend is a flat key-value store. Keys use forward-slash separated
// paths like "ca/root/cert.pem". Values are opaque bytes.
type Backend interface {
	Get(ctx context.Context, key string) (value []byte, ok bool, err error)
	Put(ctx context.Context, key string, value []byte) error
	List(ctx context.Context, prefix string) (keys []string, err error)
}

// Memory is an in-process Backend, intended for tests.
type Memory struct {
	mu sync.Mutex
	m  map[string][]byte
}

func NewMemory() *Memory {
	return &Memory{m: map[string][]byte{}}
}

func (m *Memory) Get(_ context.Context, key string) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.m[key]
	if !ok {
		return nil, false, nil
	}
	return append([]byte(nil), v...), true, nil
}

func (m *Memory) Put(_ context.Context, key string, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.m[key] = append([]byte(nil), value...)
	return nil
}

func (m *Memory) List(_ context.Context, prefix string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.m))
	for k := range m.m {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out, nil
}

// Filesystem stores values under a root directory. Files are mode 0600,
// directories 0700. Used both by the offline operator workflow
// (`orlop-control ca init --root`) and by deploy targets that materialize
// secrets as files at boot.
type Filesystem struct {
	root string
}

func NewFilesystem(root string) *Filesystem {
	return &Filesystem{root: root}
}

func (f *Filesystem) Root() string { return f.root }

func (f *Filesystem) path(key string) string {
	return filepath.Join(f.root, filepath.FromSlash(key))
}

func (f *Filesystem) Get(_ context.Context, key string) ([]byte, bool, error) {
	b, err := os.ReadFile(f.path(key))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return b, true, nil
}

func (f *Filesystem) Put(_ context.Context, key string, value []byte) error {
	p := f.path(key)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, value, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

func (f *Filesystem) List(_ context.Context, prefix string) ([]string, error) {
	base := f.path(prefix)
	info, err := os.Stat(base)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	if !info.IsDir() {
		rel, err := filepath.Rel(f.root, base)
		if err != nil {
			return nil, err
		}
		return []string{filepath.ToSlash(rel)}, nil
	}
	err = filepath.WalkDir(base, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(f.root, path)
		if err != nil {
			return err
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}
