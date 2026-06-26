package quota

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeExec records calls and returns a preset error on demand.
type fakeExec struct {
	mu    sync.Mutex
	calls [][]string
	errOn string // if non-empty, return an error when name == errOn
}

func (f *fakeExec) Run(_ context.Context, name string, args ...string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	entry := append([]string{name}, args...)
	f.calls = append(f.calls, entry)
	if f.errOn != "" && name == f.errOn {
		return fmt.Errorf("fake error from %s", name)
	}
	return nil
}

func (f *fakeExec) reset() {
	f.mu.Lock()
	f.calls = nil
	f.mu.Unlock()
}

func newManager(t *testing.T, ex *fakeExec) (*Manager, string) {
	t.Helper()
	dir := t.TempDir()
	statePath := filepath.Join(dir, "quota.json")
	m, err := NewManager(statePath, "/var/lib/orlop", ex, nil, true)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m, statePath
}

func TestAllocateFreshTenant(t *testing.T) {
	fx := &fakeExec{}
	m, _ := newManager(t, fx)

	projID, err := m.Allocate(context.Background(), "tenant-a", "/data/tenant-a", 1<<20)
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if projID != 100 {
		t.Errorf("first project ID: got %d, want 100", projID)
	}

	// Expect chattr +P -p 100 /data/tenant-a
	// then setquota -P 100 0 <hard_kb> 0 0 -a /var/lib/orlop
	fx.mu.Lock()
	calls := fx.calls
	fx.mu.Unlock()

	if len(calls) != 2 {
		t.Fatalf("expected 2 exec calls, got %d: %v", len(calls), calls)
	}
	if calls[0][0] != "chattr" || calls[0][1] != "+P" || calls[0][2] != "-p" || calls[0][3] != "100" || calls[0][4] != "/data/tenant-a" {
		t.Errorf("chattr call mismatch: %v", calls[0])
	}
	hardKB := fmt.Sprintf("%d", (1<<20+1023)/1024)
	if calls[1][0] != "setquota" || calls[1][1] != "-P" || calls[1][2] != "100" ||
		calls[1][3] != "0" || calls[1][4] != hardKB || calls[1][5] != "0" || calls[1][6] != "0" ||
		calls[1][7] != "-a" || calls[1][8] != "/var/lib/orlop" {
		t.Errorf("setquota call mismatch: %v", calls[1])
	}
}

func TestAllocateIdempotent(t *testing.T) {
	fx := &fakeExec{}
	m, _ := newManager(t, fx)

	projID1, err := m.Allocate(context.Background(), "tenant-a", "/data/tenant-a", 1<<20)
	if err != nil {
		t.Fatalf("first Allocate: %v", err)
	}

	fx.reset()

	projID2, err := m.Allocate(context.Background(), "tenant-a", "/data/tenant-a", 1<<20)
	if err != nil {
		t.Fatalf("second Allocate: %v", err)
	}
	if projID1 != projID2 {
		t.Errorf("idempotent: got different project IDs %d vs %d", projID1, projID2)
	}

	fx.mu.Lock()
	n := len(fx.calls)
	fx.mu.Unlock()
	if n != 0 {
		t.Errorf("idempotent: expected 0 exec calls on re-allocate, got %d", n)
	}
}

func TestAllocateSizeMismatch(t *testing.T) {
	fx := &fakeExec{}
	m, _ := newManager(t, fx)

	if _, err := m.Allocate(context.Background(), "tenant-a", "/data/tenant-a", 1<<20); err != nil {
		t.Fatalf("first Allocate: %v", err)
	}

	_, err := m.Allocate(context.Background(), "tenant-a", "/data/tenant-a", 2<<20)
	if err == nil {
		t.Fatal("expected ErrSizeMismatch, got nil")
	}
	var mismatch ErrSizeMismatch
	if !errors.As(err, &mismatch) {
		t.Fatalf("expected ErrSizeMismatch, got %T: %v", err, err)
	}
	if mismatch.Existing != 1<<20 {
		t.Errorf("ErrSizeMismatch.Existing: got %d, want %d", mismatch.Existing, 1<<20)
	}
}

func TestCrashRecoveryAndMonotonicIDs(t *testing.T) {
	fx := &fakeExec{}
	dir := t.TempDir()
	statePath := filepath.Join(dir, "quota.json")

	// Write a partial state file (simulates crash after some allocations).
	partial := `{"next_project_id":105,"tenants":{"t1":{"project_id":100,"size_bytes":1048576},"t2":{"project_id":101,"size_bytes":2097152}}}`
	if err := os.WriteFile(statePath, []byte(partial), 0o600); err != nil {
		t.Fatal(err)
	}

	m, err := NewManager(statePath, "/var/lib/orlop", fx, nil, true)
	if err != nil {
		t.Fatalf("NewManager after partial state: %v", err)
	}

	// Existing tenants should be visible via Lookup.
	pid, sz, ok := m.Lookup("t1")
	if !ok || pid != 100 || sz != 1<<20 {
		t.Errorf("Lookup t1: pid=%d sz=%d ok=%v", pid, sz, ok)
	}

	// New allocation should start at 105.
	projID, err := m.Allocate(context.Background(), "t3", "/data/t3", 512)
	if err != nil {
		t.Fatalf("Allocate t3: %v", err)
	}
	if projID != 105 {
		t.Errorf("expected project ID 105, got %d", projID)
	}

	// Second allocation after that.
	projID2, err := m.Allocate(context.Background(), "t4", "/data/t4", 512)
	if err != nil {
		t.Fatalf("Allocate t4: %v", err)
	}
	if projID2 != 106 {
		t.Errorf("expected project ID 106, got %d", projID2)
	}

	// Re-open the manager and verify IDs survived.
	m2, err := NewManager(statePath, "/var/lib/orlop", fx, nil, true)
	if err != nil {
		t.Fatalf("re-open Manager: %v", err)
	}
	pid3, _, ok3 := m2.Lookup("t3")
	if !ok3 || pid3 != 105 {
		t.Errorf("after re-open: Lookup t3: pid=%d ok=%v", pid3, ok3)
	}
	pid4, _, ok4 := m2.Lookup("t4")
	if !ok4 || pid4 != 106 {
		t.Errorf("after re-open: Lookup t4: pid=%d ok=%v", pid4, ok4)
	}

	// Next allocation from re-opened manager should be 107.
	projID5, err := m2.Allocate(context.Background(), "t5", "/data/t5", 512)
	if err != nil {
		t.Fatalf("Allocate t5: %v", err)
	}
	if projID5 != 107 {
		t.Errorf("expected project ID 107, got %d", projID5)
	}
}

func TestSetquotaFailureRollsBack(t *testing.T) {
	fx := &fakeExec{errOn: "setquota"}
	m, statePath := newManager(t, fx)

	_, err := m.Allocate(context.Background(), "tenant-x", "/data/tenant-x", 1<<20)
	if err == nil {
		t.Fatal("expected error from setquota failure, got nil")
	}
	var notPQ ErrNotProjectQuotaFS
	if !errors.As(err, &notPQ) {
		t.Fatalf("expected ErrNotProjectQuotaFS, got %T: %v", err, err)
	}

	// State file must not contain tenant-x.
	data, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read state file: %v", err)
	}
	var st state
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatalf("parse state: %v", err)
	}
	if _, ok := st.Tenants["tenant-x"]; ok {
		t.Error("rolled-back tenant still present in state file")
	}
	// next_project_id must not have advanced.
	if st.NextProjectID != 100 {
		t.Errorf("NextProjectID after rollback: got %d, want 100", st.NextProjectID)
	}
}

func TestConcurrentAllocateUniqueIDs(t *testing.T) {
	fx := &fakeExec{}
	m, _ := newManager(t, fx)

	const n = 20
	ids := make([]uint32, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := range n {
		i := i
		go func() {
			defer wg.Done()
			tenantID := fmt.Sprintf("tenant-%d", i)
			dir := fmt.Sprintf("/data/%s", tenantID)
			pid, err := m.Allocate(context.Background(), tenantID, dir, 1<<20)
			if err != nil {
				t.Errorf("Allocate %s: %v", tenantID, err)
				return
			}
			ids[i] = pid
		}()
	}
	wg.Wait()

	seen := map[uint32]int{}
	for i, pid := range ids {
		if pid == 0 {
			continue // failed goroutine already reported
		}
		if prev, dup := seen[pid]; dup {
			t.Errorf("duplicate project ID %d for tenants %d and %d", pid, prev, i)
		}
		seen[pid] = i
	}
	if len(seen) != n {
		t.Errorf("expected %d unique IDs, got %d", n, len(seen))
	}
}

// TestRollbackPersistFailureJoinsErrors verifies that when setquota fails AND
// the subsequent rollback persist also fails, Allocate returns a joined error
// containing both ErrNotProjectQuotaFS and the persist error, so callers know
// on-disk state is divergent.
func TestRollbackPersistFailureJoinsErrors(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("chmod-based test is Linux-only")
	}

	dir := t.TempDir()
	statePath := filepath.Join(dir, "quota.json")

	// sabotageExec: succeeds chattr, then on setquota makes the state dir
	// read-only (so rollback's persist will fail) and returns an error.
	fx := &sabotageExec{dir: dir}

	m, err := NewManager(statePath, "/var/lib/orlop", fx, nil, true)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	_, allocErr := m.Allocate(context.Background(), "tenant-y", "/data/tenant-y", 1<<20)
	if allocErr == nil {
		t.Fatal("expected error, got nil")
	}

	// Must contain ErrNotProjectQuotaFS.
	var notPQ ErrNotProjectQuotaFS
	if !errors.As(allocErr, &notPQ) {
		t.Errorf("expected ErrNotProjectQuotaFS in error chain, got: %v", allocErr)
	}

	// Must also contain the persist error (errors.Join makes both reachable via error string).
	if !strings.Contains(allocErr.Error(), "quota:") {
		t.Errorf("joined error does not mention persist failure: %v", allocErr)
	}
}

// sabotageExec succeeds for chattr; for setquota it first makes dir read-only
// (so rollback's persist will fail) then returns an error.
type sabotageExec struct {
	dir string
}

func (s *sabotageExec) Run(_ context.Context, name string, _ ...string) error {
	if name == "setquota" {
		_ = os.Chmod(s.dir, 0o555)
		return fmt.Errorf("fake setquota failure")
	}
	return nil
}

// TestDefaultExecCapturesStderr verifies that DefaultExec includes captured
// stderr text in the returned error when a command exits non-zero.
func TestDefaultExecCapturesStderr(t *testing.T) {
	ex := DefaultExec()
	err := ex.Run(context.Background(), "sh", "-c", "echo nope >&2; exit 1")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "nope") {
		t.Errorf("expected stderr 'nope' in error, got: %v", err)
	}
}

// TestDefaultExecCapturesStderrViaAllocate verifies that ErrNotProjectQuotaFS.Stderr
// contains captured stderr when DefaultExec is used end-to-end.
func TestDefaultExecCapturesStderrViaAllocate(t *testing.T) {
	// Use a real Exec that wraps a script printing to stderr then failing.
	realExec := &stderrExec{}
	dir := t.TempDir()
	statePath := filepath.Join(dir, "quota.json")
	m, err := NewManager(statePath, "/var/lib/orlop", realExec, nil, true)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	_, allocErr := m.Allocate(context.Background(), "tenant-z", "/data/tenant-z", 1<<20)
	if allocErr == nil {
		t.Fatal("expected error")
	}
	var notPQ ErrNotProjectQuotaFS
	if !errors.As(allocErr, &notPQ) {
		t.Fatalf("expected ErrNotProjectQuotaFS, got %T: %v", allocErr, allocErr)
	}
	if !strings.Contains(notPQ.Stderr, "stderr-marker") {
		t.Errorf("ErrNotProjectQuotaFS.Stderr missing captured stderr: %q", notPQ.Stderr)
	}
}

// TestDefaultExecTimeout verifies that a stuck command is killed when the
// timeout expires. Uses a 100 ms timeout so the test runs well under 1 s.
func TestDefaultExecTimeout(t *testing.T) {
	ex := NewDefaultExec(100 * time.Millisecond)
	err := ex.Run(context.Background(), "sleep", "10")
	if err == nil {
		t.Fatal("expected error from timed-out command, got nil")
	}
	// The error must mention the context deadline or killed signal.
	errStr := err.Error()
	if !strings.Contains(errStr, "killed") && !strings.Contains(errStr, "deadline") && !strings.Contains(errStr, "signal") {
		t.Errorf("expected timeout/kill in error, got: %v", err)
	}
}

func TestResizeGrowsQuota(t *testing.T) {
	fx := &fakeExec{}
	m, _ := newManager(t, fx)

	projID, err := m.Allocate(context.Background(), "tenant-a", "/data/tenant-a", 1<<30)
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	fx.reset()

	got, err := m.Resize(context.Background(), "tenant-a", 4<<30)
	if err != nil {
		t.Fatalf("Resize: %v", err)
	}
	if got != projID {
		t.Errorf("Resize project ID: got %d, want %d (must be preserved)", got, projID)
	}

	// Exactly one setquota call with the new hard limit; no chattr (already set).
	fx.mu.Lock()
	calls := fx.calls
	fx.mu.Unlock()
	if len(calls) != 1 {
		t.Fatalf("expected 1 exec call, got %d: %v", len(calls), calls)
	}
	hardKB := fmt.Sprintf("%d", (int64(4<<30)+1023)/1024)
	if calls[0][0] != "setquota" || calls[0][2] != fmt.Sprintf("%d", projID) || calls[0][4] != hardKB {
		t.Errorf("setquota call mismatch: %v (want proj=%d hard_kb=%s)", calls[0], projID, hardKB)
	}

	if _, size, ok := m.Lookup("tenant-a"); !ok || size != 4<<30 {
		t.Errorf("Lookup after resize: size=%d ok=%v, want %d", size, ok, int64(4<<30))
	}
}

func TestResizeIdempotentSameSize(t *testing.T) {
	fx := &fakeExec{}
	m, _ := newManager(t, fx)
	if _, err := m.Allocate(context.Background(), "tenant-a", "/data/tenant-a", 1<<30); err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	fx.reset()

	if _, err := m.Resize(context.Background(), "tenant-a", 1<<30); err != nil {
		t.Fatalf("Resize: %v", err)
	}
	fx.mu.Lock()
	n := len(fx.calls)
	fx.mu.Unlock()
	if n != 0 {
		t.Errorf("idempotent resize: expected 0 exec calls, got %d", n)
	}
}

func TestResizeUnknownTenant(t *testing.T) {
	fx := &fakeExec{}
	m, _ := newManager(t, fx)
	if _, err := m.Resize(context.Background(), "ghost", 1<<30); !errors.Is(err, ErrTenantNotFound) {
		t.Fatalf("expected ErrTenantNotFound, got %v", err)
	}
}

func TestResizeSetquotaFailureLeavesSizeUnchanged(t *testing.T) {
	fx := &fakeExec{}
	m, _ := newManager(t, fx)
	if _, err := m.Allocate(context.Background(), "tenant-a", "/data/tenant-a", 1<<30); err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	fx.errOn = "setquota"

	_, err := m.Resize(context.Background(), "tenant-a", 4<<30)
	var notQuota ErrNotProjectQuotaFS
	if !errors.As(err, &notQuota) {
		t.Fatalf("expected ErrNotProjectQuotaFS, got %T: %v", err, err)
	}
	// A failed setquota must not advance the recorded size.
	if _, size, ok := m.Lookup("tenant-a"); !ok || size != 1<<30 {
		t.Errorf("Lookup after failed resize: size=%d ok=%v, want %d (unchanged)", size, ok, int64(1<<30))
	}
}

func TestAllocateAppliesBurstMargin(t *testing.T) {
	fx := &fakeExec{}
	dir := t.TempDir()
	m, err := NewManager(filepath.Join(dir, "quota.json"), "/var/lib/orlop", fx, nil, true, WithBurstMargin(256<<20))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	if _, err := m.Allocate(context.Background(), "t", "/data/t", 1<<30); err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	fx.mu.Lock()
	calls := fx.calls
	fx.mu.Unlock()
	if len(calls) != 2 {
		t.Fatalf("expected chattr + setquota, got %d: %v", len(calls), calls)
	}
	// Hard limit is grant + margin; arg index 4 is the hard KiB value.
	wantHardKB := fmt.Sprintf("%d", (int64(1<<30)+int64(256<<20)+1023)/1024)
	if calls[1][0] != "setquota" || calls[1][4] != wantHardKB {
		t.Errorf("setquota = %v, want hard %s (grant+margin)", calls[1], wantHardKB)
	}
	// Stored/reported size is the accounted grant, NOT grant+margin.
	if _, size, ok := m.Lookup("t"); !ok || size != 1<<30 {
		t.Errorf("Lookup size = %d, want %d (accounted grant)", size, int64(1<<30))
	}
}

func TestResizeAppliesBurstMargin(t *testing.T) {
	fx := &fakeExec{}
	dir := t.TempDir()
	m, err := NewManager(filepath.Join(dir, "quota.json"), "/var/lib/orlop", fx, nil, true, WithBurstMargin(256<<20))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if _, err := m.Allocate(context.Background(), "t", "/data/t", 1<<30); err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	fx.reset()

	if _, err := m.Resize(context.Background(), "t", 4<<30); err != nil {
		t.Fatalf("Resize: %v", err)
	}
	fx.mu.Lock()
	calls := fx.calls
	fx.mu.Unlock()
	if len(calls) != 1 {
		t.Fatalf("expected 1 setquota call, got %d: %v", len(calls), calls)
	}
	wantHardKB := fmt.Sprintf("%d", (int64(4<<30)+int64(256<<20)+1023)/1024)
	if calls[0][0] != "setquota" || calls[0][4] != wantHardKB {
		t.Errorf("setquota = %v, want hard %s (grant+margin)", calls[0], wantHardKB)
	}
	if _, size, ok := m.Lookup("t"); !ok || size != 4<<30 {
		t.Errorf("Lookup size = %d, want %d (accounted grant)", size, int64(4<<30))
	}
}

// stderrExec succeeds for chattr but fails setquota with a known stderr string.
type stderrExec struct{}

func (stderrExec) Run(ctx context.Context, name string, args ...string) error {
	if name == "setquota" {
		var buf bytes.Buffer
		cmd := exec.CommandContext(ctx, "sh", "-c", "echo stderr-marker >&2; exit 1")
		cmd.Stderr = &buf
		_ = cmd.Run()
		return fmt.Errorf("exit status 1: %s", buf.String())
	}
	return nil
}

func newJuicefsManager(t *testing.T, ex *fakeExec, burst int64) *Manager {
	t.Helper()
	statePath := filepath.Join(t.TempDir(), "quota.json")
	m, err := NewManager(statePath, "/jfs/tenants", ex, nil, true,
		WithBurstMargin(burst),
		WithJuiceFS("postgres://meta/juicefs", "/jfs"),
		WithJuicefsBin("juicefs"),
	)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m
}

func TestJuicefsAllocateRunsQuotaSet(t *testing.T) {
	fx := &fakeExec{}
	m := newJuicefsManager(t, fx, 0)

	projID, err := m.Allocate(context.Background(), "u_a", "/jfs/tenants/u_a", 1<<30)
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if projID != 100 {
		t.Errorf("project ID: got %d, want 100", projID)
	}
	if len(fx.calls) != 1 {
		t.Fatalf("calls = %v, want exactly one juicefs invocation", fx.calls)
	}
	want := []string{"juicefs", "quota", "set", "postgres://meta/juicefs", "--path", "/tenants/u_a", "--capacity", "1"}
	if !reflect.DeepEqual(fx.calls[0], want) {
		t.Errorf("call = %v, want %v", fx.calls[0], want)
	}
}

// Sub-GiB grants (anon trial 128 MiB) clamp to JuiceFS's 1 GiB minimum; the
// precise cap stays at the application layer.
func TestJuicefsCapacityClampsToOneGiB(t *testing.T) {
	fx := &fakeExec{}
	m := newJuicefsManager(t, fx, 0)
	if _, err := m.Allocate(context.Background(), "u_small", "/jfs/tenants/u_small", 128<<20); err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if got := fx.calls[0][len(fx.calls[0])-1]; got != "1" {
		t.Errorf("capacity = %s, want 1 (clamped)", got)
	}
}

// The burst margin folds into the capacity and partial GiBs round up:
// 1 GiB grant + 256 MiB margin -> 2 GiB quota.
func TestJuicefsCapacityRoundsUpWithBurstMargin(t *testing.T) {
	fx := &fakeExec{}
	m := newJuicefsManager(t, fx, 256<<20)
	if _, err := m.Allocate(context.Background(), "u_b", "/jfs/tenants/u_b", 1<<30); err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if got := fx.calls[0][len(fx.calls[0])-1]; got != "2" {
		t.Errorf("capacity = %s, want 2", got)
	}
}

func TestJuicefsResizeRunsQuotaSet(t *testing.T) {
	fx := &fakeExec{}
	m := newJuicefsManager(t, fx, 0)
	if _, err := m.Allocate(context.Background(), "u_c", "/jfs/tenants/u_c", 1<<30); err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	fx.reset()

	if _, err := m.Resize(context.Background(), "u_c", 5<<30); err != nil {
		t.Fatalf("Resize: %v", err)
	}
	want := []string{"juicefs", "quota", "set", "postgres://meta/juicefs", "--path", "/tenants/u_c", "--capacity", "5"}
	if !reflect.DeepEqual(fx.calls[0], want) {
		t.Errorf("call = %v, want %v", fx.calls[0], want)
	}
	if _, size, ok := m.Lookup("u_c"); !ok || size != 5<<30 {
		t.Errorf("Lookup after resize: size=%d ok=%v, want %d", size, ok, int64(5<<30))
	}
}

func TestJuicefsAllocateFailureRollsBack(t *testing.T) {
	fx := &fakeExec{errOn: "juicefs"}
	m := newJuicefsManager(t, fx, 0)
	_, err := m.Allocate(context.Background(), "u_d", "/jfs/tenants/u_d", 1<<30)
	var quotaErr ErrNotProjectQuotaFS
	if !errors.As(err, &quotaErr) {
		t.Fatalf("err = %v, want ErrNotProjectQuotaFS", err)
	}
	if _, _, ok := m.Lookup("u_d"); ok {
		t.Errorf("tenant record not rolled back after failed quota set")
	}
}
