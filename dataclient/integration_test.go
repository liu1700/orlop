package dataclient_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/liu1700/orlop/client"
	dc "github.com/liu1700/orlop/dataclient"
)

// TestIntegrationDataplane exercises the whole client flow — enroll → mTLS dial →
// list/stat/read/write(CAS)/rename/delete, including a multi-chunk file — against
// a LIVE orlop stack. It is skipped unless the stack coordinates are provided, so
// it never runs in unit CI:
//
//	# bring a stack up (e.g. `orlop dev up`), then:
//	ORLOP_E2E_CONTROL=http://localhost:8080 \
//	ORLOP_E2E_TOKEN=<control-plane service token> \
//	go test -run TestIntegrationDataplane -v ./dataclient/
func TestIntegrationDataplane(t *testing.T) {
	controlURL := os.Getenv("ORLOP_E2E_CONTROL")
	token := os.Getenv("ORLOP_E2E_TOKEN")
	if controlURL == "" || token == "" {
		t.Skip("set ORLOP_E2E_CONTROL + ORLOP_E2E_TOKEN to run the live integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// The control API requires UUID entity/owner ids.
	const agentID = "e2e00000-0000-4000-8000-000000000001"
	const ownerID = "e2e00000-0000-4000-8000-0000000000ff"
	ctrl := client.New(controlURL, token)

	// Provision the agent's disk + a per-agent enroll token (idempotent).
	if _, err := ctrl.AllocateDisk(ctx, agentID, ownerID, 0); err != nil {
		t.Fatalf("AllocateDisk: %v", err)
	}
	enrollTok, err := ctrl.MintEnrollToken(ctx, agentID)
	if err != nil {
		t.Fatalf("MintEnrollToken: %v", err)
	}

	// Enroll → 1h agent-scoped cert, then mTLS dial the data plane.
	creds, err := dc.Enroll(ctx, http.DefaultClient, controlURL, enrollTok, dc.WithInsecureControlURL())
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	t.Logf("enrolled: server_addr=%s allocation=%s", creds.ServerAddr, creds.AllocationID)

	cli, err := dc.Dial(ctx, creds)
	if err != nil {
		t.Fatalf("Dial %s: %v", creds.ServerAddr, err)
	}
	defer func() { _ = cli.Close() }()
	if cli.AgentID() == "" {
		t.Fatalf("client has no agent scope (no /agent SAN in the cert?)")
	}
	t.Logf("dialed; paths scoped to agent %q", cli.AgentID())

	// A freshly allocated disk has no agent root dir until something mounts it,
	// so create it (idempotent; a real agent gets this on its first mount).
	if err := cli.MakeDir(ctx, "/", 0o755); err != nil && !errors.Is(err, dc.ErrExists) {
		t.Fatalf("MakeDir root: %v", err)
	}

	const path = "/e2e-notes.txt"
	// Clean any residue from a prior run so the test is re-runnable.
	if info, serr := cli.StatFile(ctx, path); serr == nil {
		_ = cli.Delete(ctx, path, info.Version)
	}
	if info, serr := cli.StatFile(ctx, "/e2e-big.bin"); serr == nil {
		_ = cli.Delete(ctx, "/e2e-big.bin", info.Version)
	}

	// Create.
	content := []byte("hello from the dataclient e2e")
	v1, err := cli.WriteFile(ctx, path, content, 0, dc.WriteOpts{})
	if err != nil {
		t.Fatalf("WriteFile create: %v", err)
	}

	// Read back byte-identical, version matches.
	got, info, err := cli.ReadFile(ctx, path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("read mismatch: got %q", got)
	}
	if info.Version != v1 {
		t.Fatalf("read version %d != write version %d", info.Version, v1)
	}

	// Listing finds it.
	entries, err := cli.ListDir(ctx, "/")
	if err != nil {
		t.Fatalf("ListDir: %v", err)
	}
	if !containsName(entries, "e2e-notes.txt") {
		t.Fatalf("listing missing e2e-notes.txt: %+v", entries)
	}

	// CAS: overwrite at the right version succeeds; a stale version is ErrStale.
	v2, err := cli.WriteFile(ctx, path, []byte("second version"), v1, dc.WriteOpts{})
	if err != nil {
		t.Fatalf("CAS overwrite at v%d: %v", v1, err)
	}
	if v2 != v1+1 {
		t.Fatalf("overwrite version %d != %d", v2, v1+1)
	}
	_, err = cli.WriteFile(ctx, path, []byte("stale"), v1, dc.WriteOpts{})
	if !errors.Is(err, dc.ErrStale) {
		t.Fatalf("stale write err = %v, want ErrStale", err)
	}
	var se *dc.StaleError
	if errors.As(err, &se) && se.CurrentVersion != v2 {
		t.Fatalf("StaleError.CurrentVersion = %d, want %d", se.CurrentVersion, v2)
	}

	// Multi-chunk round-trip (3 MiB > the 1 MiB chunk size).
	big := bytes.Repeat([]byte("orlop-"), (3<<20)/6)
	if _, err := cli.WriteFile(ctx, "/e2e-big.bin", big, 0, dc.WriteOpts{}); err != nil {
		t.Fatalf("multi-chunk write: %v", err)
	}
	gotBig, _, err := cli.ReadFile(ctx, "/e2e-big.bin")
	if err != nil {
		t.Fatalf("multi-chunk read: %v", err)
	}
	if !bytes.Equal(gotBig, big) {
		t.Fatalf("multi-chunk mismatch: got %d bytes, want %d", len(gotBig), len(big))
	}

	// Rename (soft-delete style) removes the source.
	cur, _ := cli.StatFile(ctx, path)
	if _, err := cli.Rename(ctx, path, "/e2e-trash.txt", cur.Version); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if _, err := cli.StatFile(ctx, path); !errors.Is(err, dc.ErrNotFound) {
		t.Fatalf("source present after rename: %v", err)
	}

	// Delete both leftovers.
	for _, p := range []string{"/e2e-trash.txt", "/e2e-big.bin"} {
		if info, serr := cli.StatFile(ctx, p); serr == nil {
			if err := cli.Delete(ctx, p, info.Version); err != nil {
				t.Fatalf("Delete %s: %v", p, err)
			}
		}
	}
	t.Logf("PASS: create v%d → overwrite v%d → stale-conflict → 3MiB round-trip → rename → delete, all over real mTLS", v1, v2)
}

func containsName(entries []dc.DirEntry, name string) bool {
	for _, e := range entries {
		if e.Name == name {
			return true
		}
	}
	return false
}
