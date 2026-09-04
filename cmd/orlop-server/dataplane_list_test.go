package main

import (
	"testing"

	"github.com/liu1700/orlop/cmd/orlop-server/dataplane"
	"github.com/vmihailenco/msgpack/v5"
)

// listEntries drives handleList through the wire path and returns the decoded
// entries keyed by name.
func listEntries(t *testing.T, state *serverState, tenant *tenantState, ident Identity, dir string) map[string]dataplane.EntryWire {
	t.Helper()
	frame := dispatchAndReadFrame(t, state, tenant, ident, dataplane.OpList,
		dataplane.ListRequest{Path: dir}, handleList)
	expectSuccess(t, frame)
	var resp dataplane.ListResponse
	if err := msgpack.Unmarshal(frame.Payload, &resp); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	byName := make(map[string]dataplane.EntryWire, len(resp.Entries))
	for _, e := range resp.Entries {
		byName[e.Name] = e
	}
	return byName
}

// A listing must answer readlink for every symlink child it reports. Before
// this test, handleList built each child from ListChildren alone and left
// Target empty, so a consumer that only ever issues LIST (the Go SDK's
// ListDir is exactly that) saw every symlink as a link pointing at nothing.
// A Python virtualenv is entirely such links, so the whole tree was
// unreadable through a listing.
//
// The table is the completeness statement: one child of every kind a listing
// can report, each with the fields that kind must carry. A future refactor
// that drops an attribute on the way out of the loop fails here.
func TestListCarriesEverySymlinkChildsTargetVerbatim(t *testing.T) {
	state := newTestState(t, nil, nil)
	tenant, ok := state.tenant(testTenant)
	if !ok {
		t.Fatalf("tenant %q not found", testTenant)
	}
	ident := testIdentity()

	const dir = "/venv-bin"
	if err := tenant.manifests.DirCreate(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}

	// Relative, absolute, and dangling — the three shapes a venv produces.
	// "python -> python3" is relative and, for the moment between the two
	// entries landing, dangling; POSIX allows both and orlop stores the
	// target bytes verbatim without resolving them.
	symlinks := map[string]string{
		"python":     "python3",                     // relative, resolves inside the dir
		"python3":    "/usr/local/bin/python3.12",   // absolute, resolves outside the tree
		"broken":     "../../nowhere/at/all",        // dangling: nothing at the far end
		"weird-name": "target with spaces/and#hash", // bytes are bytes
	}
	for name, target := range symlinks {
		if err := tenant.manifests.Symlink(dir+"/"+name, target, 0o777); err != nil {
			t.Fatalf("symlink %s -> %s: %v", name, target, err)
		}
	}

	// A regular file and a FIFO share the listing: neither may grow a target.
	put := dataplane.ManifestPutRequest{
		Path:   dir + "/activate",
		Size:   7,
		Mode:   0o644,
		Chunks: []dataplane.ChunkRef{{Hash: makeTestHash(21), Offset: 0, Len: 7}},
	}
	expectSuccess(t, dispatchAndReadFrame(t, state, tenant, ident, dataplane.OpManifestPut, put, handleManifestPut))
	if err := tenant.manifests.Mknod(dir+"/pipe", sIFIFO|0o644, 0); err != nil {
		t.Fatalf("mknod pipe: %v", err)
	}
	if err := tenant.manifests.DirCreate(dir+"/subdir", 0o755); err != nil {
		t.Fatalf("mkdir subdir: %v", err)
	}

	got := listEntries(t, state, tenant, ident, dir)
	if len(got) != len(symlinks)+3 {
		t.Fatalf("listing returned %d entries, want %d: %v", len(got), len(symlinks)+3, got)
	}

	for name, want := range symlinks {
		e, ok := got[name]
		if !ok {
			t.Fatalf("%s missing from the listing", name)
		}
		if e.Kind != "symlink" {
			t.Errorf("%s: kind = %q, want symlink", name, e.Kind)
		}
		if e.Target != want {
			t.Errorf("%s: target = %q, want %q (verbatim, never resolved or substituted)", name, e.Target, want)
		}
		// Size is the target length, so a listing that reported the size but
		// dropped the target was already self-contradictory.
		if e.Size != uint64(len(want)) {
			t.Errorf("%s: size = %d, want %d (len of the target)", name, e.Size, len(want))
		}
	}

	// A listing must agree with a STAT of the same path — that divergence is
	// what let the target go missing here in the first place.
	for name, want := range symlinks {
		frame := dispatchAndReadFrame(t, state, tenant, ident, dataplane.OpStat,
			dataplane.StatRequest{Path: dir + "/" + name}, handleStat)
		expectSuccess(t, frame)
		var sr dataplane.StatResponse
		if err := msgpack.Unmarshal(frame.Payload, &sr); err != nil {
			t.Fatalf("decode stat response for %s: %v", name, err)
		}
		if sr.Entry.Target != want || sr.Entry.Target != got[name].Target {
			t.Errorf("%s: stat target = %q, list target = %q, want %q — list and stat must agree",
				name, sr.Entry.Target, got[name].Target, want)
		}
	}

	for _, name := range []string{"activate", "pipe", "subdir"} {
		e, ok := got[name]
		if !ok {
			t.Fatalf("%s missing from the listing", name)
		}
		if e.Target != "" {
			t.Errorf("%s (kind %q): target = %q, want empty — only symlinks carry one", name, e.Kind, e.Target)
		}
	}
	if k := got["activate"].Kind; k != "file" {
		t.Errorf("activate: kind = %q, want file", k)
	}
	if k := got["pipe"].Kind; k != "fifo" {
		t.Errorf("pipe: kind = %q, want fifo", k)
	}
	if k := got["subdir"].Kind; k != "dir" {
		t.Errorf("subdir: kind = %q, want dir", k)
	}
}
