package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"log/slog"
	"math/big"
	"net/url"
	"testing"

	"github.com/liu1700/orlop/cmd/orlop-server/dataplane"
	"github.com/vmihailenco/msgpack/v5"
)

// --- identity: certScopedAgentID -------------------------------------------

// A cert that carries both a tenant SAN and an /agent/<id> SAN must surface
// the agent id as the connection's authorization scope.
func TestCertScopedAgentIDFromAgentSAN(t *testing.T) {
	const td = "orlop.example"
	cert := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "user@example.com"},
		SerialNumber: big.NewInt(7),
		URIs: []*url.URL{
			mustParseURL(t, "spiffe://"+td+"/tenant/tenant-a"),
			mustParseURL(t, "spiffe://"+td+"/agent/agent-A"),
		},
	}
	if got := certScopedAgentID(cert, td); got != "agent-A" {
		t.Fatalf("certScopedAgentID = %q, want %q", got, "agent-A")
	}
}

// A tenant-only cert (no /agent SAN) must return "" so the connection keeps
// the historical tenant-wide access (no per-agent moat).
func TestCertScopedAgentIDTenantOnlyReturnsEmpty(t *testing.T) {
	const td = "orlop.example"
	cert := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "user@example.com"},
		SerialNumber: big.NewInt(8),
		URIs: []*url.URL{
			mustParseURL(t, "spiffe://"+td+"/tenant/tenant-a"),
		},
	}
	if got := certScopedAgentID(cert, td); got != "" {
		t.Fatalf("certScopedAgentID = %q, want empty (tenant-only cert)", got)
	}
}

// A wrong-trust-domain agent SAN must be ignored (no cross-domain scope leak).
func TestCertScopedAgentIDIgnoresForeignTrustDomain(t *testing.T) {
	const td = "orlop.example"
	cert := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "user@example.com"},
		SerialNumber: big.NewInt(9),
		URIs: []*url.URL{
			mustParseURL(t, "spiffe://other.example/agent/agent-A"),
		},
	}
	if got := certScopedAgentID(cert, td); got != "" {
		t.Fatalf("certScopedAgentID = %q, want empty (foreign trust domain)", got)
	}
}

func TestAgentIDFromSPIFFE(t *testing.T) {
	const td = "orlop.example"
	cases := []struct {
		raw     string
		wantID  string
		wantOK  bool
		comment string
	}{
		{"spiffe://" + td + "/agent/agent-A", "agent-A", true, "well-formed"},
		{"spiffe://" + td + "/agent/", "", false, "empty id"},
		{"spiffe://" + td + "/agent", "", false, "one segment"},
		{"spiffe://" + td + "/agent/a/b", "", false, "three segments"},
		{"spiffe://" + td + "/tenant/tenant-a", "", false, "tenant uri, not agent"},
		{"spiffe://other.example/agent/agent-A", "", false, "wrong trust domain"},
	}
	for _, c := range cases {
		u := mustParseURL(t, c.raw)
		gotID, gotOK := agentIDFromSPIFFE(u, td)
		if gotID != c.wantID || gotOK != c.wantOK {
			t.Fatalf("%s: agentIDFromSPIFFE(%q) = (%q,%v), want (%q,%v)",
				c.comment, c.raw, gotID, gotOK, c.wantID, c.wantOK)
		}
	}
}

// --- enforcement: checkAgentPath at the handler layer ----------------------

// agentScopedIdentity returns an injected Identity carrying an /agent SAN
// scope, mirroring testIdentity() but with ScopedAgentID set.
func agentScopedIdentity(agentID string) Identity {
	id := testIdentity()
	id.ScopedAgentID = agentID
	return id
}

// expectEACCESOutsideSubtree asserts that frame is an EACCES error frame whose
// message identifies the per-agent moat (not a policy denial), so the two
// EACCES sources stay distinguishable.
func expectEACCESOutsideSubtree(t *testing.T, frame dataplane.Frame) {
	t.Helper()
	if frame.Flags&dataplane.FlagError == 0 {
		t.Fatalf("expected an error frame, got flags=%v", frame.Flags)
	}
	var ep dataplane.ErrorPayload
	if err := msgpack.Unmarshal(frame.Payload, &ep); err != nil {
		t.Fatalf("decode error payload: %v", err)
	}
	if ep.Errno != dataplane.ErrnoEACCES {
		t.Fatalf("errno = %d, want EACCES (%d); msg=%q", ep.Errno, dataplane.ErrnoEACCES, ep.Message)
	}
	if ep.Message != "path outside agent subtree" {
		t.Fatalf("message = %q, want %q (agent-moat denial, not policy)", ep.Message, "path outside agent subtree")
	}
}

func expectSuccess(t *testing.T, frame dataplane.Frame) {
	t.Helper()
	if frame.Flags&dataplane.FlagError != 0 {
		var ep dataplane.ErrorPayload
		_ = msgpack.Unmarshal(frame.Payload, &ep)
		t.Fatalf("expected success, got error errno=%d msg=%q", ep.Errno, ep.Message)
	}
}

// seedAgentDir creates the agent's single-segment disk dir /<id> for the tenant
// so writes under the agent subtree can succeed once authorization passes.
func seedAgentDir(t *testing.T, tenant *tenantState, agentID string) {
	t.Helper()
	if err := tenant.manifests.DirCreate("/"+agentID, 0o755); err != nil && !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("seed /%s: %v", agentID, err)
	}
}

// (a) An agent-scoped ident must be denied when it writes/reads outside its
// subtree (here: agent-A's cert touching agent-B's tree).
func TestAgentPathDeniesCrossAgentWrite(t *testing.T) {
	state := newTestState(t, nil, nil)
	tenant, ok := state.tenant(testTenant)
	if !ok {
		t.Fatalf("tenant %q not found", testTenant)
	}
	ident := agentScopedIdentity("agent-A")

	// Write into agent-B's subtree → EACCES.
	put := dataplane.ManifestPutRequest{
		Path:   "/agent-B/file.txt",
		Size:   1,
		Mode:   0o644,
		Chunks: []dataplane.ChunkRef{{Hash: makeTestHash(1), Offset: 0, Len: 1}},
	}
	frame := dispatchAndReadFrame(t, state, tenant, ident, dataplane.OpManifestPut, put, handleManifestPut)
	expectEACCESOutsideSubtree(t, frame)

	// Read from agent-B's subtree → EACCES.
	get := dataplane.ManifestGetRequest{Path: "/agent-B/file.txt"}
	frame = dispatchAndReadFrame(t, state, tenant, ident, dataplane.OpManifestGet, get, handleManifestGet)
	expectEACCESOutsideSubtree(t, frame)
}

// (b) The same agent-scoped ident must succeed inside its own subtree.
func TestAgentPathAllowsOwnSubtree(t *testing.T) {
	state := newTestState(t, nil, nil)
	tenant, ok := state.tenant(testTenant)
	if !ok {
		t.Fatalf("tenant %q not found", testTenant)
	}
	seedAgentDir(t, tenant, "agent-A")
	ident := agentScopedIdentity("agent-A")

	put := dataplane.ManifestPutRequest{
		Path:   "/agent-A/file.txt",
		Size:   4,
		Mode:   0o644,
		Chunks: []dataplane.ChunkRef{{Hash: makeTestHash(2), Offset: 0, Len: 4}},
	}
	frame := dispatchAndReadFrame(t, state, tenant, ident, dataplane.OpManifestPut, put, handleManifestPut)
	expectSuccess(t, frame)

	get := dataplane.ManifestGetRequest{Path: "/agent-A/file.txt"}
	frame = dispatchAndReadFrame(t, state, tenant, ident, dataplane.OpManifestGet, get, handleManifestGet)
	expectSuccess(t, frame)
}

// (c) A traversal that escapes the subtree via ".." must be denied, even
// though path.Clean would land it in another agent's tree. The raw,
// non-canonical path is rejected before it can reach storage.
func TestAgentPathDeniesTraversalEscape(t *testing.T) {
	state := newTestState(t, nil, nil)
	tenant, ok := state.tenant(testTenant)
	if !ok {
		t.Fatalf("tenant %q not found", testTenant)
	}
	seedAgentDir(t, tenant, "agent-A")
	ident := agentScopedIdentity("agent-A")

	// path.Clean("/agent-A/../agent-B/x") == "/agent-B/x".
	put := dataplane.ManifestPutRequest{
		Path:   "/agent-A/../agent-B/x",
		Size:   1,
		Mode:   0o644,
		Chunks: []dataplane.ChunkRef{{Hash: makeTestHash(3), Offset: 0, Len: 1}},
	}
	frame := dispatchAndReadFrame(t, state, tenant, ident, dataplane.OpManifestPut, put, handleManifestPut)
	expectEACCESOutsideSubtree(t, frame)

	// A traversal that "stays" inside the subtree textually is still rejected
	// because the raw path is non-canonical (defense in depth: the stored path
	// must equal the authorized path).
	put2 := dataplane.ManifestPutRequest{
		Path:   "/agent-A/sub/../file.txt",
		Size:   1,
		Mode:   0o644,
		Chunks: []dataplane.ChunkRef{{Hash: makeTestHash(4), Offset: 0, Len: 1}},
	}
	frame = dispatchAndReadFrame(t, state, tenant, ident, dataplane.OpManifestPut, put2, handleManifestPut)
	expectEACCESOutsideSubtree(t, frame)
}

// (d) checkAgentPath's empty-scope branch is now only reachable via an INJECTED
// test Identity: real data-plane traffic with a tenant-only cert is rejected
// upstream at identifyV2Peer (see TestIdentifyV2PeerRejectsTenantOnlyCert). This
// keeps the per-op handler tests (which inject testIdentity()) working without a
// tenant-wide production path.
func TestAgentPathTenantOnlyBypassesMoat(t *testing.T) {
	state := newTestState(t, nil, nil)
	tenant, ok := state.tenant(testTenant)
	if !ok {
		t.Fatalf("tenant %q not found", testTenant)
	}
	seedAgentDir(t, tenant, "agent-B")
	ident := testIdentity() // ScopedAgentID == ""

	put := dataplane.ManifestPutRequest{
		Path:   "/agent-B/file.txt",
		Size:   2,
		Mode:   0o644,
		Chunks: []dataplane.ChunkRef{{Hash: makeTestHash(5), Offset: 0, Len: 2}},
	}
	frame := dispatchAndReadFrame(t, state, tenant, ident, dataplane.OpManifestPut, put, handleManifestPut)
	expectSuccess(t, frame)
}

// checkAgentPath must also gate the listing/dir ops, not just manifest_put.
func TestAgentPathGatesListAndDirOps(t *testing.T) {
	state := newTestState(t, nil, nil)
	tenant, ok := state.tenant(testTenant)
	if !ok {
		t.Fatalf("tenant %q not found", testTenant)
	}
	ident := agentScopedIdentity("agent-A")

	frame := dispatchAndReadFrame(t, state, tenant, ident, dataplane.OpList,
		dataplane.ListRequest{Path: "/agent-B"}, handleList)
	expectEACCESOutsideSubtree(t, frame)

	frame = dispatchAndReadFrame(t, state, tenant, ident, dataplane.OpDirCreate,
		dataplane.DirCreateRequest{Path: "/agent-B/sub", Mode: 0o755}, handleDirCreate)
	expectEACCESOutsideSubtree(t, frame)
}

// Single isolation policy: identifyV2Peer (the data-plane connection auth) rejects
// a tenant-only cert (no /agent SAN) at the door, and accepts an agent-scoped one.
func TestIdentifyV2PeerRejectsTenantOnlyCert(t *testing.T) {
	state := newTestState(t, nil, nil)
	td := state.trustDomain
	mkCert := func(uris ...string) *x509.Certificate {
		c := &x509.Certificate{Subject: pkix.Name{CommonName: "user@example.com"}, SerialNumber: big.NewInt(11)}
		for _, u := range uris {
			c.URIs = append(c.URIs, mustParseURL(t, u))
		}
		return c
	}

	// Tenant-only cert → rejected (no agent SAN; tenant-wide path removed).
	if _, _, ok := identifyV2Peer(slog.Default(), state, mkCert(
		"spiffe://"+td+"/tenant/"+testTenant)); ok {
		t.Fatal("tenant-only cert must be rejected (agent scope is the only policy)")
	}

	// Agent-scoped cert → accepted, scope surfaced.
	_, ident, ok := identifyV2Peer(slog.Default(), state, mkCert(
		"spiffe://"+td+"/tenant/"+testTenant, "spiffe://"+td+"/agent/agent-A"))
	if !ok {
		t.Fatal("agent-scoped cert must be accepted")
	}
	if ident.ScopedAgentID != "agent-A" {
		t.Fatalf("ScopedAgentID = %q, want agent-A", ident.ScopedAgentID)
	}
}
