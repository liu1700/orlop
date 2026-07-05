package dataclient

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/vmihailenco/msgpack/v5"
	"lukechampine.com/blake3"

	wire "github.com/liu1700/orlop/cmd/orlop-server/dataplane"
)

// fakeServer is a minimal in-process orlop-server that speaks the real frame
// protocol against in-memory manifest + chunk stores, mirroring the CAS and
// error semantics (including Rename's overwrite behaviour) the client depends
// on. corruptChunks makes ChunkGet return tampered bytes, to exercise the
// download integrity check.
type fakeServer struct {
	manifests     map[string]*mstate
	chunks        map[string][]byte
	dirs          map[string]bool
	corruptChunks bool
}

type mstate struct {
	version uint64
	size    uint64
	mode    uint32
	mtime   int64
	chunks  []wire.ChunkRef
}

func newFakeServer() *fakeServer {
	return &fakeServer{
		manifests: map[string]*mstate{},
		chunks:    map[string][]byte{},
		dirs:      map[string]bool{"/": true},
	}
}

func (fs *fakeServer) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	for {
		fr, err := wire.ReadFrame(conn)
		if err != nil {
			return
		}
		fs.dispatch(conn, fr)
	}
}

func (fs *fakeServer) reply(conn net.Conn, fr wire.Frame, val any) {
	payload, _ := msgpack.Marshal(val)
	_ = wire.WriteFrame(conn, wire.Frame{Op: fr.Op, Flags: wire.FlagResponse, RID: fr.RID, Payload: payload})
}

func (fs *fakeServer) fail(conn net.Conn, fr wire.Frame, ep wire.ErrorPayload) {
	payload, _ := msgpack.Marshal(ep)
	_ = wire.WriteFrame(conn, wire.Frame{Op: fr.Op, Flags: wire.FlagResponse | wire.FlagError, RID: fr.RID, Payload: payload})
}

func staleHint(current uint64) wire.ErrorPayload {
	cur := current
	return wire.ErrESTALE("manifest version conflict").
		WithRecovery(&wire.RecoveryHint{Kind: wire.RecoveryKindCasConflict, CurrentVersion: &cur, SuggestedAction: "reload"})
}

func (fs *fakeServer) dispatch(conn net.Conn, fr wire.Frame) {
	switch fr.Op {
	case wire.OpList:
		var req wire.ListRequest
		_ = msgpack.Unmarshal(fr.Payload, &req)
		var entries []wire.EntryWire
		for p, m := range fs.manifests {
			if path.Dir(p) == req.Path {
				entries = append(entries, wire.EntryWire{Name: path.Base(p), Kind: "file", Size: m.size, Mode: m.mode})
			}
		}
		for d := range fs.dirs {
			if d != "/" && path.Dir(d) == req.Path {
				entries = append(entries, wire.EntryWire{Name: path.Base(d), Kind: "dir", Mode: 0o755})
			}
		}
		fs.reply(conn, fr, wire.ListResponse{Entries: entries})

	case wire.OpManifestGet:
		var req wire.ManifestGetRequest
		_ = msgpack.Unmarshal(fr.Payload, &req)
		m, ok := fs.manifests[req.Path]
		if !ok {
			fs.fail(conn, fr, wire.ErrENOENT("no such file"))
			return
		}
		fs.reply(conn, fr, wire.ManifestGetResponse{Version: m.version, Size: m.size, Mode: m.mode, Mtime: m.mtime, Chunks: m.chunks})

	case wire.OpChunkGet:
		var req wire.ChunkGetRequest
		_ = msgpack.Unmarshal(fr.Payload, &req)
		b, ok := fs.chunks[string(req.Hash)]
		if !ok {
			fs.fail(conn, fr, wire.ErrENOENT("no such chunk"))
			return
		}
		if fs.corruptChunks && len(b) > 0 {
			b = append([]byte(nil), b...)
			b[0] ^= 0xFF
		}
		fs.reply(conn, fr, wire.ChunkGetResponse{Bytes: b})

	case wire.OpChunkPut:
		var req wire.ChunkPutRequest
		_ = msgpack.Unmarshal(fr.Payload, &req)
		sum := blake3.Sum256(req.Bytes)
		if !bytes.Equal(sum[:], req.Hash) {
			fs.fail(conn, fr, wire.ErrEINVAL("hash mismatch"))
			return
		}
		_, existed := fs.chunks[string(req.Hash)]
		fs.chunks[string(req.Hash)] = append([]byte(nil), req.Bytes...)
		fs.reply(conn, fr, wire.ChunkPutResponse{Stored: !existed})

	case wire.OpManifestPut:
		var req wire.ManifestPutRequest
		_ = msgpack.Unmarshal(fr.Payload, &req)
		cur, exists := fs.manifests[req.Path]
		if req.VersionExpected == 0 {
			if exists {
				fs.fail(conn, fr, staleHint(cur.version))
				return
			}
		} else {
			if !exists {
				fs.fail(conn, fr, staleHint(0))
				return
			}
			if cur.version != req.VersionExpected {
				fs.fail(conn, fr, staleHint(cur.version))
				return
			}
		}
		newV := req.VersionExpected + 1
		fs.manifests[req.Path] = &mstate{version: newV, size: req.Size, mode: req.Mode, mtime: req.Mtime, chunks: req.Chunks}
		fs.reply(conn, fr, wire.ManifestPutResponse{Version: newV})

	case wire.OpManifestDelete:
		var req wire.ManifestDeleteRequest
		_ = msgpack.Unmarshal(fr.Payload, &req)
		cur, exists := fs.manifests[req.Path]
		if !exists {
			fs.fail(conn, fr, wire.ErrENOENT("no such file"))
			return
		}
		if cur.version != req.ExpectedVersion {
			fs.fail(conn, fr, staleHint(cur.version))
			return
		}
		delete(fs.manifests, req.Path)
		fs.reply(conn, fr, wire.ManifestDeleteResponse{})

	case wire.OpManifestRename:
		var req wire.ManifestRenameRequest
		_ = msgpack.Unmarshal(fr.Payload, &req)
		src, ok := fs.manifests[req.From]
		if !ok {
			fs.fail(conn, fr, wire.ErrENOENT("no such file"))
			return
		}
		if src.version != req.ExpectedVersionFrom {
			fs.fail(conn, fr, staleHint(src.version))
			return
		}
		// Mirror the real server: expectedTo==0 does NOT enforce must-not-exist;
		// an existing destination regular file is overwritten.
		delete(fs.manifests, req.From)
		moved := *src
		moved.version = 1
		fs.manifests[req.To] = &moved
		fs.reply(conn, fr, wire.ManifestRenameResponse{NewVersionAtTo: 1})

	case wire.OpDirCreate:
		var req wire.DirCreateRequest
		_ = msgpack.Unmarshal(fr.Payload, &req)
		if fs.dirs[req.Path] {
			fs.fail(conn, fr, wire.ErrEEXIST("directory exists"))
			return
		}
		fs.dirs[req.Path] = true
		fs.reply(conn, fr, wire.DirCreateResponse{})

	case wire.OpDirRemove:
		var req wire.DirRemoveRequest
		_ = msgpack.Unmarshal(fr.Payload, &req)
		for p := range fs.manifests {
			if path.Dir(p) == req.Path {
				fs.fail(conn, fr, wire.ErrENOTEMPTY("not empty"))
				return
			}
		}
		for d := range fs.dirs {
			if d != req.Path && path.Dir(d) == req.Path {
				fs.fail(conn, fr, wire.ErrENOTEMPTY("not empty"))
				return
			}
		}
		delete(fs.dirs, req.Path)
		fs.reply(conn, fr, wire.DirRemoveResponse{})

	default:
		fs.fail(conn, fr, wire.ErrEINVAL("unsupported op"))
	}
}

// pipeClient wires a Client to a fresh fakeServer over an in-process pipe.
// chunkSize is deliberately tiny in some tests so small payloads exercise
// multi-chunk paths; agentID scopes paths ("" = verbatim).
func pipeClient(t *testing.T, chunkSize int, agentID string) (*Client, *fakeServer) {
	t.Helper()
	srv, cli := net.Pipe()
	fs := newFakeServer()
	go fs.serve(srv)
	c := newClient(cli, chunkSize, agentID)
	t.Cleanup(func() { _ = c.Close() })
	return c, fs
}

func TestWriteReadRoundTripMultiChunk(t *testing.T) {
	c, _ := pipeClient(t, 8, "")
	ctx := context.Background()
	data := []byte("hello orlop dataclient, this spans several chunks")

	v, err := c.WriteFile(ctx, "/notes.txt", data, 0, WriteOpts{})
	if err != nil {
		t.Fatalf("WriteFile create: %v", err)
	}
	if v != 1 {
		t.Fatalf("create version = %d, want 1", v)
	}
	got, info, err := c.ReadFile(ctx, "/notes.txt")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, data)
	}
	if info.Version != 1 || info.Size != uint64(len(data)) {
		t.Fatalf("info = %+v, want version 1 size %d", info, len(data))
	}
}

func TestWriteEmptyFile(t *testing.T) {
	c, _ := pipeClient(t, 8, "")
	ctx := context.Background()
	if _, err := c.WriteFile(ctx, "/empty", nil, 0, WriteOpts{}); err != nil {
		t.Fatalf("WriteFile empty: %v", err)
	}
	got, info, err := c.ReadFile(ctx, "/empty")
	if err != nil {
		t.Fatalf("ReadFile empty: %v", err)
	}
	if len(got) != 0 || info.Size != 0 {
		t.Fatalf("empty round-trip: got %d bytes, size %d", len(got), info.Size)
	}
}

func TestWriteCASOverwriteAndStale(t *testing.T) {
	c, _ := pipeClient(t, 1<<20, "")
	ctx := context.Background()

	v1, err := c.WriteFile(ctx, "/f", []byte("one"), 0, WriteOpts{})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	v2, err := c.WriteFile(ctx, "/f", []byte("two"), v1, WriteOpts{})
	if err != nil {
		t.Fatalf("overwrite at v%d: %v", v1, err)
	}
	if v2 != v1+1 {
		t.Fatalf("overwrite version = %d, want %d", v2, v1+1)
	}
	_, err = c.WriteFile(ctx, "/f", []byte("three"), v1, WriteOpts{})
	if !errors.Is(err, ErrStale) {
		t.Fatalf("stale overwrite err = %v, want ErrStale", err)
	}
	var se *StaleError
	if !errors.As(err, &se) {
		t.Fatalf("stale overwrite not a *StaleError: %v", err)
	}
	if se.CurrentVersion != v2 {
		t.Fatalf("StaleError.CurrentVersion = %d, want %d", se.CurrentVersion, v2)
	}
}

func TestCreateConflictIsStale(t *testing.T) {
	c, _ := pipeClient(t, 1<<20, "")
	ctx := context.Background()
	if _, err := c.WriteFile(ctx, "/f", []byte("x"), 0, WriteOpts{}); err != nil {
		t.Fatalf("create: %v", err)
	}
	_, err := c.WriteFile(ctx, "/f", []byte("y"), 0, WriteOpts{})
	if !errors.Is(err, ErrStale) {
		t.Fatalf("create-on-existing err = %v, want ErrStale", err)
	}
}

func TestReadMissingIsNotFound(t *testing.T) {
	c, _ := pipeClient(t, 1<<20, "")
	_, _, err := c.ReadFile(context.Background(), "/nope")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("ReadFile missing err = %v, want ErrNotFound", err)
	}
}

func TestListDir(t *testing.T) {
	c, _ := pipeClient(t, 1<<20, "")
	ctx := context.Background()
	if _, err := c.WriteFile(ctx, "/a.txt", []byte("a"), 0, WriteOpts{}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.WriteFile(ctx, "/b.txt", []byte("bb"), 0, WriteOpts{}); err != nil {
		t.Fatal(err)
	}
	if err := c.MakeDir(ctx, "/sub", 0); err != nil {
		t.Fatal(err)
	}
	entries, err := c.ListDir(ctx, "/")
	if err != nil {
		t.Fatalf("ListDir: %v", err)
	}
	kinds := map[string]string{}
	for _, e := range entries {
		kinds[e.Name] = e.Kind
	}
	if kinds["a.txt"] != "file" || kinds["b.txt"] != "file" || kinds["sub"] != "dir" {
		t.Fatalf("ListDir kinds = %v", kinds)
	}
}

func TestDeleteCAS(t *testing.T) {
	c, _ := pipeClient(t, 1<<20, "")
	ctx := context.Background()
	v, err := c.WriteFile(ctx, "/f", []byte("x"), 0, WriteOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(ctx, "/f", v+9); !errors.Is(err, ErrStale) {
		t.Fatalf("stale delete err = %v, want ErrStale", err)
	}
	if err := c.Delete(ctx, "/f", v); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := c.StatFile(ctx, "/f"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete StatFile err = %v, want ErrNotFound", err)
	}
}

func TestRenameMovesAndOverwrites(t *testing.T) {
	c, _ := pipeClient(t, 1<<20, "")
	ctx := context.Background()
	v, err := c.WriteFile(ctx, "/f", []byte("x"), 0, WriteOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Rename(ctx, "/f", "/.trash/f", v); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if _, err := c.StatFile(ctx, "/f"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("source still present: %v", err)
	}
	if _, err := c.StatFile(ctx, "/.trash/f"); err != nil {
		t.Fatalf("trash target missing: %v", err)
	}
	// The server overwrites an existing destination (no create-only); verify.
	v2, _ := c.WriteFile(ctx, "/g", []byte("y"), 0, WriteOpts{})
	if _, err := c.Rename(ctx, "/g", "/.trash/f", v2); err != nil {
		t.Fatalf("rename onto existing should overwrite, got: %v", err)
	}
}

func TestPathScoping(t *testing.T) {
	c, _ := pipeClient(t, 1<<20, "a1")
	ctx := context.Background()
	if _, err := c.WriteFile(ctx, "/notes.txt", []byte("x"), 0, WriteOpts{}); err != nil {
		t.Fatalf("scoped write: %v", err)
	}
	// A scoped ListDir("/") resolves to "/a1" and finds the file there — which
	// it only can if WriteFile stored it under the "/a1" prefix.
	entries, err := c.ListDir(ctx, "/")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name != "notes.txt" {
		t.Fatalf("scoped ListDir = %v", entries)
	}
	got, _, err := c.ReadFile(ctx, "/notes.txt")
	if err != nil || string(got) != "x" {
		t.Fatalf("scoped round-trip: %v %q", err, got)
	}
	if c.AgentID() != "a1" {
		t.Fatalf("AgentID = %q, want a1", c.AgentID())
	}
}

func TestTransportErrorPoisonsClient(t *testing.T) {
	srv, cli := net.Pipe()
	fs := newFakeServer()
	go fs.serve(srv)
	c := newClient(cli, 1<<20, "")
	ctx := context.Background()

	if _, err := c.WriteFile(ctx, "/f", []byte("x"), 0, WriteOpts{}); err != nil {
		t.Fatal(err)
	}
	_ = srv.Close() // kill the peer mid-life
	if err := c.Delete(ctx, "/f", 1); err == nil {
		t.Fatalf("expected a transport error after peer close")
	}
	// Poisoned: further calls short-circuit to net.ErrClosed rather than read a
	// possibly-desynchronised stream.
	if err := c.Delete(ctx, "/f", 1); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("after poison err = %v, want net.ErrClosed", err)
	}
}

func TestDownloadDetectsCorruptChunk(t *testing.T) {
	srv, cli := net.Pipe()
	fs := newFakeServer()
	fs.corruptChunks = true
	go fs.serve(srv)
	c := newClient(cli, 8, "")
	t.Cleanup(func() { _ = c.Close() })
	ctx := context.Background()

	// ChunkPut stores the correct bytes; only ChunkGet is corrupted, so the
	// write succeeds and the read must detect the tamper via the content hash.
	if _, err := c.WriteFile(ctx, "/f", []byte("abcdefghij"), 0, WriteOpts{}); err != nil {
		t.Fatal(err)
	}
	_, _, err := c.ReadFile(ctx, "/f")
	if err == nil || !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("ReadFile of corrupted chunk err = %v, want hash mismatch", err)
	}
}

// TestDialMTLS exercises the real Dial path: X.509 keypair, RootCAs, ServerName,
// and the mTLS handshake, then a ListDir over TLS. The client cert has no SPIFFE
// /agent SAN, so paths are unscoped.
func TestDialMTLS(t *testing.T) {
	caCert, caKey := makeCA(t)
	serverCertPEM, serverKeyPEM := leafCert(t, caCert, caKey, "localhost", false)
	clientCertPEM, clientKeyPEM := leafCert(t, caCert, caKey, "agent-1", true)

	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	fs := newFakeServer()
	fs.manifests["/hello.txt"] = &mstate{version: 1, size: 2, mode: 0o644}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go fs.serve(conn)
		}
	}()

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	creds := &AgentCredentials{
		ClientCertPEM: clientCertPEM,
		ClientKeyPEM:  clientKeyPEM,
		CACertPEM:     certPEM(caCert),
		ServerAddr:    "localhost:" + port,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := Dial(ctx, creds)
	if err != nil {
		t.Fatalf("Dial over mTLS: %v", err)
	}
	defer func() { _ = c.Close() }()

	entries, err := c.ListDir(ctx, "/")
	if err != nil {
		t.Fatalf("ListDir over TLS: %v", err)
	}
	if len(entries) != 1 || entries[0].Name != "hello.txt" {
		t.Fatalf("ListDir over TLS = %v", entries)
	}
}

// TestDialPresentsIntermediate is the regression test for the real-orlop bug:
// the server's client-CA pool is the ROOT ALONE, and the agent leaf is signed by
// a tenant INTERMEDIATE. Dial must present leaf+intermediate or the TLS 1.3
// handshake "succeeds" client-side but the server closes the connection, so the
// first op sees a closed conn. Here ClientCAs is the root only; a leaf-only
// presentation would fail — this passes only because Dial appends the
// intermediate from ca_chain_pem.
func TestDialPresentsIntermediate(t *testing.T) {
	root, rootKey := makeCA(t)
	interCert, interKey := intermediateCA(t, root, rootKey, "tenant-intermediate")
	clientPEM, clientKeyPEM := leafCert(t, interCert, interKey, "agent-x", true) // signed by the intermediate
	serverPEM, serverKeyPEM := leafCert(t, root, rootKey, "localhost", false)    // signed by the root

	serverCert, err := tls.X509KeyPair(serverPEM, serverKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	rootOnly := x509.NewCertPool()
	rootOnly.AddCert(root) // deliberately NOT the intermediate — mirrors orlop-server

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    rootOnly,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	fs := newFakeServer()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go fs.serve(conn)
		}
	}()

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	creds := &AgentCredentials{
		ClientCertPEM: clientPEM,
		ClientKeyPEM:  clientKeyPEM,
		// ca_chain_pem carries the intermediate AND the root, as enroll returns.
		CACertPEM:  append(append([]byte{}, certPEM(interCert)...), certPEM(root)...),
		ServerAddr: "localhost:" + port,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := Dial(ctx, creds)
	if err != nil {
		t.Fatalf("Dial (root-only verifier, intermediate-signed leaf): %v", err)
	}
	defer func() { _ = c.Close() }()
	// The op only completes if the server verified our client cert — i.e. we
	// presented the intermediate.
	if _, err := c.ListDir(ctx, "/"); err != nil {
		t.Fatalf("ListDir after intermediate-chain dial: %v", err)
	}
}

// ---- cert helpers ----------------------------------------------------------

func makeCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert, key
}

// intermediateCA mints a CA cert signed by parent (a sub-CA), so a leaf signed
// by it chains parent → intermediate → leaf.
func intermediateCA(t *testing.T, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, name string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert, key
}

func leafCert(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, name string, client bool) (certPEMOut, keyPEMOut []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if client {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.DNSNames = []string{name}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func certPEM(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}
