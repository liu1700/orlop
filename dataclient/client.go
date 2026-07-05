package dataclient

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/vmihailenco/msgpack/v5"
	"lukechampine.com/blake3"

	wire "github.com/liu1700/orlop/cmd/orlop-server/dataplane"
)

const (
	// DefaultChunkSize is the fixed size WriteFile splits uploads into. It is
	// well under the server's 20 MiB per-chunk cap; because chunks are
	// content-addressed, the boundary choice only affects dedup, never
	// correctness or readability of the resulting file.
	DefaultChunkSize = 1 << 20 // 1 MiB

	// defaultOpTimeout bounds a single request/response when the caller's
	// context carries no deadline of its own. When the context does carry a
	// deadline it is honoured verbatim, which — because it is absolute — also
	// bounds the whole of a multi-chunk Download/WriteFile, not just one frame.
	defaultOpTimeout = 30 * time.Second

	hashLen = 32 // BLAKE3-256 digest length
)

// Client is a data-plane connection to orlop-server for one agent. It speaks
// the binary frame protocol over a single mTLS TCP connection and offers
// whole-file operations that need no FUSE mount and take no mount lease.
//
// Paths are agent-relative: "/" is the agent's own root. The client prefixes
// every path with the agent id taken from the enrolled certificate, matching
// the server-side agent moat, so callers never write the id themselves.
//
// A Client serializes requests on its connection (one op in flight at a time);
// construct several Clients for concurrency. A transport error (I/O failure, or
// a context cancellation that interrupts a partially-read frame) poisons the
// Client: it is closed and every subsequent call returns net.ErrClosed, so a
// desynchronised stream can never be misread — Dial again. A returned
// *DataError/*StaleError is an ordinary protocol response and leaves the
// connection healthy and reusable.
type Client struct {
	conn      net.Conn
	chunkSize int
	agentID   string // path scope from the cert SAN; "" => send paths verbatim

	// session identity for lease-holding callers (a real mount session). Empty
	// for lease-free browsing; a non-mount session id is rejected by the server.
	sessionID    string
	allocationID string

	mu     sync.Mutex
	ridSeq uint64
	closed bool
}

// DialOption configures Dial.
type DialOption func(*dialConfig)

type dialConfig struct {
	chunkSize    int
	dialer       *net.Dialer
	sessionID    string
	allocationID string
}

// WithChunkSize overrides the upload chunk size in bytes (default 1 MiB). Values
// <= 0 or > 20 MiB are ignored in favour of the default / cap.
func WithChunkSize(n int) DialOption {
	return func(c *dialConfig) {
		if n > 0 && n <= 20<<20 {
			c.chunkSize = n
		}
	}
}

// WithDialer sets the net.Dialer used for the TCP connection (timeouts, etc.).
func WithDialer(d *net.Dialer) DialOption {
	return func(c *dialConfig) { c.dialer = d }
}

// WithSession tags every write on this connection with a mount session. Only
// callers that hold a real granted mount lease ("mount:<hex>") should set this;
// lease-free browsers must leave it unset (the server rejects a non-mount
// session id). Most callers of this package never need it.
func WithSession(sessionID, allocationID string) DialOption {
	return func(c *dialConfig) {
		c.sessionID = sessionID
		c.allocationID = allocationID
	}
}

// Dial opens an mTLS TCP connection to creds.ServerAddr, presenting the agent
// client certificate and verifying the server against creds.CACertPEM. The TLS
// ServerName is the host part of ServerAddr (which must be host:port). The
// agent id used to scope paths is read from the client certificate's SPIFFE
// /agent/<id> SAN.
func Dial(ctx context.Context, creds *AgentCredentials, opts ...DialOption) (*Client, error) {
	cfg := dialConfig{chunkSize: DefaultChunkSize}
	for _, o := range opts {
		o(&cfg)
	}

	cert, err := tls.X509KeyPair(creds.ClientCertPEM, creds.ClientKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("orlop dataclient: client keypair: %w", err)
	}
	// Present the signing intermediate(s) alongside the leaf. orlop-server's
	// client-CA pool is the org ROOT alone, so a TLS 1.3 verify of a leaf signed
	// by a tenant intermediate only succeeds if we send that intermediate too —
	// it arrives in ca_chain_pem next to the root. Without this the handshake
	// "succeeds" client-side but the server closes the connection right after,
	// surfacing as a closed conn on the first op.
	cert.Certificate = append(cert.Certificate, intermediateDERs(creds.CACertPEM)...)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(creds.CACertPEM) {
		return nil, fmt.Errorf("orlop dataclient: no CA certs in ca_chain_pem")
	}
	host, _, err := net.SplitHostPort(creds.ServerAddr)
	if err != nil {
		return nil, fmt.Errorf("orlop dataclient: server_addr %q must be host:port: %w", creds.ServerAddr, err)
	}

	dialer := cfg.dialer
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	raw, err := dialer.DialContext(ctx, "tcp", creds.ServerAddr)
	if err != nil {
		return nil, fmt.Errorf("orlop dataclient: dial %s: %w", creds.ServerAddr, err)
	}
	tconn := tls.Client(raw, &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      roots,
		ServerName:   host,
		MinVersion:   tls.VersionTLS13,
	})
	if err := tconn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("orlop dataclient: tls handshake with %s: %w", creds.ServerAddr, err)
	}

	c := newClient(tconn, cfg.chunkSize, agentIDFromCertDER(cert.Certificate))
	c.sessionID = cfg.sessionID
	c.allocationID = cfg.allocationID
	return c, nil
}

// newClient wraps an established connection. Exposed to tests so the frame
// protocol can be exercised over an in-process pipe without TLS; agentID scopes
// paths (pass "" to send them verbatim).
func newClient(conn net.Conn, chunkSize int, agentID string) *Client {
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}
	return &Client{conn: conn, chunkSize: chunkSize, agentID: agentID}
}

// AgentID returns the agent id paths are scoped to (from the certificate SAN).
func (c *Client) AgentID() string { return c.agentID }

// Close closes the underlying connection. Idempotent.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	return c.conn.Close()
}

// scope prefixes an agent-relative path with the agent's root, producing the
// canonical /<agentID>/... form the server's agent moat requires. With no agent
// scope (tenant-scoped cert / test) the path is passed through cleaned.
func (c *Client) scope(p string) string {
	clean := path.Clean("/" + strings.TrimPrefix(p, "/"))
	if c.agentID == "" {
		return clean
	}
	if clean == "/" {
		return "/" + c.agentID
	}
	return "/" + c.agentID + clean
}

// call sends one request frame and returns the matching response, decoding an
// error frame into a typed error. It serializes on c.mu so only one op is in
// flight per connection.
func (c *Client) call(ctx context.Context, op wire.Op, req, resp any) error {
	payload, err := msgpack.Marshal(req)
	if err != nil {
		return fmt.Errorf("orlop dataclient: marshal %s: %w", op, err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	c.ridSeq++
	rid := c.ridSeq

	// Honour the caller's absolute deadline verbatim (it also bounds a whole
	// multi-chunk op); default to a per-op timeout only when none is set.
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(defaultOpTimeout)
	}
	_ = c.conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = c.conn.SetDeadline(time.Now()) })
	defer stop()

	if err := wire.WriteFrame(c.conn, wire.Frame{Op: op, RID: rid, Payload: payload}); err != nil {
		return c.transportErr(ctx, err)
	}
	for {
		fr, err := wire.ReadFrame(c.conn)
		if err != nil {
			return c.transportErr(ctx, err)
		}
		if fr.RID != rid {
			// Unsolicited server push (e.g. a lease revoke) or a late frame.
			// Serialized calls mean our RID is the only one in flight, so any
			// non-matching frame is not our response — skip and keep reading
			// (bounded by the connection deadline set above).
			continue
		}
		if !fr.IsResponse() {
			return &DataError{Errno: wire.ErrnoEIO, Message: "expected a response frame"}
		}
		if fr.IsError() {
			var ep wire.ErrorPayload
			if e := msgpack.Unmarshal(fr.Payload, &ep); e != nil {
				return &DataError{Errno: wire.ErrnoEIO, Message: "undecodable error payload"}
			}
			return errorFromPayload(ep)
		}
		if resp != nil {
			if e := msgpack.Unmarshal(fr.Payload, resp); e != nil {
				return fmt.Errorf("orlop dataclient: unmarshal %s response: %w", op, e)
			}
		}
		return nil
	}
}

// transportErr converts an I/O failure into the caller-facing error and poisons
// the Client: the connection may now be byte-misaligned (a partially read frame
// on a cancel), so it is closed and every later call returns net.ErrClosed
// rather than risk decoding a desynchronised stream. Holds c.mu (its only
// caller does).
func (c *Client) transportErr(ctx context.Context, err error) error {
	if !c.closed {
		c.closed = true
		_ = c.conn.Close()
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// ---- Public types ----------------------------------------------------------

// DirEntry is one child returned by ListDir.
type DirEntry struct {
	Name   string // base name, no slashes
	Kind   string // "file", "dir", or "symlink"
	Size   uint64
	Mode   uint32 // POSIX permission bits
	Target string // symlink destination, when Kind == "symlink"
}

// IsDir reports whether the entry is a directory.
func (e DirEntry) IsDir() bool { return e.Kind == "dir" }

// FileInfo describes a single file's manifest metadata. Version is the CAS
// token to pass back to WriteFile/Delete/Rename.
type FileInfo struct {
	Path    string
	Size    uint64
	Mode    uint32
	Mtime   int64 // Unix seconds
	Version uint64
}

// WriteOpts carries optional metadata for WriteFile. The zero value is valid:
// Mode defaults to 0644 and Mtime to the current time.
type WriteOpts struct {
	Mode  uint32
	Mtime int64
}

// ---- High-level file operations --------------------------------------------

// ListDir lists the immediate children of a directory. path is agent-relative
// ("/" for the agent root). Symlinks are returned as opaque entries.
func (c *Client) ListDir(ctx context.Context, dir string) ([]DirEntry, error) {
	var resp wire.ListResponse
	if err := c.call(ctx, wire.OpList, wire.ListRequest{Path: c.scope(dir)}, &resp); err != nil {
		return nil, err
	}
	out := make([]DirEntry, 0, len(resp.Entries))
	for _, e := range resp.Entries {
		out = append(out, DirEntry{Name: e.Name, Kind: e.Kind, Size: e.Size, Mode: e.Mode, Target: e.Target})
	}
	return out, nil
}

// StatFile returns manifest metadata (including the CAS Version) for a regular
// file. Because it reads the file manifest, a missing path AND a directory both
// return ErrNotFound (a directory has no manifest); use ListDir for directories.
func (c *Client) StatFile(ctx context.Context, filePath string) (FileInfo, error) {
	var mg wire.ManifestGetResponse
	if err := c.call(ctx, wire.OpManifestGet, wire.ManifestGetRequest{Path: c.scope(filePath)}, &mg); err != nil {
		return FileInfo{}, err
	}
	return FileInfo{Path: filePath, Size: mg.Size, Mode: mg.Mode, Mtime: mg.Mtime, Version: mg.Version}, nil
}

// Download streams a file's bytes to w and returns its metadata. It fetches the
// manifest once and streams the referenced chunks in order, verifying each
// chunk's content-address (BLAKE3), its length, contiguity, and the total
// against the manifest size — so corrupted or non-contiguous data is reported
// rather than silently returned. Note there is no read lease: a concurrent
// overwrite that GCs a chunk mid-stream can make Download fail partway, after
// some bytes have already been written to w.
func (c *Client) Download(ctx context.Context, filePath string, w io.Writer) (FileInfo, error) {
	var mg wire.ManifestGetResponse
	if err := c.call(ctx, wire.OpManifestGet, wire.ManifestGetRequest{Path: c.scope(filePath)}, &mg); err != nil {
		return FileInfo{}, err
	}
	var running uint64
	for _, ch := range mg.Chunks {
		if ch.Offset != running {
			return FileInfo{}, &DataError{Errno: wire.ErrnoEIO, Message: "non-contiguous manifest chunk"}
		}
		var cr wire.ChunkGetResponse
		if err := c.call(ctx, wire.OpChunkGet, wire.ChunkGetRequest{Hash: ch.Hash}, &cr); err != nil {
			return FileInfo{}, err
		}
		if uint32(len(cr.Bytes)) != ch.Len {
			return FileInfo{}, &DataError{Errno: wire.ErrnoEIO, Message: "chunk length mismatch"}
		}
		if sum := blake3.Sum256(cr.Bytes); subtle.ConstantTimeCompare(sum[:], ch.Hash) != 1 {
			return FileInfo{}, &DataError{Errno: wire.ErrnoEIO, Message: "chunk hash mismatch (corrupt data)"}
		}
		if _, err := w.Write(cr.Bytes); err != nil {
			return FileInfo{}, err
		}
		running += uint64(ch.Len)
	}
	if running != mg.Size {
		return FileInfo{}, &DataError{Errno: wire.ErrnoEIO, Message: "assembled size does not match manifest"}
	}
	return FileInfo{Path: filePath, Size: mg.Size, Mode: mg.Mode, Mtime: mg.Mtime, Version: mg.Version}, nil
}

// ReadFile reads an entire file into memory and returns its metadata. For large
// files prefer Download to a streaming writer.
func (c *Client) ReadFile(ctx context.Context, filePath string) ([]byte, FileInfo, error) {
	var buf bytes.Buffer
	info, err := c.Download(ctx, filePath, &buf)
	if err != nil {
		return nil, FileInfo{}, err
	}
	return buf.Bytes(), info, nil
}

// WriteFile writes data to path under compare-and-swap. expectedVersion is 0 to
// create a new file, or the file's current Version to overwrite it. A version
// mismatch — including creating (0) a path that already exists — returns a
// *StaleError carrying the current version. It splits data into
// content-addressed chunks, stores them, then commits the manifest. Returns the
// new version.
func (c *Client) WriteFile(ctx context.Context, filePath string, data []byte, expectedVersion uint64, opts WriteOpts) (uint64, error) {
	scoped := c.scope(filePath)
	chunks := make([]wire.ChunkRef, 0, len(data)/c.chunkSize+1)
	for off := 0; off < len(data); off += c.chunkSize {
		end := off + c.chunkSize
		if end > len(data) {
			end = len(data)
		}
		piece := data[off:end]
		sum := blake3.Sum256(piece)
		hash := sum[:]
		if err := c.call(ctx, wire.OpChunkPut, wire.ChunkPutRequest{
			Hash:      hash,
			Bytes:     piece,
			SessionID: c.sess(),
		}, &wire.ChunkPutResponse{}); err != nil {
			return 0, err
		}
		chunks = append(chunks, wire.ChunkRef{Hash: hash, Offset: uint64(off), Len: uint32(len(piece))})
	}

	mode := opts.Mode
	if mode == 0 {
		mode = 0o644
	}
	mtime := opts.Mtime
	if mtime == 0 {
		mtime = time.Now().Unix()
	}
	var resp wire.ManifestPutResponse
	err := c.call(ctx, wire.OpManifestPut, wire.ManifestPutRequest{
		Path:            scoped,
		VersionExpected: expectedVersion,
		Size:            uint64(len(data)),
		Mode:            mode,
		Mtime:           mtime,
		Chunks:          chunks,
		SessionID:       c.sess(),
		AllocationID:    c.alloc(),
	}, &resp)
	if err != nil {
		return 0, err
	}
	return resp.Version, nil
}

// Delete removes a file under compare-and-swap. expectedVersion must be the
// file's current Version (a *StaleError otherwise; its CurrentVersion is not
// populated for delete conflicts, so re-Stat to recover). This is a hard
// delete; for a restore window Rename into a trash namespace first.
func (c *Client) Delete(ctx context.Context, filePath string, expectedVersion uint64) error {
	return c.call(ctx, wire.OpManifestDelete, wire.ManifestDeleteRequest{
		Path:            c.scope(filePath),
		ExpectedVersion: expectedVersion,
		SessionID:       c.sess(),
		AllocationID:    c.alloc(),
	}, &wire.ManifestDeleteResponse{})
}

// Rename moves a file from -> to. expectedVersionFrom must be the source's
// current Version (a *StaleError otherwise). NOTE: the server OVERWRITES an
// existing destination regular file (it does not enforce create-only), so
// callers that need collision safety — e.g. moving into a trash namespace —
// must either pick a unique destination path or use RenameNoReplace. Returns
// the new version at the destination.
func (c *Client) Rename(ctx context.Context, from, to string, expectedVersionFrom uint64) (uint64, error) {
	return c.rename(ctx, from, to, expectedVersionFrom, false)
}

// RenameNoReplace is Rename with create-only semantics: if the destination
// already exists it fails with ErrExists instead of overwriting it (POSIX
// RENAME_NOREPLACE). Requires an orlop-server that honors no_replace; an older
// server silently ignores the flag and overwrites, so a caller that must not
// clobber against an unknown server version should keep a stat-based guard.
func (c *Client) RenameNoReplace(ctx context.Context, from, to string, expectedVersionFrom uint64) (uint64, error) {
	return c.rename(ctx, from, to, expectedVersionFrom, true)
}

func (c *Client) rename(ctx context.Context, from, to string, expectedVersionFrom uint64, noReplace bool) (uint64, error) {
	var resp wire.ManifestRenameResponse
	err := c.call(ctx, wire.OpManifestRename, wire.ManifestRenameRequest{
		From:                c.scope(from),
		To:                  c.scope(to),
		ExpectedVersionFrom: expectedVersionFrom,
		ExpectedVersionTo:   0,
		NoReplace:           noReplace,
		SessionID:           c.sess(),
		AllocationID:        c.alloc(),
	}, &resp)
	if err != nil {
		return 0, err
	}
	return resp.NewVersionAtTo, nil
}

// MakeDir creates a directory. mode 0 defaults to 0755.
func (c *Client) MakeDir(ctx context.Context, dir string, mode uint32) error {
	if mode == 0 {
		mode = 0o755
	}
	return c.call(ctx, wire.OpDirCreate, wire.DirCreateRequest{
		Path:      c.scope(dir),
		Mode:      mode,
		SessionID: c.sess(),
	}, &wire.DirCreateResponse{})
}

// RemoveDir removes an empty directory (ErrNotEmpty if it has children).
func (c *Client) RemoveDir(ctx context.Context, dir string) error {
	return c.call(ctx, wire.OpDirRemove, wire.DirRemoveRequest{
		Path:      c.scope(dir),
		SessionID: c.sess(),
	}, &wire.DirRemoveResponse{})
}

func (c *Client) sess() *string  { return optStr(c.sessionID) }
func (c *Client) alloc() *string { return optStr(c.allocationID) }

// optStr returns a pointer to s, or nil when s is empty, so an unset optional
// msgpack field is omitted on the wire.
func optStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// intermediateDERs returns the DER of the non-self-signed (intermediate) certs
// in a PEM chain — the certs a client must present alongside its leaf so a
// root-only verifier can build leaf → intermediate → root. Self-signed roots
// are skipped (they belong in the verifier's pool, not the presented chain).
func intermediateDERs(pemChain []byte) [][]byte {
	var out [][]byte
	rest := pemChain
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil || bytes.Equal(c.RawSubject, c.RawIssuer) {
			continue // parse error or a self-signed root
		}
		out = append(out, block.Bytes)
	}
	return out
}

// agentIDFromCertDER extracts the agent id from the leaf certificate's SPIFFE
// /agent/<id> SAN. chain is tls.Certificate.Certificate (leaf first). Returns
// "" for a tenant-scoped cert with no /agent SAN.
func agentIDFromCertDER(chain [][]byte) string {
	if len(chain) == 0 {
		return ""
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return ""
	}
	for _, u := range leaf.URIs {
		segs := strings.Split(strings.Trim(u.Path, "/"), "/")
		for i := 0; i+1 < len(segs); i++ {
			if segs[i] == "agent" && segs[i+1] != "" {
				return segs[i+1]
			}
		}
	}
	return ""
}
