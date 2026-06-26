package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/vmihailenco/msgpack/v5"

	"github.com/liu1700/orlop/cmd/orlop-server/dataplane"
)

// joinVirtual joins a parent virtual path and a child name without
// double-slashing the root.
func joinVirtual(parent, name string) string {
	if parent == "/" {
		return "/" + name
	}
	return strings.TrimRight(parent, "/") + "/" + name
}

const orlopQUICALPN = "orlop-data"

// runDataPlaneListener accepts mTLS connections carrying the data-plane binary protocol and
// dispatches each frame to the existing route/policy/storage logic.
//
// One read goroutine per connection sequences inbound frames. List/Stat/Read
// requests are handled in their own goroutines so a slow op (e.g. large READ)
// can't block fast ones (STAT). All responses funnel back through one writer
// goroutine keyed by the connection — wire ordering of responses is whatever
// the workers produce, and clients route by `rid`.
func runDataPlaneListener(ctx context.Context, logger *slog.Logger, state *serverState, bind string, tlsConfig *tls.Config) error {
	errs := make(chan error, 2)
	go func() {
		errs <- runV2TCPListener(ctx, logger, state, bind, tlsConfig)
	}()
	go func() {
		errs <- runV2QUICListener(ctx, logger, state, bind, tlsConfig)
	}()

	select {
	case <-ctx.Done():
		return nil
	case err := <-errs:
		return err
	}
}

func runV2TCPListener(ctx context.Context, logger *slog.Logger, state *serverState, bind string, tlsConfig *tls.Config) error {
	ln, err := tls.Listen("tcp", bind, tlsConfig)
	if err != nil {
		return err
	}
	logger.Info("orlop-server data-plane TCP listening with mTLS", "bind", bind)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			logger.Error("data-plane accept failed", "error", err)
			continue
		}
		go serveV2TCPConnection(logger, state, conn)
	}
}

func runV2QUICListener(ctx context.Context, logger *slog.Logger, state *serverState, bind string, tlsConfig *tls.Config) error {
	quicTLSConfig := tlsConfig.Clone()
	quicTLSConfig.NextProtos = []string{orlopQUICALPN}
	listener, err := quic.ListenAddr(bind, quicTLSConfig, &quic.Config{
		KeepAlivePeriod:    30 * time.Second,
		MaxIdleTimeout:     2 * time.Minute,
		MaxIncomingStreams: 128,
	})
	if err != nil {
		return err
	}
	logger.Info("orlop-server data-plane QUIC listening with mTLS", "bind", bind)

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {
		conn, err := listener.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			logger.Error("data-plane QUIC accept failed", "error", err)
			continue
		}
		go serveV2QUICConnection(ctx, logger, state, conn)
	}
}

func serveV2TCPConnection(logger *slog.Logger, state *serverState, conn net.Conn) {
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return
	}
	if err := tlsConn.Handshake(); err != nil {
		logger.Debug("data-plane handshake failed", "error", err)
		return
	}

	serveFrames(logger, state, conn, tlsConn.ConnectionState())
}

func serveV2QUICConnection(ctx context.Context, logger *slog.Logger, state *serverState, conn *quic.Conn) {
	tlsState := conn.ConnectionState().TLS
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go serveV2QUICStream(logger, state, stream, tlsState)
	}
}

func serveV2QUICStream(logger *slog.Logger, state *serverState, stream *quic.Stream, tlsState tls.ConnectionState) {
	defer stream.Close()
	serveFrames(logger, state, stream, tlsState)
}

func serveFrames(logger *slog.Logger, state *serverState, conn io.ReadWriteCloser, tlsState tls.ConnectionState) {
	// Bound concurrent framed sessions. Non-blocking acquire: at the cap we
	// reject (close) rather than queue, so a connection flood fails fast instead
	// of growing goroutines/memory without limit.
	if state.connSem != nil {
		select {
		case state.connSem <- struct{}{}:
			defer func() { <-state.connSem }()
		default:
			logger.Warn("data-plane session cap reached; rejecting connection",
				"limit", cap(state.connSem))
			return
		}
	}
	if len(tlsState.PeerCertificates) == 0 {
		return
	}
	cert := tlsState.PeerCertificates[0]
	tenant, ident, ok := identifyV2Peer(logger, state, cert)
	if !ok {
		return
	}
	// Defense-in-depth: confirm the intermediate that signed this leaf is scoped
	// to the same tenant as the leaf's SAN, so a leaked tenant-intermediate key
	// can't forge a cross-tenant cert against the shared root.
	if !checkTenantBinding(logger, ident.TenantID, tlsState.VerifiedChains) {
		return
	}

	writer := newFrameWriter(conn)
	defer writer.close()
	connID := state.conns.Register(writer)
	writer.connID = connID
	// Defers run LIFO: ReleaseAllForConn fires first (may push revoke frames
	// to peers), then Unregister, then writer.close. Reordering breaks the
	// invariant that lease cleanup can still write to the live socket.
	defer state.conns.Unregister(connID)
	defer tenant.leases.ReleaseAllForConn(connID)

	for {
		frame, err := dataplane.ReadFrame(conn)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				logger.Debug("data-plane read frame", "error", err)
			}
			return
		}
		switch frame.Op {
		case dataplane.OpPing:
			writer.send(dataplane.Frame{
				Op:      dataplane.OpPing,
				Flags:   dataplane.FlagResponse,
				RID:     frame.RID,
				Payload: frame.Payload,
			})
		case dataplane.OpClose:
			return
		case dataplane.OpLeaseGrant, dataplane.OpLeaseRefresh, dataplane.OpLeaseRelease:
			f := frame
			state.goRequest(func() { handleLeaseRequest(state, tenant, ident, writer, connID, f) })
		default:
			if _, ok := OpTable[frame.Op]; ok {
				f := frame
				state.goRequest(func() { handleRequest(state, tenant, ident, writer, f) })
			} else {
				writeFrameError(writer, frame.Op, frame.RID, dataplane.ErrEINVAL("unsupported op"))
			}
		}
	}
}

func identifyV2Peer(logger *slog.Logger, state *serverState, cert *x509.Certificate) (*tenantState, Identity, bool) {
	agentID := certAgentID(cert)
	if agentID == "" {
		return nil, Identity{}, false
	}
	tenantID, err := certTenantID(cert, state.trustDomain)
	if err != nil {
		logger.Debug("data-plane tenant id missing", "error", err)
		return nil, Identity{}, false
	}
	tenant, ok := state.tenant(tenantID)
	if !ok {
		logger.Debug("data-plane tenant not configured", "tenant", tenantID)
		return nil, Identity{}, false
	}
	// Single isolation policy: every data-plane cert MUST be agent-scoped (carry a
	// `spiffe://<td>/agent/<id>` SAN). A tenant-only cert is rejected at the door —
	// the tenant-wide path is removed. orlop mints agent-scoped certs for BOTH
	// registered and anonymous users (control-plane → /v1/entities per-user tenant
	// → /agent/enroll); only the legacy standalone anon flow produced tenant-only
	// certs, and it is being retired. See
	// the agent-isolation and cert-bootstrap design.
	scopedAgentID := certScopedAgentID(cert, state.trustDomain)
	if scopedAgentID == "" {
		logger.Debug("data-plane cert has no agent scope; rejecting", "tenant", tenantID)
		return nil, Identity{}, false
	}
	ident := Identity{
		AgentID:       agentID,
		TenantID:      tenantID,
		CertSubject:   cert.Subject.String(),
		ScopedAgentID: scopedAgentID,
	}
	if cert.SerialNumber != nil {
		ident.CertSerial = cert.SerialNumber.String()
	}
	return tenant, ident, true
}

// OpHandler is the uniform shape of every request-handling dataplane op
// (excludes Ping/Close, which the read loop short-circuits, and the lease
// ops, which need the connID).
type OpHandler func(s *serverState, tenant *tenantState, ident Identity, w *frameWriter, frame dataplane.Frame)

// opSpec is one entry in the dispatch table: the canonical Prometheus label
// (dashboards depend on these names — never change without an alert plan)
// plus the handler.
type opSpec struct {
	label   string
	handler OpHandler
}

// OpTable is the single source of truth for dataplane ops. Adding or
// removing an op is a one-line change here; the read loop, dispatch, and
// metrics naming all read from this map.
var OpTable = map[dataplane.Op]opSpec{
	dataplane.OpList:              {"list", handleList},
	dataplane.OpStat:              {"stat", handleStat},
	dataplane.OpManifestGet:       {"manifest_get", handleManifestGet},
	dataplane.OpManifestPut:       {"manifest_put", handleManifestPut},
	dataplane.OpManifestDelete:    {"manifest_delete", handleManifestDelete},
	dataplane.OpManifestRename:    {"manifest_rename", handleManifestRename},
	dataplane.OpDirCreate:         {"dir_create", handleDirCreate},
	dataplane.OpDirRemove:         {"dir_remove", handleDirRemove},
	dataplane.OpSetattr:           {"setattr", handleSetattr},
	dataplane.OpSymlink:           {"symlink", handleSymlink},
	dataplane.OpReadlink:          {"readlink", handleReadlink},
	dataplane.OpMknod:             {"mknod", handleMknod},
	dataplane.OpChunkGet:          {"chunk_get", handleChunkGet},
	dataplane.OpChunkHas:          {"chunk_has", handleChunkHas},
	dataplane.OpChunkPut:          {"chunk_put", handleChunkPut},
	dataplane.OpJournalQuery:      {"journal_query", handleJournalQuery},
	dataplane.OpJournalRevertPath: {"journal_revert_path", handleJournalRevertPath},
}

// nonTableOpLabels maps the ops handled outside OpTable (ping/close,
// connection-aware lease ops) to their metric labels. Kept here to keep all
// label strings discoverable in one file.
var nonTableOpLabels = map[dataplane.Op]string{
	dataplane.OpPing:         "ping",
	dataplane.OpClose:        "close",
	dataplane.OpLeaseGrant:   "lease_grant",
	dataplane.OpLeaseRefresh: "lease_refresh",
	dataplane.OpLeaseRelease: "lease_release",
	dataplane.OpLeaseRevoke:  "lease_revoke",
}

func handleRequest(s *serverState, tenant *tenantState, ident Identity, w *frameWriter, frame dataplane.Frame) {
	defer recoverRequest(s, w, frame)
	spec, ok := OpTable[frame.Op]
	if !ok {
		writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEINVAL("unsupported op"))
		return
	}
	started := time.Now()
	defer s.metrics.observeDuration(spec.label, started)
	spec.handler(s, tenant, ident, w, frame)
}

// opLabel returns the canonical Prometheus label for a dataplane op code.
// Stable across releases — dashboards rely on these names.
func opLabel(op dataplane.Op) string {
	if spec, ok := OpTable[op]; ok {
		return spec.label
	}
	if label, ok := nonTableOpLabels[op]; ok {
		return label
	}
	return "unknown"
}

// decodeReq unmarshals frame.Payload into a value of type T. On failure
// writes an EINVAL response and returns ok=false; the handler should return
// immediately. label appears in the error message ("malformed <label> payload").
func decodeReq[T any](w *frameWriter, frame dataplane.Frame, label string) (T, bool) {
	var req T
	if err := safeUnmarshal(frame.Payload, &req); err != nil {
		writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEINVAL("malformed "+label+" payload"))
		return req, false
	}
	return req, true
}

// sendResp marshals val and sends it as a response frame for the request in
// frame. On marshal failure writes EIO. Handlers that build their response
// frame manually (e.g. to set custom flags or hints) bypass this helper.
func sendResp[T any](w *frameWriter, frame dataplane.Frame, val T) {
	payload, err := msgpack.Marshal(val)
	if err != nil {
		writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEIO(err.Error()))
		return
	}
	w.send(dataplane.Frame{Op: frame.Op, Flags: dataplane.FlagResponse, RID: frame.RID, Payload: payload})
}

func handleList(s *serverState, tenant *tenantState, ident Identity, w *frameWriter, frame dataplane.Frame) {
	req, ok := decodeReq[dataplane.ListRequest](w, frame, "list")
	if !ok {
		return
	}
	if !s.policy.Permits(policyPath(req.Path)) {
		s.recordDataAudit(ident, "list_entries", req.Path, nil, false, nil)
		writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEACCES("path denied by policy"))
		return
	}
	if !s.checkAgentPath(ident, w, frame, req.Path) {
		return
	}

	// Manifest dir_entries is the source of truth for listings.
	children, err := tenant.manifests.ListChildren(req.Path)
	if err != nil {
		writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEIO(err.Error()))
		return
	}
	entries := make([]dataplane.EntryWire, 0, len(children))
	for _, c := range children {
		child := joinVirtual(req.Path, c.Name)
		if !s.policy.Permits(policyPath(child)) {
			continue
		}
		e := dataplane.EntryWire{Name: c.Name, Kind: c.Kind, Size: c.Size, Mode: c.Mode, Uid: c.Uid, Gid: c.Gid, Atime: c.Atime}
		// Best-effort: ListChildren's JOIN does not cover special_nodes, so a
		// special node lands here as "dir". Reclassify it (and carry rdev) with a
		// targeted lookup. On error or absence we leave the "dir" default — a
		// listing must not fail because one child could not be classified.
		if c.Kind == "dir" {
			if snMode, snRdev, snUID, snGID, snAtime, snKind, isSpecial, snErr := tenant.manifests.SpecialNodeInfo(child); snErr == nil && isSpecial {
				e.Kind = snKind
				e.Mode = snMode
				e.Rdev = snRdev
				e.Uid = snUID
				e.Gid = snGID
				e.Atime = snAtime
				e.Size = 0
			}
		}
		entries = append(entries, e)
	}
	writeFrameList(w, frame.RID, entries)
	s.recordDataAudit(ident, "list_entries", req.Path, nil, true, nil)
}

func handleStat(s *serverState, tenant *tenantState, ident Identity, w *frameWriter, frame dataplane.Frame) {
	req, ok := decodeReq[dataplane.StatRequest](w, frame, "stat")
	if !ok {
		return
	}
	if !s.policy.Permits(policyPath(req.Path)) {
		s.recordDataAudit(ident, "head_file", req.Path, nil, false, nil)
		writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEACCES("path denied by policy"))
		return
	}
	if !s.checkAgentPath(ident, w, frame, req.Path) {
		return
	}
	// Source of truth, in order: manifest (file) → symlinks (symlink) →
	// dir_entries (directory). Each carries its own mode + owner + atime.
	mf, err := tenant.manifests.Get(req.Path)
	if err != nil && !errors.Is(err, ErrManifestNotFound) {
		writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEIO(err.Error()))
		return
	}
	base := filepath.Base(req.Path)
	var entry dataplane.EntryWire
	switch {
	case err == nil:
		entry = dataplane.EntryWire{Name: base, Kind: "file", Size: mf.Size, Mode: mf.Mode, Uid: mf.Uid, Gid: mf.Gid, Atime: mf.Atime}
	default:
		if target, mode, uid, gid, atime, isSym, sErr := tenant.manifests.SymlinkInfo(req.Path); sErr != nil {
			writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEIO(sErr.Error()))
			return
		} else if isSym {
			entry = dataplane.EntryWire{Name: base, Kind: "symlink", Size: uint64(len(target)), Mode: mode, Uid: uid, Gid: gid, Atime: atime, Target: target}
			break
		}
		if snMode, snRdev, snUID, snGID, snAtime, snKind, isSpecial, snErr := tenant.manifests.SpecialNodeInfo(req.Path); snErr != nil {
			writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEIO(snErr.Error()))
			return
		} else if isSpecial {
			entry = dataplane.EntryWire{Name: base, Kind: snKind, Size: 0, Mode: snMode, Uid: snUID, Gid: snGID, Atime: snAtime, Rdev: snRdev}
			break
		}
		mode, uid, gid, atime, isDir, dirErr := tenant.manifests.DirInfo(req.Path)
		if dirErr != nil {
			writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEIO(dirErr.Error()))
			return
		}
		if !isDir {
			writeFrameError(w, frame.Op, frame.RID, dataplane.ErrENOENT("path not found"))
			return
		}
		entry = dataplane.EntryWire{Name: base, Kind: "dir", Size: 0, Mode: mode, Uid: uid, Gid: gid, Atime: atime}
	}
	sendResp(w, frame, dataplane.StatResponse{Entry: entry})
	s.recordDataAudit(ident, "head_file", req.Path, &entry.Size, true, nil)
}

func handleManifestGet(s *serverState, tenant *tenantState, ident Identity, w *frameWriter, frame dataplane.Frame) {
	req, ok := decodeReq[dataplane.ManifestGetRequest](w, frame, "manifest_get")
	if !ok {
		return
	}
	if !s.policy.Permits(policyPath(req.Path)) {
		s.recordManifestAudit(ident, "manifest_get", req.Path, 0, 0, false, nil)
		writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEACCES("path denied by policy"))
		return
	}
	if !s.checkAgentPath(ident, w, frame, req.Path) {
		return
	}
	mf, err := tenant.manifests.Get(req.Path)
	if err != nil {
		if errors.Is(err, ErrManifestNotFound) {
			writeFrameError(w, frame.Op, frame.RID, dataplane.ErrENOENT("manifest not found"))
			return
		}
		writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEIO(err.Error()))
		return
	}
	resp := dataplane.ManifestGetResponse{
		Version: mf.Version,
		Size:    mf.Size,
		Mode:    mf.Mode,
		Mtime:   mf.Mtime,
		Chunks:  toWireChunks(mf.Chunks),
	}
	payload, err := msgpack.Marshal(resp)
	if err != nil {
		writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEIO(err.Error()))
		return
	}
	w.send(dataplane.Frame{Op: frame.Op, Flags: dataplane.FlagResponse, RID: frame.RID, Payload: payload})
	// Marshal once + observe payload size: skip sendResp here so we can pass
	// len(payload) to the metrics histogram.
	s.metrics.observeOp("manifest_get", "out", uint64(len(payload)))
	s.recordManifestAudit(ident, "manifest_get", req.Path, mf.Size, mf.Version, true, nil)
}

func handleManifestPut(s *serverState, tenant *tenantState, ident Identity, w *frameWriter, frame dataplane.Frame) {
	req, ok := decodeReq[dataplane.ManifestPutRequest](w, frame, "manifest_put")
	if !ok {
		return
	}
	if !s.policy.Permits(policyPath(req.Path)) {
		s.recordManifestAudit(ident, "manifest_put", req.Path, 0, 0, false, req.SessionID)
		writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEACCES("path denied by policy"))
		return
	}
	if !s.checkAgentPath(ident, w, frame, req.Path) {
		return
	}
	if tenant.leases != nil {
		ctx, cancel := context.WithTimeout(context.Background(), tenant.leases.cfg.revokeTimeout+time.Second)
		defer cancel()
		if err := tenant.leases.YieldFor(ctx, ident.AgentID, req.Path, "manifest_put_contention"); err != nil {
			if errors.Is(err, errLeaseHeld) {
				writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEBUSY("lease_held"))
				return
			}
			writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEIO(err.Error()))
			return
		}
	}
	mf := Manifest{
		Path:   req.Path,
		Size:   req.Size,
		Mode:   req.Mode,
		Mtime:  req.Mtime,
		Chunks: fromWireChunks(req.Chunks),
	}
	sessionID := derefSession(req.SessionID)
	allocationID := derefSession(req.AllocationID)
	activeLeaseHex, ok := s.checkSessionFence(tenant, w, frame, sessionID, allocationID)
	if !ok {
		return
	}
	newVersion, err := tenant.manifests.PutWithLeaseCheck(req.Path, req.VersionExpected, mf, sessionID, allocationID, ident.AgentID, activeLeaseHex)
	if err != nil {
		if errors.Is(err, ErrVersionConflict) {
			// last_writer is best-effort metadata for the recovery hint.
			// Swallow lookup errors so a broken routes.db doesn't morph the
			// underlying CAS conflict into a different failure mode.
			lastWriter, _ := tenant.journal.LookupLastWriter(req.Path)
			payload := dataplane.ErrESTALE("manifest version conflict").
				WithRecovery(buildCasConflictHint(req.VersionExpected, err, lastWriter))
			writeFrameError(w, frame.Op, frame.RID, payload)
			return
		}
		writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEIO(err.Error()))
		return
	}
	sendResp(w, frame, dataplane.ManifestPutResponse{Version: newVersion})
	s.metrics.observeOp("manifest_put", "in", req.Size)
	s.recordManifestAudit(ident, "manifest_put", req.Path, req.Size, newVersion, true, req.SessionID)
}

// manifestErrToWire maps known ManifestStore sentinel errors to wire error
// payloads. Unrecognised errors map to ErrEIO.
func manifestErrToWire(err error) dataplane.ErrorPayload {
	switch {
	case errors.Is(err, ErrManifestNotFound):
		return dataplane.ErrENOENT(err.Error())
	case errors.Is(err, ErrParentNotFound):
		return dataplane.ErrENOENT(err.Error())
	case errors.Is(err, ErrAlreadyExists):
		return dataplane.ErrEEXIST(err.Error())
	case errors.Is(err, ErrVersionConflict):
		return dataplane.ErrESTALE(err.Error())
	case errors.Is(err, ErrNotEmpty):
		return dataplane.ErrENOTEMPTY(err.Error())
	case errors.Is(err, ErrNotDir):
		return dataplane.ErrENOTDIR(err.Error())
	case errors.Is(err, ErrIsDir):
		return dataplane.ErrEISDIR(err.Error())
	default:
		return dataplane.ErrEIO(err.Error())
	}
}

func handleManifestDelete(s *serverState, tenant *tenantState, ident Identity, w *frameWriter, frame dataplane.Frame) {
	req, ok := decodeReq[dataplane.ManifestDeleteRequest](w, frame, "manifest_delete")
	if !ok {
		return
	}
	if !s.policy.Permits(policyPath(req.Path)) {
		s.recordDataAudit(ident, "manifest_delete", req.Path, nil, false, req.SessionID)
		writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEACCES("path denied by policy"))
		return
	}
	if !s.checkAgentPath(ident, w, frame, req.Path) {
		return
	}
	delSessionID := derefSession(req.SessionID)
	delAllocationID := derefSession(req.AllocationID)
	delActiveLeaseHex, ok := s.checkSessionFence(tenant, w, frame, delSessionID, delAllocationID)
	if !ok {
		return
	}
	if err := tenant.manifests.DeleteWithLeaseCheck(req.Path, req.ExpectedVersion, delSessionID, delAllocationID, ident.AgentID, delActiveLeaseHex); err != nil {
		writeFrameError(w, frame.Op, frame.RID, manifestErrToWire(err))
		return
	}
	sendResp(w, frame, dataplane.ManifestDeleteResponse{})
	s.recordDataAudit(ident, "manifest_delete", req.Path, nil, true, req.SessionID)
}

func handleManifestRename(s *serverState, tenant *tenantState, ident Identity, w *frameWriter, frame dataplane.Frame) {
	req, ok := decodeReq[dataplane.ManifestRenameRequest](w, frame, "manifest_rename")
	if !ok {
		return
	}
	if !s.policy.Permits(policyPath(req.From)) || !s.policy.Permits(policyPath(req.To)) {
		s.recordDataAudit(ident, "manifest_rename", req.From, nil, false, req.SessionID)
		writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEACCES("path denied by policy"))
		return
	}
	// Both endpoints of the rename must be inside the agent's subtree.
	if !s.checkAgentPath(ident, w, frame, req.From) {
		return
	}
	if !s.checkAgentPath(ident, w, frame, req.To) {
		return
	}
	renSessionID := derefSession(req.SessionID)
	renAllocationID := derefSession(req.AllocationID)
	renActiveLeaseHex, ok := s.checkSessionFence(tenant, w, frame, renSessionID, renAllocationID)
	if !ok {
		return
	}
	newV, err := tenant.manifests.RenameWithLeaseCheck(req.From, req.To, req.ExpectedVersionFrom, req.ExpectedVersionTo, renSessionID, renAllocationID, ident.AgentID, renActiveLeaseHex)
	if err != nil {
		writeFrameError(w, frame.Op, frame.RID, manifestErrToWire(err))
		return
	}
	sendResp(w, frame, dataplane.ManifestRenameResponse{NewVersionAtTo: newV})
	s.recordDataAudit(ident, "manifest_rename", req.From, nil, true, req.SessionID)
}

func handleDirCreate(s *serverState, tenant *tenantState, ident Identity, w *frameWriter, frame dataplane.Frame) {
	req, ok := decodeReq[dataplane.DirCreateRequest](w, frame, "dir_create")
	if !ok {
		return
	}
	if !s.policy.Permits(policyPath(req.Path)) {
		s.recordDataAudit(ident, "dir_create", req.Path, nil, false, req.SessionID)
		writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEACCES("path denied by policy"))
		return
	}
	if !s.checkAgentPath(ident, w, frame, req.Path) {
		return
	}
	if err := tenant.manifests.DirCreate(req.Path, req.Mode); err != nil {
		writeFrameError(w, frame.Op, frame.RID, manifestErrToWire(err))
		return
	}
	sendResp(w, frame, dataplane.DirCreateResponse{})
	s.recordDataAudit(ident, "dir_create", req.Path, nil, true, req.SessionID)
}

func handleDirRemove(s *serverState, tenant *tenantState, ident Identity, w *frameWriter, frame dataplane.Frame) {
	req, ok := decodeReq[dataplane.DirRemoveRequest](w, frame, "dir_remove")
	if !ok {
		return
	}
	if !s.policy.Permits(policyPath(req.Path)) {
		s.recordDataAudit(ident, "dir_remove", req.Path, nil, false, req.SessionID)
		writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEACCES("path denied by policy"))
		return
	}
	if !s.checkAgentPath(ident, w, frame, req.Path) {
		return
	}
	if err := tenant.manifests.DirRemove(req.Path); err != nil {
		writeFrameError(w, frame.Op, frame.RID, manifestErrToWire(err))
		return
	}
	sendResp(w, frame, dataplane.DirRemoveResponse{})
	s.recordDataAudit(ident, "dir_remove", req.Path, nil, true, req.SessionID)
}

// handleSetattr changes a path's metadata: permission bits (chmod), ownership
// (chown via UID/GID), and access time (utimensat via Atime). Works for files,
// directories, and symlinks; the chmod on a file path is journaled +
// lease-fenced (it's a manifest version bump), while dir/symlink mode and all
// owner/atime updates are metadata-only writes in place. Owner/atime carry no
// permission enforcement (single-identity agent disk) — store-and-readback.
func handleSetattr(s *serverState, tenant *tenantState, ident Identity, w *frameWriter, frame dataplane.Frame) {
	req, ok := decodeReq[dataplane.SetattrRequest](w, frame, "setattr")
	if !ok {
		return
	}
	if !s.policy.Permits(policyPath(req.Path)) {
		s.recordDataAudit(ident, "setattr", req.Path, nil, false, req.SessionID)
		writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEACCES("path denied by policy"))
		return
	}
	if !s.checkAgentPath(ident, w, frame, req.Path) {
		return
	}
	sessionID := derefSession(req.SessionID)
	allocationID := derefSession(req.AllocationID)
	activeLeaseHex, ok := s.checkSessionFence(tenant, w, frame, sessionID, allocationID)
	if !ok {
		return
	}
	if err := tenant.manifests.SetMode(req.Path, req.Mode, sessionID, allocationID, ident.AgentID, activeLeaseHex); err != nil {
		writeFrameError(w, frame.Op, frame.RID, manifestErrToWire(err))
		return
	}
	// chown: only when uid and/or gid were provided. For the field left unset we
	// preserve the stored value by reading it back via the same stat fan-out
	// (manifest → symlink → dir).
	if req.UID != nil || req.GID != nil {
		curUID, curGID, oErr := statOwner(tenant, req.Path)
		if oErr != nil {
			writeFrameError(w, frame.Op, frame.RID, manifestErrToWire(oErr))
			return
		}
		newUID, newGID := curUID, curGID
		if req.UID != nil {
			newUID = *req.UID
		}
		if req.GID != nil {
			newGID = *req.GID
		}
		if err := tenant.manifests.SetOwner(req.Path, newUID, newGID); err != nil {
			writeFrameError(w, frame.Op, frame.RID, manifestErrToWire(err))
			return
		}
	}
	// utimensat (atime only — mtime rides the manifest write path).
	if req.Atime != nil {
		if err := tenant.manifests.SetAtime(req.Path, *req.Atime); err != nil {
			writeFrameError(w, frame.Op, frame.RID, manifestErrToWire(err))
			return
		}
	}
	sendResp(w, frame, dataplane.SetattrResponse{})
	s.recordDataAudit(ident, "setattr", req.Path, nil, true, req.SessionID)
}

// statOwner returns the stored uid/gid for a path using the same source-of-
// truth fan-out as handleStat: manifest (file) → symlinks (symlink) →
// dir_entries (directory). Used by handleSetattr to preserve the field a
// partial chown leaves unset. Returns 0/0 for an unknown path (the SetOwner
// call that follows will surface ENOENT).
func statOwner(tenant *tenantState, p string) (uint32, uint32, error) {
	mf, err := tenant.manifests.Get(p)
	if err == nil {
		return mf.Uid, mf.Gid, nil
	}
	if !errors.Is(err, ErrManifestNotFound) {
		return 0, 0, err
	}
	if _, _, uid, gid, _, isSym, sErr := tenant.manifests.SymlinkInfo(p); sErr != nil {
		return 0, 0, sErr
	} else if isSym {
		return uid, gid, nil
	}
	if _, _, uid, gid, _, _, isSpecial, snErr := tenant.manifests.SpecialNodeInfo(p); snErr != nil {
		return 0, 0, snErr
	} else if isSpecial {
		return uid, gid, nil
	}
	_, uid, gid, _, _, dErr := tenant.manifests.DirInfo(p)
	if dErr != nil {
		return 0, 0, dErr
	}
	return uid, gid, nil
}

// handleSymlink creates a symbolic link at req.Path pointing at req.Target.
func handleSymlink(s *serverState, tenant *tenantState, ident Identity, w *frameWriter, frame dataplane.Frame) {
	req, ok := decodeReq[dataplane.SymlinkRequest](w, frame, "symlink")
	if !ok {
		return
	}
	if !s.policy.Permits(policyPath(req.Path)) {
		s.recordDataAudit(ident, "symlink", req.Path, nil, false, req.SessionID)
		writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEACCES("path denied by policy"))
		return
	}
	if !s.checkAgentPath(ident, w, frame, req.Path) {
		return
	}
	if err := tenant.manifests.Symlink(req.Path, req.Target, req.Mode); err != nil {
		writeFrameError(w, frame.Op, frame.RID, manifestErrToWire(err))
		return
	}
	sendResp(w, frame, dataplane.SymlinkResponse{})
	s.recordDataAudit(ident, "symlink", req.Path, nil, true, req.SessionID)
}

// handleMknod creates a POSIX special node (FIFO, socket, block/char device)
// at req.Path. Mirrors handleSymlink with the session-fence check applied.
func handleMknod(s *serverState, tenant *tenantState, ident Identity, w *frameWriter, frame dataplane.Frame) {
	req, ok := decodeReq[dataplane.MknodRequest](w, frame, "mknod")
	if !ok {
		return
	}
	if !s.policy.Permits(policyPath(req.Path)) {
		s.recordDataAudit(ident, "mknod", req.Path, nil, false, req.SessionID)
		writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEACCES("path denied by policy"))
		return
	}
	if !s.checkAgentPath(ident, w, frame, req.Path) {
		return
	}
	sessionID := derefSession(req.SessionID)
	allocationID := derefSession(req.AllocationID)
	if _, ok := s.checkSessionFence(tenant, w, frame, sessionID, allocationID); !ok {
		return
	}
	if err := tenant.manifests.Mknod(req.Path, req.Mode, req.Rdev); err != nil {
		writeFrameError(w, frame.Op, frame.RID, manifestErrToWire(err))
		return
	}
	sendResp(w, frame, dataplane.MknodResponse{})
	s.recordDataAudit(ident, "mknod", req.Path, nil, true, req.SessionID)
}

// handleReadlink returns a symlink's target.
func handleReadlink(s *serverState, tenant *tenantState, ident Identity, w *frameWriter, frame dataplane.Frame) {
	req, ok := decodeReq[dataplane.ReadlinkRequest](w, frame, "readlink")
	if !ok {
		return
	}
	if !s.policy.Permits(policyPath(req.Path)) {
		s.recordDataAudit(ident, "readlink", req.Path, nil, false, nil)
		writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEACCES("path denied by policy"))
		return
	}
	if !s.checkAgentPath(ident, w, frame, req.Path) {
		return
	}
	target, err := tenant.manifests.Readlink(req.Path)
	if err != nil {
		writeFrameError(w, frame.Op, frame.RID, manifestErrToWire(err))
		return
	}
	sendResp(w, frame, dataplane.ReadlinkResponse{Target: target})
	s.recordDataAudit(ident, "readlink", req.Path, nil, true, nil)
}

func handleChunkGet(s *serverState, tenant *tenantState, ident Identity, w *frameWriter, frame dataplane.Frame) {
	req, ok := decodeReq[dataplane.ChunkGetRequest](w, frame, "chunk_get")
	if !ok {
		return
	}
	if len(req.Hash) != HashLen {
		writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEINVAL("hash must be 32 bytes"))
		return
	}
	bytes, err := tenant.chunks.Get(req.Hash)
	if err != nil {
		if os.IsNotExist(err) {
			writeFrameError(w, frame.Op, frame.RID, dataplane.ErrENOENT("chunk not found"))
			return
		}
		writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEIO(err.Error()))
		return
	}
	sendResp(w, frame, dataplane.ChunkGetResponse{Bytes: bytes})
	size := uint64(len(bytes))
	s.metrics.observeOp("chunk_get", "out", size)
	s.metrics.chunkState("fetched")
	s.recordChunkAudit(ident, "chunk_get", req.Hash, size, true, nil)
}

func handleChunkHas(s *serverState, tenant *tenantState, ident Identity, w *frameWriter, frame dataplane.Frame) {
	req, ok := decodeReq[dataplane.ChunkHasRequest](w, frame, "chunk_has")
	if !ok {
		return
	}
	if len(req.Hashes)%HashLen != 0 {
		writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEINVAL("hashes buffer must be a multiple of 32"))
		return
	}
	n := len(req.Hashes) / HashLen
	hashes := make([][]byte, n)
	for i := 0; i < n; i++ {
		hashes[i] = req.Hashes[i*HashLen : (i+1)*HashLen]
	}
	present, err := tenant.chunks.HasMany(hashes)
	if err != nil {
		writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEIO(err.Error()))
		return
	}
	bitmap := make([]byte, (n+7)/8)
	for i, p := range present {
		if p {
			bitmap[i/8] |= 1 << (i % 8)
		}
	}
	sendResp(w, frame, dataplane.ChunkHasResponse{Present: bitmap})
	s.metrics.observeOp("chunk_has", "out", uint64(len(bitmap)))
	s.recordChunkHasAudit(ident, uint64(n), true)
}

func handleChunkPut(s *serverState, tenant *tenantState, ident Identity, w *frameWriter, frame dataplane.Frame) {
	req, ok := decodeReq[dataplane.ChunkPutRequest](w, frame, "chunk_put")
	if !ok {
		return
	}
	if len(req.Bytes) > maxChunkBytes {
		writeFrameError(w, frame.Op, frame.RID,
			dataplane.ErrEINVAL("chunk exceeds maximum size"))
		return
	}
	stored, err := tenant.chunks.Put(req.Hash, req.Bytes)
	if err != nil {
		writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEINVAL(err.Error()))
		return
	}
	sendResp(w, frame, dataplane.ChunkPutResponse{Stored: stored})
	size := uint64(len(req.Bytes))
	s.metrics.observeOp("chunk_put", "in", size)
	if stored {
		s.metrics.chunkState("cached")
	} else {
		s.metrics.chunkState("deduped")
	}
	s.recordChunkAudit(ident, "chunk_put", req.Hash, size, true, req.SessionID)
}

// handleJournalQuery returns journal rows filtered by allocation_id, with
// cursor-based pagination. Tenants are isolated by mTLS — the per-tenant DB
// is already scoped, so no additional ownership check is required when
// querying by allocation_id (all rows in the DB belong to this tenant).
// When AllocationID is empty the caller signals a merged-feed request across
// all of the tenant's allocations; userAllocations is populated from the
// data plane's own journal rows (the distinct set of allocation_ids in the DB).
func handleJournalQuery(s *serverState, tenant *tenantState, ident Identity, w *frameWriter, frame dataplane.Frame) {
	req, ok := decodeReq[dataplane.JournalQueryRequest](w, frame, "journal_query")
	if !ok {
		return
	}

	// Resolve the set of allocation ids to query. When the request specifies
	// one, use it directly. When it does not, enumerate the distinct allocation
	// ids present in the tenant's journal (the tenant DB is already isolated by
	// mTLS, so this is safe without a separate ownership check).
	var userAllocations []string
	if req.AllocationID == "" {
		var err error
		userAllocations, err = tenant.journal.ListAllocations()
		if err != nil {
			writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEIO(err.Error()))
			return
		}
	}

	rows, nextCursor, err := tenant.journal.Query(req.AllocationID, req.Limit, req.Cursor, userAllocations)
	if err != nil {
		s.recordDataAudit(ident, "journal_query", "", nil, false, nil)
		writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEIO(err.Error()))
		return
	}

	entries := make([]dataplane.JournalEntry, 0, len(rows))
	for _, row := range rows {
		entries = append(entries, dataplane.JournalEntry{
			SessionID:     row.SessionID,
			AllocationID:  row.AllocationID,
			Seq:           row.Seq,
			TsUnixMs:      row.TsUnixMs,
			Path:          row.Path,
			Op:            row.Op,
			AgentID:       row.AgentID,
			BeforeVersion: row.BeforeVersion,
			AfterVersion:  row.AfterVersion,
			RenameFrom:    row.RenameFrom,
			SizeBefore:    row.SizeBefore,
			SizeAfter:     row.SizeAfter,
		})
	}
	sendResp(w, frame, dataplane.JournalQueryResponse{
		Entries:    entries,
		NextCursor: nextCursor,
	})
	s.recordDataAudit(ident, "journal_query", "", nil, true, nil)
}

// handleJournalRevertPath replays the most recent journal row for each
// requested path in reverse, restoring before-state under CAS. Conflicts
// (concurrent_writer, no_journal_row) are returned inline in the response
// rather than as ESTALE errors, so the caller can handle partial success.
// No session lifecycle is touched — implicit sessions live with the lease.
func handleJournalRevertPath(s *serverState, tenant *tenantState, ident Identity, w *frameWriter, frame dataplane.Frame) {
	req, ok := decodeReq[dataplane.JournalRevertPathRequest](w, frame, "journal_revert_path")
	if !ok {
		return
	}
	if req.AllocationID == "" {
		writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEINVAL("journal_revert_path requires allocation_id"))
		return
	}
	if len(req.Paths) == 0 {
		writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEINVAL("journal_revert_path requires at least one path"))
		return
	}
	// RevertPaths writes inverse manifests at every caller-supplied path, so an
	// agent-scoped cert must own each one. (This handler has no policy.Permits
	// gate today; the agent moat is enforced here directly.)
	for _, rp := range req.Paths {
		if !s.checkAgentPath(ident, w, frame, rp) {
			return
		}
	}

	// Attribute the inverse write to the allocation's currently-active mount
	// lease so the revert journals as "mount:<active_lease_hex>", indistinguishable
	// shape-wise from any other write on this allocation. The dataplane wire
	// has no per-row seq, so pass nil for expectedSeqs (no seq-pin check).
	revertSessionID := s.writerSessionForRevert(req.AllocationID)

	reverted, conflicts, err := tenant.journal.RevertPaths(
		req.AllocationID, req.Paths, nil, nil, tenant.manifests,
		revertSessionID, ident.AgentID, req.Force,
	)
	if err != nil {
		s.recordDataAudit(ident, "journal_revert_path", "", nil, false, nil)
		writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEIO(err.Error()))
		return
	}

	// Convert local conflict struct → wire struct.
	wireConflicts := make([]dataplane.RevertConflict, len(conflicts))
	for i, c := range conflicts {
		wireConflicts[i] = dataplane.RevertConflict{Path: c.Path, Reason: c.Reason}
	}

	sendResp(w, frame, dataplane.JournalRevertPathResponse{
		RevertedPaths: reverted,
		Conflicts:     wireConflicts,
	})
	s.recordDataAudit(ident, "journal_revert_path", "", nil, true, nil)
}

func toWireChunks(in []ChunkRef) []dataplane.ChunkRef {
	out := make([]dataplane.ChunkRef, len(in))
	if len(in) == 0 {
		return out
	}
	// One backing array for every Hash slice — N chunks would otherwise
	// allocate N×HashLen separate slices on the manifest_get hot path.
	buf := make([]byte, len(in)*HashLen)
	for i, c := range in {
		off := i * HashLen
		copy(buf[off:off+HashLen], c.Hash[:])
		out[i] = dataplane.ChunkRef{
			Hash:   buf[off : off+HashLen : off+HashLen],
			Offset: c.Offset,
			Len:    c.Len,
		}
	}
	return out
}

func fromWireChunks(in []dataplane.ChunkRef) []ChunkRef {
	out := make([]ChunkRef, len(in))
	for i, c := range in {
		var h [HashLen]byte
		if len(c.Hash) == HashLen {
			copy(h[:], c.Hash)
		}
		out[i] = ChunkRef{Hash: h, Offset: c.Offset, Len: c.Len}
	}
	return out
}

func writeFrameList(w *frameWriter, rid uint64, entries []dataplane.EntryWire) {
	payload, err := msgpack.Marshal(dataplane.ListResponse{Entries: entries})
	if err != nil {
		writeFrameError(w, dataplane.OpList, rid, dataplane.ErrEIO(err.Error()))
		return
	}
	w.send(dataplane.Frame{Op: dataplane.OpList, Flags: dataplane.FlagResponse, RID: rid, Payload: payload})
}

// buildCasConflictHint constructs the recovery hint attached to ESTALE
// responses (issues #103 + #100). Pulls the server's current version from
// `*VersionConflictError` when available so the client can skip a
// `manifest_get` round-trip on retry. `lastWriter`, when non-nil, names the
// agent + session that landed the conflicting prior version (issue #100);
// pass nil when no journal-tracked writer exists for the path (e.g., the
// conflict was caused by the migrate-to-chunks tool).
func buildCasConflictHint(yourVersion uint64, err error, lastWriter *LastWriterRow) *dataplane.RecoveryHint {
	hint := &dataplane.RecoveryHint{
		Kind:        dataplane.RecoveryKindCasConflict,
		YourVersion: &yourVersion,
	}
	var conflict *VersionConflictError
	if errors.As(err, &conflict) {
		curr := conflict.Existing
		hint.CurrentVersion = &curr
		hint.SuggestedAction = fmt.Sprintf(
			"file changed since you read it; re-read manifest at version %d, re-apply your edit, re-put with expected=%d",
			curr, curr,
		)
	} else {
		hint.SuggestedAction = "file changed since you read it; re-read manifest then retry"
	}
	if lastWriter != nil {
		lw := &dataplane.LastWriter{AtUnixMs: lastWriter.AtUnixMs}
		if lastWriter.AgentID != "" {
			id := lastWriter.AgentID
			lw.AgentID = &id
		}
		if lastWriter.SessionID != "" {
			sid := lastWriter.SessionID
			lw.SessionID = &sid
		}
		hint.LastWriter = lw
	}
	return hint
}

func writeFrameError(w *frameWriter, op dataplane.Op, rid uint64, err dataplane.ErrorPayload) {
	payload, marshalErr := msgpack.Marshal(err)
	if marshalErr != nil {
		// Fallback: empty payload still flags an error so clients return a
		// generic EIO instead of hanging.
		payload = nil
	}
	w.send(dataplane.Frame{
		Op:      op,
		Flags:   dataplane.FlagResponse | dataplane.FlagError,
		RID:     rid,
		Payload: payload,
	})
}

// derefSession unwraps the optional msgpack session_id field into a plain
// string for ManifestStore — empty string means "no session, do not journal".
func derefSession(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// checkAgentPath enforces the per-agent path moat (Phase 3 of the
// agent-storage bridge, docs/design/agent-storage-bridge.md).
//
// When a connection's client cert carries a `spiffe://<td>/agent/<id>` SAN
// (ident.ScopedAgentID != ""), that connection may operate ONLY on paths
// under `/agents/<ScopedAgentID>`. A cert with no agent SAN
// (ScopedAgentID == "") is tenant-scoped and keeps the historical
// tenant-wide access — this is the backward-compatible bypass.
//
// Path-traversal safety. The handlers and the ManifestStore operate on the
// RAW req.Path: policyPath() only strips the leading "/<mount>/" prefix, it
// does NOT path.Clean the value, and tenant.manifests.Get/Put/Rename/... are
// handed req.Path verbatim. So a prefix check performed on a *cleaned* path
// could authorize one subtree while storage touches another (e.g. the raw
// "/agents/A/../B/x" cleans to "/agents/B/x"). To make the authorized path
// and the stored path provably identical, we DENY any non-canonical path for
// an agent-scoped cert: we require that path.Clean("/"+p) equals the raw
// leading-slash form of p. That rejects "..", "." segments, "//", and
// trailing-slash variants before they can diverge. Only after the path is
// proven canonical do we apply the subtree prefix check. When in doubt we
// deny.
//
// Returns true to continue, or false after writing an EACCES frame and
// recording the authz-denial audit row + metric; callers must stop.
func (s *serverState) checkAgentPath(ident Identity, w *frameWriter, frame dataplane.Frame, p string) bool {
	if ident.ScopedAgentID == "" {
		// Tenant-scoped cert: no per-agent moat (backward compatible).
		return true
	}

	// Canonical leading-slash form storage will actually use.
	raw := p
	if raw == "" || raw[0] != '/' {
		raw = "/" + raw
	}
	cp := path.Clean("/" + p)
	if cp != raw {
		// Non-canonical path (.., ., //, trailing slash): reject so the
		// authorized path can never diverge from the stored path.
		s.denyAgentPath(ident, w, frame, p)
		return false
	}

	// An agent's disk is a single top-level dir named by its id (`/<agent_id>`),
	// so the mounter can create its own root on mount (parent = tenant root) —
	// there is no un-creatable intermediate like `/agents`.
	subtree := "/" + ident.ScopedAgentID
	if cp == subtree || strings.HasPrefix(cp, subtree+"/") {
		return true
	}
	s.denyAgentPath(ident, w, frame, p)
	return false
}

// denyAgentPath records the per-agent authz failure (audit row + metric) and
// writes the EACCES error frame. Mirrors how handlers audit a policy denial
// and how checkSessionFence bumps a metric on a forgery rejection.
//
// The op label is derived from frame.Op.String() (lowercased to match the
// codebase's audit/metric label convention) rather than opLabel(): opLabel
// reads the package-level OpTable, and routing this denial through it would
// create an OpTable initialization cycle (OpTable → handlers → checkAgentPath
// → denyAgentPath → opLabel → OpTable).
func (s *serverState) denyAgentPath(ident Identity, w *frameWriter, frame dataplane.Frame, p string) {
	op := strings.ToLower(frame.Op.String())
	s.metrics.agentPathDeniedInc(op)
	s.recordDataAudit(ident, op, p, nil, false, nil)
	writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEACCES("path outside agent subtree"))
}

// checkSessionFence enforces two layers of mount-session authentication:
//
//  1. The session_id hex must decode to a lease currently held in the
//     tenant's lease store (no forgery — Phase 1.5, spec
//     an internal design spec).
//  2. The hex must not be fenced for the allocation, and must match any hex
//     already active for it (Take-over / Revoke — issue #175).
//
// For unsessioned writes (empty sessionID) it is a no-op, returning
// ("", true). On any failure it writes an EACCES frame and returns
// ("", false); callers must stop processing the request.
func (s *serverState) checkSessionFence(tenant *tenantState, w *frameWriter, frame dataplane.Frame, sessionID, allocationID string) (string, bool) {
	if sessionID == "" {
		return "", true
	}
	if !strings.HasPrefix(sessionID, sessionMountPrefix) || len(sessionID) <= len(sessionMountPrefix) {
		s.metrics.sessionForgery("bad_format")
		writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEACCES("invalid session_id: expected mount:<hex>"))
		return "", false
	}
	leaseHex := sessionID[len(sessionMountPrefix):]
	leaseID, err := decodeLeaseHex(leaseHex)
	if err != nil {
		s.metrics.sessionForgery("bad_hex")
		writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEACCES("invalid session_id hex: "+err.Error()))
		return "", false
	}
	if !tenant.leases.HeldByConn(leaseID, w.connID) {
		s.metrics.sessionForgery("unknown_or_wrong_conn")
		writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEACCES("session_id does not match a granted lease on this connection"))
		return "", false
	}
	if !s.mountLeases.Install(allocationID, leaseHex) {
		s.metrics.sessionForgery("fenced")
		writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEACCES("session fenced; mount has been revoked or taken over"))
		return "", false
	}
	return leaseHex, true
}

// decodeLeaseHex parses the 32-char lowercase-hex tail of a mount session_id
// back into the 16-byte lease id. Zero-allocation: writes directly into the
// returned array via hex.Decode.
func decodeLeaseHex(s string) ([16]byte, error) {
	var id [16]byte
	if len(s) != 32 {
		return id, fmt.Errorf("expected 32 hex chars, got %d", len(s))
	}
	if _, err := hex.Decode(id[:], []byte(s)); err != nil {
		return id, err
	}
	return id, nil
}

// recordDataAudit logs a request that came in over the binary plane. Mirrors
// recordAudit but doesn't take an *http.Request — identity and metadata are
// passed explicitly.
// sessionID is non-nil for writes performed inside a `orlop session begin`
// window; nil for reads and unsessioned writes.
func (s *serverState) recordDataAudit(ident Identity, event, path string, size *uint64, allowed bool, sessionID *string) {
	rec := AuditRecord{
		Event:       event,
		Path:        path,
		Size:        size,
		AgentID:     ident.AgentID,
		TenantID:    ident.TenantID,
		CertSerial:  ident.CertSerial,
		CertSubject: ident.CertSubject,
		UID:         uintPtr(s.uid),
		GID:         uintPtr(s.gid),
		SessionID:   sessionID,
		Command:     "orlop-server",
		Allowed:     allowed,
	}
	s.audit.Record(rec)
}

// recordManifestAudit emits a manifest_get / manifest_put event with the
// canonical {path, size, version, allowed} shape from issue #82.
// version == 0 is treated as "unknown" and omitted. sessionID is non-nil
// for writes performed inside a `orlop session begin` window.
func (s *serverState) recordManifestAudit(ident Identity, event, path string, size, version uint64, allowed bool, sessionID *string) {
	rec := AuditRecord{
		Event:       event,
		Path:        path,
		AgentID:     ident.AgentID,
		TenantID:    ident.TenantID,
		CertSerial:  ident.CertSerial,
		CertSubject: ident.CertSubject,
		UID:         uintPtr(s.uid),
		GID:         uintPtr(s.gid),
		SessionID:   sessionID,
		Command:     "orlop-server",
		Allowed:     allowed,
	}
	if size > 0 {
		rec.Size = &size
	}
	if version > 0 {
		v := version
		rec.Version = &v
	}
	s.audit.Record(rec)
}

// recordChunkAudit emits chunk_get / chunk_put events keyed by the chunk
// hash (hex). The path field is left blank — chunk events are content-
// addressed, not path-addressed. sessionID is non-nil for chunk_put
// inside a session window; nil for chunk_get and unsessioned writes.
func (s *serverState) recordChunkAudit(ident Identity, event string, hash []byte, size uint64, allowed bool, sessionID *string) {
	rec := AuditRecord{
		Event:       event,
		AgentID:     ident.AgentID,
		TenantID:    ident.TenantID,
		CertSerial:  ident.CertSerial,
		CertSubject: ident.CertSubject,
		UID:         uintPtr(s.uid),
		GID:         uintPtr(s.gid),
		SessionID:   sessionID,
		Command:     "orlop-server",
		Allowed:     allowed,
		Hash:        hex.EncodeToString(hash),
		Size:        &size,
	}
	s.audit.Record(rec)
}

// recordChunkHasAudit emits a chunk_has event covering an N-hash batch.
// Per-hash audit is intentionally skipped — chunk_has is a presence probe
// fired on every write and produces too much log volume to be useful at
// per-chunk granularity.
func (s *serverState) recordChunkHasAudit(ident Identity, count uint64, allowed bool) {
	rec := AuditRecord{
		Event:       "chunk_has",
		AgentID:     ident.AgentID,
		TenantID:    ident.TenantID,
		CertSerial:  ident.CertSerial,
		CertSubject: ident.CertSubject,
		UID:         uintPtr(s.uid),
		GID:         uintPtr(s.gid),
		Command:     "orlop-server",
		Allowed:     allowed,
		Count:       &count,
	}
	s.audit.Record(rec)
}

// frameWriter serialises outbound frames on a single goroutine so multiple
// request workers can call send() concurrently without tearing the wire.
//
// connID identifies the data-plane connection this writer is bound to. It is
// zero until the read loop populates it (after connRegistry.Register) and is
// read by checkSessionFence to enforce the "session_id must match a lease
// granted on this connection" rule (Phase 1.5).
type frameWriter struct {
	ch     chan dataplane.Frame
	done   chan struct{}
	connID uint64
}

func newFrameWriter(w io.Writer) *frameWriter {
	fw := &frameWriter{
		ch:   make(chan dataplane.Frame, 256),
		done: make(chan struct{}),
	}
	go func() {
		defer close(fw.done)
		for f := range fw.ch {
			if err := dataplane.WriteFrame(w, f); err != nil {
				return
			}
		}
	}()
	return fw
}

func (fw *frameWriter) send(f dataplane.Frame) {
	defer func() {
		// Recover from sending on closed channel — happens during clean
		// shutdown; we just drop the frame.
		_ = recover()
	}()
	fw.ch <- f
}

func (fw *frameWriter) close() {
	close(fw.ch)
	<-fw.done
}
