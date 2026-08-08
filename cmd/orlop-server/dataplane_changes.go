package main

// Dataplane handlers for the metadata change feed (issue #122,
// docs/design-metadata-mirror.md): CHANGES_FETCH pages the coalesced
// final-state feed through a (rev, path) cursor; CHANGES_SUBSCRIBE registers
// the connection for CHANGES_EVENT doorbell pushes. Negotiation is explicit:
// both requests carry sync_protocol and the response echoes it; an old
// server answers these ops with EINVAL (unknown op) and the client runs
// mirror-less.

import (
	"time"

	"github.com/vmihailenco/msgpack/v5"

	"github.com/liu1700/orlop/cmd/orlop-server/dataplane"
)

// changesFetchDefaultLimit / changesFetchMaxLimit clamp CHANGES_FETCH page
// sizes (same shape as the journal query's clamp).
const (
	changesFetchDefaultLimit = 500
	changesFetchMaxLimit     = 1000
)

func handleChangesFetch(s *serverState, tenant *tenantState, ident Identity, w *frameWriter, frame dataplane.Frame) {
	req, ok := decodeReq[dataplane.ChangesFetchRequest](w, frame, "changes_fetch")
	if !ok {
		return
	}
	if req.SyncProtocol != dataplane.SyncProtocolV1 {
		writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEINVAL("unsupported sync_protocol"))
		return
	}
	// The feed is confined to the caller's subtree by construction: the
	// subtree comes from the verified cert (identifyV2Peer rejects certs
	// without an agent scope), never from the request, so there is no
	// client-supplied path to authorize. Per-entry policy runs below.
	subtree := ""
	if ident.ScopedAgentID != "" {
		subtree = "/" + ident.ScopedAgentID
	}

	// Read the counter BEFORE the query: the query then reflects at least
	// everything up to lastRev, which is what lets a not-full page advance
	// the cursor to lastRev safely.
	lastRev, prunedBefore, err := changeFeedState(tenant.db.DB())
	if err != nil {
		writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEIO(err.Error()))
		return
	}
	if req.CursorRev > 0 && req.CursorRev < prunedBefore {
		// The cursor predates pruned tombstones: deletions may be missing
		// from the feed, so the client must discard its mirror and restart
		// from (0, ""). A fresh (0, "") cursor is exempt — an empty mirror
		// has nothing stale for a missed tombstone to invalidate.
		sendResp(w, frame, dataplane.ChangesFetchResponse{
			SyncProtocol:   dataplane.SyncProtocolV1,
			NextRev:        req.CursorRev,
			NextPath:       req.CursorPath,
			CurrentRev:     lastRev,
			ResyncRequired: true,
		})
		s.recordDataAudit(ident, "changes_fetch", subtree, nil, true, nil)
		return
	}

	limit := int(req.Limit)
	if limit <= 0 {
		limit = changesFetchDefaultLimit
	} else if limit > changesFetchMaxLimit {
		limit = changesFetchMaxLimit
	}
	entries, err := queryChanges(tenant.db.DB(), subtree, req.CursorRev, req.CursorPath, limit, req.IncludeChunks)
	if err != nil {
		writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEIO(err.Error()))
		return
	}

	// Per-entry policy filter mirrors handleList: denied paths are silently
	// skipped. The cursor advances over them regardless, so pagination can
	// never stall on a denied entry.
	wire := make([]dataplane.ChangeEntryWire, 0, len(entries))
	for _, e := range entries {
		if !s.policy.Permits(policyPath(e.Path)) {
			continue
		}
		we := dataplane.ChangeEntryWire{
			Path:      e.Path,
			Rev:       e.Rev,
			Kind:      e.Kind,
			Size:      e.Size,
			Mode:      e.Mode,
			Mtime:     e.Mtime,
			Uid:       e.Uid,
			Gid:       e.Gid,
			Atime:     e.Atime,
			InodeID:   e.InodeID,
			Nlink:     e.Nlink,
			Version:   e.Version,
			Target:    e.Target,
			Rdev:      e.Rdev,
			HasChunks: e.HasChunks,
		}
		if e.HasChunks {
			we.Chunks = toWireChunks(e.Chunks)
		}
		wire = append(wire, we)
	}

	resp := dataplane.ChangesFetchResponse{
		SyncProtocol: dataplane.SyncProtocolV1,
		Entries:      wire,
		CurrentRev:   lastRev,
	}
	if len(entries) < limit {
		// Not-full page: the subtree's feed is drained as of query time. Jump
		// the cursor to the counter so the client's applied watermark can
		// reach CurrentRev even though other agents' revisions are invisible
		// to this subtree.
		if n := len(entries); n > 0 && entries[n-1].Rev >= lastRev {
			resp.NextRev, resp.NextPath = entries[n-1].Rev, entries[n-1].Path
			resp.CurrentRev = entries[n-1].Rev
		} else {
			resp.NextRev, resp.NextPath = lastRev, ""
		}
	} else {
		last := entries[len(entries)-1]
		resp.NextRev, resp.NextPath = last.Rev, last.Path
	}
	sendResp(w, frame, resp)
	s.recordDataAudit(ident, "changes_fetch", subtree, nil, true, nil)
}

// handleChangesSubscribe registers the connection for doorbell pushes. Routed
// beside the lease ops (not through OpTable) because the subscription is
// per-connection state keyed by connID.
func handleChangesSubscribe(s *serverState, tenant *tenantState, ident Identity, w *frameWriter, connID uint64, frame dataplane.Frame) {
	defer recoverRequest(s, w, frame)
	started := time.Now()
	defer s.metrics.observeDuration("changes_subscribe", started)

	req, ok := decodeReq[dataplane.ChangesSubscribeRequest](w, frame, "changes_subscribe")
	if !ok {
		return
	}
	if req.SyncProtocol != dataplane.SyncProtocolV1 {
		writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEINVAL("unsupported sync_protocol"))
		return
	}
	sub := tenant.changes.Subscribe(connID)
	if sub == nil {
		writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEIO("change feed unavailable"))
		return
	}
	// Register first, read the counter second: a mutation landing in between
	// rings the new subscription instead of falling into a gap.
	lastRev, _, err := changeFeedState(tenant.db.DB())
	if err != nil {
		tenant.changes.DropConn(connID)
		writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEIO(err.Error()))
		return
	}
	go changesEventPump(w, sub)
	sendResp(w, frame, dataplane.ChangesSubscribeResponse{
		SyncProtocol: dataplane.SyncProtocolV1,
		CurrentRev:   lastRev,
	})
	s.recordDataAudit(ident, "changes_subscribe", "", nil, true, nil)
}

// changesEventPump forwards conflated doorbells to the connection until the
// subscription is dropped (connection teardown, or replacement by a newer
// subscribe on the same connection). Sends ride the connection's frameWriter,
// which tolerates writes racing teardown.
func changesEventPump(w *frameWriter, sub *changeSub) {
	for {
		select {
		case <-sub.done:
			return
		case <-sub.signal:
			payload, err := msgpack.Marshal(dataplane.ChangesEventPush{CurrentRev: sub.rev.Load()})
			if err != nil {
				continue
			}
			// Same push-RID convention as buildRevokeFrame: server-allocated
			// push frames live above 1<<63.
			const pushRIDBase uint64 = 1 << 63
			w.send(dataplane.Frame{
				Op:      dataplane.OpChangesEvent,
				Flags:   0,
				RID:     pushRIDBase | uint64(time.Now().UnixNano()),
				Payload: payload,
			})
		}
	}
}
