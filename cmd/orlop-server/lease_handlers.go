package main

import (
	"context"
	"errors"
	"time"

	"github.com/vmihailenco/msgpack/v5"

	"github.com/liu1700/orlop/cmd/orlop-server/dataplane"
)

func handleLeaseRequest(state *serverState, tenant *tenantState, ident Identity, w *frameWriter, connID uint64, frame dataplane.Frame) {
	defer recoverRequest(state, w, frame)
	started := time.Now()
	defer state.metrics.observeDuration(opLabel(frame.Op), started)
	switch frame.Op {
	case dataplane.OpLeaseGrant:
		handleLeaseGrant(state, tenant, ident, w, connID, frame)
	case dataplane.OpLeaseRefresh:
		handleLeaseRefresh(tenant, w, frame)
	case dataplane.OpLeaseRelease:
		handleLeaseRelease(tenant, w, frame)
	}
}

func handleLeaseGrant(state *serverState, tenant *tenantState, ident Identity, w *frameWriter, connID uint64, frame dataplane.Frame) {
	var req dataplane.LeaseGrantRequest
	if err := safeUnmarshal(frame.Payload, &req); err != nil {
		writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEINVAL("malformed lease_grant payload"))
		return
	}
	if req.Mode != dataplane.LeaseExclusiveWrite && req.Mode != dataplane.LeaseSharedRead {
		writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEINVAL("invalid lease mode"))
		return
	}
	if !state.policy.Permits(policyPath(req.Path)) {
		writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEACCES("path denied by policy"))
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), tenant.leases.cfg.revokeTimeout+time.Second)
	defer cancel()
	g, err := tenant.leases.Grant(ctx, ident.AgentID, connID, req.Path, req.Mode)
	if err != nil {
		switch {
		case errors.Is(err, errLeaseHeld):
			writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEBUSY("lease_held"))
		default:
			writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEIO(err.Error()))
		}
		return
	}
	resp := dataplane.LeaseGrantResponse{
		LeaseID:         g.LeaseID,
		ExpiresAtUnixMs: g.ExpiresAtUnixMs,
		ModeGranted:     g.Mode,
	}
	payload, err := msgpack.Marshal(resp)
	if err != nil {
		writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEIO(err.Error()))
		return
	}
	w.send(dataplane.Frame{Op: frame.Op, Flags: dataplane.FlagResponse, RID: frame.RID, Payload: payload})
}

func handleLeaseRefresh(tenant *tenantState, w *frameWriter, frame dataplane.Frame) {
	var req dataplane.LeaseRefreshRequest
	if err := safeUnmarshal(frame.Payload, &req); err != nil {
		writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEINVAL("malformed lease_refresh payload"))
		return
	}
	r, err := tenant.leases.Refresh(req.LeaseID)
	if err != nil {
		writeFrameError(w, frame.Op, frame.RID, dataplane.ErrLeaseUnknown(err.Error()))
		return
	}
	resp := dataplane.LeaseRefreshResponse{ExpiresAtUnixMs: r.ExpiresAtUnixMs}
	payload, err := msgpack.Marshal(resp)
	if err != nil {
		writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEIO(err.Error()))
		return
	}
	w.send(dataplane.Frame{Op: frame.Op, Flags: dataplane.FlagResponse, RID: frame.RID, Payload: payload})
}

func handleLeaseRelease(tenant *tenantState, w *frameWriter, frame dataplane.Frame) {
	var req dataplane.LeaseReleaseRequest
	if err := safeUnmarshal(frame.Payload, &req); err != nil {
		writeFrameError(w, frame.Op, frame.RID, dataplane.ErrEINVAL("malformed lease_release payload"))
		return
	}
	// Idempotent: missing lease == already released; respond OK.
	_ = tenant.leases.Release(req.LeaseID)
	payload, _ := msgpack.Marshal(dataplane.LeaseReleaseResponse{})
	w.send(dataplane.Frame{Op: frame.Op, Flags: dataplane.FlagResponse, RID: frame.RID, Payload: payload})
}
