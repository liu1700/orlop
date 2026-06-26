package main

import (
	"context"
	"crypto/rand"
	"errors"
	"sync"
	"time"

	"github.com/liu1700/orlop/cmd/orlop-server/dataplane"
	"github.com/vmihailenco/msgpack/v5"
)

// pushFn delivers a server-initiated frame to a specific connection.
// Returns error if the conn has gone away.
type pushFn func(connID uint64, frame dataplane.Frame) error

type leaseConfig struct {
	ttl           time.Duration
	minHold       time.Duration
	revokeTimeout time.Duration
}

type leaseRecord struct {
	id        [16]byte
	path      string
	mode      dataplane.LeaseMode
	holder    string // agentID
	connID    uint64
	grantedAt time.Time
	expiresAt time.Time

	// Set when a revoke has been pushed; the channel is closed by Release.
	revoking chan struct{}
}

type leaseManager struct {
	mu      sync.Mutex
	byPath  map[string]*leaseRecord
	byID    map[[16]byte]*leaseRecord
	byConn  map[uint64]map[[16]byte]struct{}
	cfg     leaseConfig
	push    pushFn
	audit   *AuditLog      // may be nil in tests
	metrics *serverMetrics // may be nil in tests
}

type leaseGrantResult struct {
	LeaseID         []byte
	ExpiresAtUnixMs int64
	Mode            dataplane.LeaseMode
}

type leaseRefreshResult struct {
	ExpiresAtUnixMs int64
}

var (
	errLeaseUnknown = errors.New("lease unknown")
	errLeaseHeld    = errors.New("lease held by another agent")
)

func newLeaseManager(cfg leaseConfig, push pushFn, audit *AuditLog, metrics *serverMetrics) *leaseManager {
	return &leaseManager{
		byPath:  map[string]*leaseRecord{},
		byID:    map[[16]byte]*leaseRecord{},
		byConn:  map[uint64]map[[16]byte]struct{}{},
		cfg:     cfg,
		push:    push,
		audit:   audit,
		metrics: metrics,
	}
}

// YieldFor blocks until either the path is free for requester, the lease's
// holder releases (within revokeTimeout), or the holder is force-evicted.
// Returns nil if requester may proceed (path free or held by requester).
// Returns errLeaseHeld if another holder has the path within min-hold.
// Returns ctx.Err() if the context is cancelled.
//
// reason is the audit-log + revoke-frame label identifying why the holder
// is being asked to yield (e.g. "contention" for Grant, "manifest_put_contention"
// for write-path cross-check).
func (m *leaseManager) YieldFor(ctx context.Context, requester, path, reason string) error {
	for {
		m.mu.Lock()
		existing := m.byPath[path]
		if existing == nil || existing.holder == requester {
			m.mu.Unlock()
			return nil
		}
		if time.Since(existing.grantedAt) < m.cfg.minHold {
			m.mu.Unlock()
			return errLeaseHeld
		}
		if existing.revoking == nil {
			existing.revoking = make(chan struct{})
			revokeFrame := buildRevokeFrame(existing.id, reason)
			holderConn := existing.connID
			done := existing.revoking
			holderRec := existing
			holderMode := existing.mode
			m.mu.Unlock()
			_ = m.push(holderConn, revokeFrame)
			m.recordAudit("lease_revoke", holderRec.holder, holderRec.path, holderRec.id, holderMode, reason)
			select {
			case <-done:
				continue
			case <-time.After(m.cfg.revokeTimeout):
				m.mu.Lock()
				if cur := m.byPath[path]; cur == holderRec {
					m.recordAudit("lease_violation", cur.holder, cur.path, cur.id, cur.mode, "revoke_timeout")
					m.removeLocked(cur)
					if m.metrics != nil {
						m.metrics.leaseReleased(cur.path)
					}
				}
				m.mu.Unlock()
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		} else {
			done := existing.revoking
			m.mu.Unlock()
			select {
			case <-done:
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}

func (m *leaseManager) Grant(ctx context.Context, holder string, connID uint64, path string, mode dataplane.LeaseMode) (*leaseGrantResult, error) {
	for {
		if err := m.YieldFor(ctx, holder, path, "contention"); err != nil {
			return nil, err
		}
		m.mu.Lock()
		if existing := m.byPath[path]; existing != nil {
			if existing.holder == holder && existing.mode == mode {
				// Idempotent; rebind connID + extend expiry.
				if existing.connID != connID {
					if conn := m.byConn[existing.connID]; conn != nil {
						delete(conn, existing.id)
						if len(conn) == 0 {
							delete(m.byConn, existing.connID)
						}
					}
					existing.connID = connID
					if m.byConn[connID] == nil {
						m.byConn[connID] = map[[16]byte]struct{}{}
					}
					m.byConn[connID][existing.id] = struct{}{}
				}
				existing.expiresAt = time.Now().Add(m.cfg.ttl)
				res := &leaseGrantResult{
					LeaseID:         append([]byte(nil), existing.id[:]...),
					ExpiresAtUnixMs: existing.expiresAt.UnixMilli(),
					Mode:            existing.mode,
				}
				m.mu.Unlock()
				return res, nil
			}
			// Different holder snuck in between YieldFor and re-lock; loop.
			m.mu.Unlock()
			continue
		}
		// Free path — install.
		res := m.installLocked(holder, connID, path, mode)
		m.mu.Unlock()
		m.recordAudit("lease_grant", holder, path, idArrayFromBytes(res.LeaseID), mode, "")
		if m.metrics != nil {
			m.metrics.leaseAcquired(path)
		}
		return res, nil
	}
}

func (m *leaseManager) installLocked(holder string, connID uint64, path string, mode dataplane.LeaseMode) *leaseGrantResult {
	rec := &leaseRecord{
		path:      path,
		mode:      mode,
		holder:    holder,
		connID:    connID,
		grantedAt: time.Now(),
		expiresAt: time.Now().Add(m.cfg.ttl),
	}
	_, _ = rand.Read(rec.id[:])
	m.byPath[path] = rec
	m.byID[rec.id] = rec
	if m.byConn[connID] == nil {
		m.byConn[connID] = map[[16]byte]struct{}{}
	}
	m.byConn[connID][rec.id] = struct{}{}
	return &leaseGrantResult{
		LeaseID:         append([]byte(nil), rec.id[:]...),
		ExpiresAtUnixMs: rec.expiresAt.UnixMilli(),
		Mode:            rec.mode,
	}
}

func (m *leaseManager) removeLocked(rec *leaseRecord) {
	delete(m.byID, rec.id)
	if m.byPath[rec.path] == rec {
		delete(m.byPath, rec.path)
	}
	if conn, ok := m.byConn[rec.connID]; ok {
		delete(conn, rec.id)
		if len(conn) == 0 {
			delete(m.byConn, rec.connID)
		}
	}
	if rec.revoking != nil {
		close(rec.revoking)
		rec.revoking = nil
	}
}

func idArrayFromBytes(b []byte) [16]byte {
	var k [16]byte
	copy(k[:], b)
	return k
}

func buildRevokeFrame(id [16]byte, reason string) dataplane.Frame {
	req := dataplane.LeaseRevokeRequest{LeaseID: id[:], Reason: reason}
	payload, _ := msgpack.Marshal(req)
	// PUSH_RID_BASE = 1<<63: server-allocated push frames live above this.
	const pushRIDBase uint64 = 1 << 63
	rid := pushRIDBase | uint64(time.Now().UnixNano())
	return dataplane.Frame{Op: dataplane.OpLeaseRevoke, Flags: 0, RID: rid, Payload: payload}
}

// HeldByConn reports whether the lease with the given id is currently held by
// connID. False if the lease doesn't exist OR it's held by a different
// connection. Used by the mount-session forgery check (checkSessionFence) to
// reject (a) fabricated session_ids and (b) replay of a leaked session_id
// across connections. Spec:
// an internal design spec.
func (m *leaseManager) HeldByConn(id [16]byte, connID uint64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.byID[id]
	return ok && rec.connID == connID
}

func (m *leaseManager) Refresh(leaseID []byte) (*leaseRefreshResult, error) {
	if len(leaseID) != 16 {
		return nil, errLeaseUnknown
	}
	var key [16]byte
	copy(key[:], leaseID)

	m.mu.Lock()
	rec, ok := m.byID[key]
	if !ok {
		m.mu.Unlock()
		return nil, errLeaseUnknown
	}
	rec.expiresAt = time.Now().Add(m.cfg.ttl)
	holder := rec.holder
	path := rec.path
	mode := rec.mode
	id := rec.id
	expiry := rec.expiresAt.UnixMilli()
	m.mu.Unlock()

	m.recordAudit("lease_refresh", holder, path, id, mode, "")
	return &leaseRefreshResult{ExpiresAtUnixMs: expiry}, nil
}

func (m *leaseManager) Release(leaseID []byte) error {
	if len(leaseID) != 16 {
		return errLeaseUnknown
	}
	var key [16]byte
	copy(key[:], leaseID)

	m.mu.Lock()
	rec, ok := m.byID[key]
	if !ok {
		m.mu.Unlock()
		return errLeaseUnknown
	}
	holder := rec.holder
	path := rec.path
	mode := rec.mode
	id := rec.id
	m.removeLocked(rec)
	m.mu.Unlock()

	m.recordAudit("lease_release", holder, path, id, mode, "client")
	if m.metrics != nil {
		m.metrics.leaseReleased(path)
	}
	return nil
}

// SweepExpired removes every lease whose expiresAt has passed `now`. Each
// removal emits a lease_violation event with reason "expired"; the contract
// is that clients refresh before TTL, so an unrefreshed lease is a protocol
// violation by the client.
//
// Leases mid-revoke (revoking != nil) are skipped — the YieldFor revoke flow
// owns their cleanup via revokeTimeout. Returns the number swept.
//
// Without this loop, leases held by a client whose TCP conn lingers (NAT
// silent-drop, half-open, etc.) would never be released, since
// ReleaseAllForConn only fires on socket close.
func (m *leaseManager) SweepExpired(now time.Time) int {
	type swept struct {
		holder string
		path   string
		id     [16]byte
		mode   dataplane.LeaseMode
	}
	var freed []swept

	m.mu.Lock()
	for _, rec := range m.byID {
		if rec.revoking != nil {
			continue
		}
		if rec.expiresAt.After(now) {
			continue
		}
		freed = append(freed, swept{rec.holder, rec.path, rec.id, rec.mode})
		m.removeLocked(rec)
	}
	m.mu.Unlock()

	for _, e := range freed {
		m.recordAudit("lease_violation", e.holder, e.path, e.id, e.mode, "expired")
		if m.metrics != nil {
			m.metrics.leaseReleased(e.path)
		}
	}
	return len(freed)
}

func (m *leaseManager) ReleaseAllForConn(connID uint64) {
	m.mu.Lock()
	ids := m.byConn[connID]

	type pair struct {
		holder string
		path   string
		id     [16]byte
		mode   dataplane.LeaseMode
	}
	var freed []pair
	for id := range ids {
		rec := m.byID[id]
		if rec == nil {
			continue
		}
		// Capture audit fields before removeLocked clears revoking.
		freed = append(freed, pair{rec.holder, rec.path, rec.id, rec.mode})
		m.removeLocked(rec)
	}
	m.mu.Unlock()

	for _, p := range freed {
		m.recordAudit("lease_release", p.holder, p.path, p.id, p.mode, "conn_closed")
		if m.metrics != nil {
			m.metrics.leaseReleased(p.path)
		}
	}
}

func (m *leaseManager) recordAudit(event, holder, path string, id [16]byte, mode dataplane.LeaseMode, reason string) {
	if m.audit == nil {
		return
	}
	m.audit.RecordLease(event, holder, path, id[:], leaseModeString(mode), reason)
}

func leaseModeString(m dataplane.LeaseMode) string {
	switch m {
	case dataplane.LeaseSharedRead:
		return "read"
	case dataplane.LeaseExclusiveWrite:
		return "write"
	default:
		return ""
	}
}
