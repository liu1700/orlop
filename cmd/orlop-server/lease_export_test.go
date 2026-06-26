package main

import (
	"time"

	"github.com/liu1700/orlop/cmd/orlop-server/dataplane"
)

// installForTest seeds a synthetic lease record with id, owned by holder on
// connID for path. Tests that pre-fabricate a session_id by suffix-byte need
// a paired lease record so the production forgery check accepts the synthetic
// session_id. Production code installs via Grant; this lives in a _test.go
// file so it cannot be linked into the orlop-server binary.
func (m *leaseManager) installForTest(id [16]byte, holder string, connID uint64, path string, mode dataplane.LeaseMode) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec := &leaseRecord{
		id:        id,
		path:      path,
		mode:      mode,
		holder:    holder,
		connID:    connID,
		grantedAt: time.Now(),
		expiresAt: time.Now().Add(m.cfg.ttl),
	}
	m.byPath[path] = rec
	m.byID[id] = rec
	if m.byConn[connID] == nil {
		m.byConn[connID] = map[[16]byte]struct{}{}
	}
	m.byConn[connID][id] = struct{}{}
}
