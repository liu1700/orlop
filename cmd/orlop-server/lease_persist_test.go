package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/liu1700/orlop/cmd/orlop-server/dataplane"
)

func TestLeasePersistRoundTrip(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "leases.db")

	m1, _ := newTestMgr(t)
	g, _ := m1.Grant(context.Background(), "agentA", 1, "/file", dataplane.LeaseExclusiveWrite)

	if err := m1.Snapshot(dbPath); err != nil {
		t.Fatal(err)
	}

	pusher := &fakePusher{}
	cfg := leaseConfig{ttl: 30 * time.Second, minHold: 100 * time.Millisecond, revokeTimeout: time.Second}
	m2 := newLeaseManager(cfg, pusher.push, nil, nil)
	if err := m2.Restore(dbPath); err != nil {
		t.Fatal(err)
	}

	// agentB on /file should be blocked (lease still alive). Within min-hold of restore.
	_, err := m2.Grant(context.Background(), "agentB", 9, "/file", dataplane.LeaseExclusiveWrite)
	if err == nil {
		t.Fatal("expected lease still held after restore")
	}

	// Same agent + new connID rebinds idempotently; lease_id matches.
	g2, err := m2.Grant(context.Background(), "agentA", 1, "/file", dataplane.LeaseExclusiveWrite)
	if err != nil {
		t.Fatalf("rebind grant failed: %v", err)
	}
	if string(g2.LeaseID) != string(g.LeaseID) {
		t.Fatal("restored lease_id should round-trip")
	}
}

func TestRestoreSkipsExpired(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "leases.db")

	m1, _ := newTestMgr(t)
	g, _ := m1.Grant(context.Background(), "agentA", 1, "/file", dataplane.LeaseExclusiveWrite)
	// Force expire by editing the in-memory record.
	m1.mu.Lock()
	m1.byID[idArrayFromBytes(g.LeaseID)].expiresAt = time.Now().Add(-time.Hour)
	m1.mu.Unlock()

	if err := m1.Snapshot(dbPath); err != nil {
		t.Fatal(err)
	}
	m2 := newLeaseManager(m1.cfg, nil, nil, nil)
	if err := m2.Restore(dbPath); err != nil {
		t.Fatal(err)
	}
	// agentB grants freely.
	if _, err := m2.Grant(context.Background(), "agentB", 9, "/file", dataplane.LeaseExclusiveWrite); err != nil {
		t.Fatalf("expected free path after expiry: %v", err)
	}
}
