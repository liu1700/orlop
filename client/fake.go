package client

import (
	"context"
	"fmt"
	"sync"
)

// Fake is an in-memory Client for tests and local development. It models the
// entity = agent (1:1) contract: one unique disk per agent with a stable handle
// and a deterministic mount path.
type Fake struct {
	mu      sync.Mutex
	disks   map[string]Disk
	usage   map[string]int64 // ownerID -> aggregate used_bytes
	budgets map[string]int64 // ownerID -> account disk budget
}

var _ Client = (*Fake)(nil)

// NewFake returns an empty in-memory client.
func NewFake() *Fake {
	return &Fake{disks: make(map[string]Disk), usage: make(map[string]int64), budgets: make(map[string]int64)}
}

// AllocateDisk implements Client.
func (f *Fake) AllocateDisk(_ context.Context, agentID, _ string, grantBytes int64) (Disk, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if d, ok := f.disks[agentID]; ok {
		return d, nil // idempotent: same unique disk
	}
	d := Disk{
		AgentID:     agentID,
		Handle:      EntityType + ":" + agentID,
		VirtualPath: MountPath(agentID),
		QuotaBytes:  grantBytes,
	}
	f.disks[agentID] = d
	return d, nil
}

// SetDiskQuota implements Client.
func (f *Fake) SetDiskQuota(_ context.Context, agentID string, grantBytes int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.disks[agentID]
	if !ok {
		return fmt.Errorf("orlop: no disk for agent %q", agentID)
	}
	d.QuotaBytes = grantBytes
	f.disks[agentID] = d
	return nil
}

// SetAccountBudget implements Client. Tests can read it back via AccountBudget.
func (f *Fake) SetAccountBudget(_ context.Context, ownerID string, diskBytes int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.budgets[ownerID] = diskBytes
	return nil
}

// AccountBudget returns the budget recorded for ownerID (0 if none). Test helper.
func (f *Fake) AccountBudget(ownerID string) int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.budgets[ownerID]
}

// RevokeDisk implements Client. Idempotent: revoking an unknown agent is a no-op.
func (f *Fake) RevokeDisk(_ context.Context, agentID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.disks, agentID)
	return nil
}

// ReassignDisk implements Client. The fake keys disks by agent id, so re-homing
// is a no-op that keeps the disk: it models "data stays, only the owner changes".
func (f *Fake) ReassignDisk(_ context.Context, _, _ string) error {
	return nil
}

// ResolveDisk implements Client.
func (f *Fake) ResolveDisk(_ context.Context, agentID string) (Disk, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.disks[agentID]
	if !ok {
		return Disk{}, fmt.Errorf("orlop: no disk for agent %q", agentID)
	}
	return d, nil
}

// MintEnrollToken implements Client. Returns a deterministic stub token so that
// launcher/lifecycle tests can assert the per-agent token was threaded through
// without a live control plane.
func (f *Fake) MintEnrollToken(_ context.Context, agentID string) (string, error) {
	return "enrolltok-" + agentID, nil
}

// SetUserDiskUsage seeds an owner's aggregate disk usage for usage tests.
func (f *Fake) SetUserDiskUsage(ownerID string, bytes int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.usage[ownerID] = bytes
}

// UserDiskUsage implements Client. Returns the owner's seeded usage (0 when
// unset, modelling an owner that has never been placed on a server).
func (f *Fake) UserDiskUsage(_ context.Context, ownerID string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.usage[ownerID], nil
}
