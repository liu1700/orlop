// Package client is a small, dependency-free Go SDK for the orlop control plane
// (orlop-control).
//
// It allocates and manages each agent's unique, auto-expanding POSIX disk over
// the control-plane REST API, and mints the short-lived, agent-scoped enroll
// token an agent trades at /agent/enroll for its per-agent mTLS certificate.
// The data plane itself (the actual mount) is performed by the `orlop` binary;
// this SDK only speaks the control-plane API and imports only the standard
// library.
//
// The service bearer token passed to New authorizes control-plane operations.
// It is an operator credential and is never exposed to agents.
package client

import "context"

// EntityType is the orlop entity namespace for agent disks. Each agent maps
// 1:1 to one unique disk.
const EntityType = "agent"

// Disk is the handle to an agent's unique orlop disk.
type Disk struct {
	AgentID     string `json:"agent_id"`
	Handle      string `json:"handle"`       // opaque allocation handle
	VirtualPath string `json:"virtual_path"` // stable mount path, e.g. /mnt/orlop/agents/<id>
	QuotaBytes  int64  `json:"quota_bytes"`  // hard size cap; 0 => the server default
}

// Client talks to the orlop control plane. *HTTPClient is the live
// implementation (see New); *Fake is an in-memory implementation for tests.
type Client interface {
	// AllocateDisk idempotently creates the unique disk for an agent. ownerID is
	// the agent's owning user id; the server derives that user's per-user tenant
	// from it. grantBytes is the initial size grant (0 => the server's default
	// grant); it is the starting size, not the ceiling.
	AllocateDisk(ctx context.Context, agentID, ownerID string, grantBytes int64) (Disk, error)
	// ResolveDisk returns an agent's existing disk handle.
	ResolveDisk(ctx context.Context, agentID string) (Disk, error)
	// SetDiskQuota raises or lowers an existing disk's hard size cap, preserving
	// the allocation handle.
	SetDiskQuota(ctx context.Context, agentID string, grantBytes int64) error
	// RevokeDisk releases an agent's disk allocation. Idempotent: revoking an
	// unknown agent is a no-op.
	RevokeDisk(ctx context.Context, agentID string) error
	// SetAccountBudget sets a user's account disk budget: the shared hard cap all
	// of the user's agents draw from, enforced as one quota on the account's
	// tenant directory.
	SetAccountBudget(ctx context.Context, ownerID string, diskBytes int64) error
	// ReassignDisk re-homes an agent's disk to a new billing owner without moving
	// data: the disk keeps its per-agent tenant, only the allocation's owner
	// flips. Idempotent.
	ReassignDisk(ctx context.Context, agentID, newOwnerID string) error
	// MintEnrollToken returns a short-lived, agent-scoped enroll token. The agent
	// trades it at /agent/enroll for a per-agent client certificate, so the token
	// is the only credential that ever reaches the agent sandbox.
	MintEnrollToken(ctx context.Context, agentID string) (string, error)
	// UserDiskUsage reports a user's aggregate disk usage in bytes (used_bytes
	// across the owner's per-user tenant). Returns 0 when the owner has no disk
	// or has never been placed on a server.
	UserDiskUsage(ctx context.Context, ownerID string) (int64, error)
}

// MountPath returns the deterministic mount path for an agent's disk, so every
// run for the same agent lands on exactly the same files.
func MountPath(agentID string) string {
	return "/mnt/orlop/agents/" + agentID
}
