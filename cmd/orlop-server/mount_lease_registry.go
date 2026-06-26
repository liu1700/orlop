package main

import "sync"

// mountLeaseRegistry is the authoritative server-side record of "which lease
// is currently allowed to write to which allocation". It exists so a Take-over
// or Revoke on orlop-control can fence the displaced mount immediately — the
// old client's writes are rejected on the next request rather than waiting up
// to ~30 s for the client's lease-refresh to notice the conflict (issue #175).
//
// Lifecycle:
//
//   - When a client's first write arrives with session_id "mount:<hex>" and
//     allocation_id A, the server calls Install(A, hex). The hex slot is taken;
//     subsequent writes for A carry the same hex, and a fresh re-mount (new hex)
//     takes the slot over — only a fenced hex is barred.
//
//   - When the dashboard revokes (or hands the lease to another agent via
//     Take-over), orlop-control calls Clear(A). Clear moves the active hex
//     into a fenced set: any future write with the same hex is rejected.
//     A new mount on the same allocation can install a fresh hex, but the
//     displaced session can never resurrect.
//
// State lives only in memory. orlop-control's fence call is idempotent, so
// a server restart self-heals: the active slot is empty until a client's first
// write installs a new hex (and any pre-restart, pre-fenced hex is no longer
// banned — which is acceptable, because lease_ids are random and the displaced
// client must complete a new lease_grant first anyway).
type mountLeaseRegistry struct {
	mu    sync.Mutex
	state map[string]*allocationLeaseState
}

type allocationLeaseState struct {
	active string          // currently-installed leaseHex (empty = none)
	fenced map[string]bool // leaseHex values that may not be re-installed
}

func newMountLeaseRegistry() *mountLeaseRegistry {
	return &mountLeaseRegistry{state: make(map[string]*allocationLeaseState)}
}

// Install records leaseHex as the active session for allocationID, unless the hex has
// been fenced (explicitly displaced/revoked). It TAKES OVER a non-fenced active slot left
// by a prior session rather than rejecting: single-writer is enforced upstream — the DB
// mount lease is taken over unconditionally on re-mount, and checkSessionFence verifies
// THIS connection holds that lease before calling Install — so a differing, non-fenced hex
// is a legitimate re-mount, not a competing writer. Returns true on success; false (only
// when the hex is fenced) means the caller must reject the write.
//
// Idempotent: re-installing the same hex on an active slot returns true.
func (r *mountLeaseRegistry) Install(allocationID, leaseHex string) bool {
	if allocationID == "" || leaseHex == "" {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	st := r.state[allocationID]
	if st == nil {
		st = &allocationLeaseState{}
		r.state[allocationID] = st
	}
	if st.fenced[leaseHex] {
		return false
	}
	// Take over any non-fenced active slot. A stale active hex left by a prior pod whose
	// release-fence could not run (e.g. single-node with no server_pool placement → the
	// control-plane FenceAllocation no-ops, so Clear is never called) would otherwise EACCES
	// every write from the next mount → a silently read-only disk (chmod/install fails). The
	// fenced set above still blocks a genuinely displaced/revoked session from resurrecting.
	st.active = leaseHex
	return true
}

// Get returns the active leaseHex for an allocation, or "" if none.
func (r *mountLeaseRegistry) Get(allocationID string) string {
	if allocationID == "" {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if st := r.state[allocationID]; st != nil {
		return st.active
	}
	return ""
}

// Clear empties the active slot for an allocation and fences the previously
// active hex so it cannot be re-installed by a stale client. Called by
// orlop-control on Revoke / owner-driven Force-Unmount. Idempotent.
func (r *mountLeaseRegistry) Clear(allocationID string) {
	if allocationID == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	st := r.state[allocationID]
	if st == nil {
		return
	}
	if st.active != "" {
		if st.fenced == nil {
			st.fenced = make(map[string]bool)
		}
		st.fenced[st.active] = true
		st.active = ""
	}
}

// IsFenced reports whether leaseHex is in the fenced set for allocationID.
// Exported for tests; production callers go through Install / Get.
func (r *mountLeaseRegistry) IsFenced(allocationID, leaseHex string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if st := r.state[allocationID]; st != nil {
		return st.fenced[leaseHex]
	}
	return false
}
