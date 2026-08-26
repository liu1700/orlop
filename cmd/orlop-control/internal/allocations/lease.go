package allocations

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
)

// AcquireMountLease atomically claims the allocation for agentID and sets a fresh mount
// lease. An allocation belongs to a single orlop agent, so callers the handler authorized
// (owning user + agent-scoped cert) are always that agent; a one-shot pod re-mounts with
// a fresh enrollment every turn and claims freely once the prior lease is released or
// expired. A lease that is still LIVE for a DIFFERENT enrollment is NOT taken over unless
// force is set: the incumbent is refreshing and mid-write, so a silent takeover turns a
// caller bug (concurrent double-mount) into silent data loss (issue #93) — the refusal is
// reported as *LeaseLiveError carrying the incumbent's bound_at/lease_expires_at. force
// is the caller's explicit assertion that the incumbent's host is gone (crash recovery,
// dashboard take-over), skipping the TTL wait; a forced takeover of a live lease is
// audit-logged. Mount exclusivity is otherwise enforced by the handler's ownership check
// + the data-plane cert.
func (s *Service) AcquireMountLease(ctx context.Context, allocationID, agentID pgtype.UUID, ttl time.Duration, force bool) (Allocation, error) {
	return s.AcquireMountLeaseWithToken(ctx, allocationID, agentID, ttl, force, "")
}

// AcquireMountLeaseWithToken is the protocol-aware acquire path. tokenHash is
// empty for legacy clients and a SHA-256 digest for clients that can preserve
// lease continuity across certificate renewal.
func (s *Service) AcquireMountLeaseWithToken(ctx context.Context, allocationID, agentID pgtype.UUID, ttl time.Duration, force bool, tokenHash string) (Allocation, error) {
	if force {
		s.logLiveTakeover(ctx, allocationID, agentID)
	}
	row, err := s.store.AcquireMountLease(ctx, toUUID(allocationID), toUUID(agentID), ttl, force, tokenHash)
	if err == nil {
		return fromStorage(row), nil
	}
	if !errors.Is(err, storage.ErrNotFound) {
		return Allocation{}, fmt.Errorf("acquire: %w", err)
	}
	return Allocation{}, s.classifyLeaseMiss(ctx, allocationID, agentID, true)
}

// logLiveTakeover records that a forced acquire is about to displace a live
// lease held by a different enrollment, so a double-mount is diagnosable from
// control-plane logs in minutes instead of from FUSE logs after the fact
// (issue #93). Best-effort and read-before-update (a benign race): a lookup
// failure only costs the log line, never the acquire.
func (s *Service) logLiveTakeover(ctx context.Context, allocationID, agentID pgtype.UUID) {
	cur, err := s.store.GetAllocation(ctx, toUUID(allocationID))
	if err != nil {
		return
	}
	agent := toUUID(agentID)
	if cur.LeaseExpiresAt == nil || !cur.LeaseExpiresAt.After(time.Now()) ||
		cur.BoundAgentID == nil || *cur.BoundAgentID == agent {
		return
	}
	s.logger.Warn("mount_lease_forced_takeover",
		"allocation_id", toUUID(allocationID).String(),
		"incumbent_agent_id", cur.BoundAgentID.String(),
		"new_agent_id", agent.String(),
		"incumbent_lease_remaining", time.Until(*cur.LeaseExpiresAt).Round(time.Millisecond).String(),
	)
}

// classifyLeaseMiss reads the current row to map a zero-rows update to the
// right sentinel error. acquired=true means the failing call was an Acquire
// (so a live lease for the same agent should map to ErrAlreadyMounted);
// acquired=false means the call was a Refresh (live lease is the success
// case, so this branch should not happen).
func (s *Service) classifyLeaseMiss(ctx context.Context, allocationID, agentID pgtype.UUID, acquired bool) error {
	cur, err := s.store.GetAllocation(ctx, toUUID(allocationID))
	if errors.Is(err, storage.ErrNotFound) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("get after lease miss: %w", err)
	}
	agent := toUUID(agentID)
	if cur.RevokedAt != nil {
		return ErrRevoked
	}
	if cur.LeaseExpiresAt != nil && cur.LeaseExpiresAt.After(time.Now()) {
		if cur.BoundAgentID == nil || *cur.BoundAgentID != agent {
			if acquired {
				// The guarded acquire refused to displace a live lease held
				// by a different enrollment (issue #93). Surface who holds it
				// so the caller can decide whether to force.
				return &LeaseLiveError{BoundAt: cur.BoundAt, LeaseExpiresAt: *cur.LeaseExpiresAt}
			}
			return ErrWrongAgent
		}
		if acquired {
			return ErrAlreadyMounted
		}
		// A token-aware refresh can miss even when the enrollment still matches:
		// a re-acquire/takeover replaced its continuity token. Treat that stale
		// holder exactly like any other displaced agent.
		return ErrWrongAgent
	}
	if cur.BoundAgentID == nil || *cur.BoundAgentID != agent {
		if acquired {
			return fmt.Errorf("classify: acquire miss without live lease (state=%+v)", cur)
		}
		return ErrWrongAgent
	}
	// Lease expired or absent.
	if !acquired {
		return ErrLeaseLost
	}
	// Acquired with no live lease: the conditional update should have hit.
	// Treat as a transient race — caller may retry.
	return fmt.Errorf("classify: acquire miss with no live lease (state=%+v)", cur)
}

// RefreshMountLease extends the lease for the agent that already holds it.
// Returns ErrLeaseLost if the lease has already expired (caller must call
// AcquireMountLease again, preserving expiry as the takeover serialization
// boundary), ErrWrongAgent if a different agent holds the
// binding, ErrRevoked if the allocation was revoked, or ErrNotFound if the
// allocation id is unknown.
func (s *Service) RefreshMountLease(ctx context.Context, allocationID, agentID pgtype.UUID, ttl time.Duration) (Allocation, error) {
	return s.RefreshMountLeaseWithToken(ctx, allocationID, agentID, ttl, "", "")
}

// RefreshMountLeaseWithToken permits a renewed enrollment to replace the
// per-certificate binding only when it presents the token minted by acquire.
func (s *Service) RefreshMountLeaseWithToken(ctx context.Context, allocationID, agentID pgtype.UUID, ttl time.Duration, tokenHash, newTokenHash string) (Allocation, error) {
	row, err := s.store.RefreshMountLease(ctx, toUUID(allocationID), toUUID(agentID), ttl, tokenHash, newTokenHash)
	if err == nil {
		return fromStorage(row), nil
	}
	if !errors.Is(err, storage.ErrNotFound) {
		return Allocation{}, fmt.Errorf("refresh: %w", err)
	}
	return Allocation{}, s.classifyLeaseMiss(ctx, allocationID, agentID, false)
}

// ReleaseMountLease clears the binding (bound_agent_id, bound_at) and the
// lease, returning the allocation to Free state. Idempotent: calling on an
// already-Free allocation is a no-op.
// Errors with ErrWrongAgent if the binding belongs to a different agent.
func (s *Service) ReleaseMountLease(ctx context.Context, allocationID, agentID pgtype.UUID) error {
	return s.ReleaseMountLeaseWithToken(ctx, allocationID, agentID, "")
}

// ReleaseMountLeaseWithToken mirrors refresh continuity so a mount stopped
// immediately after certificate rotation can still clear its lease.
func (s *Service) ReleaseMountLeaseWithToken(ctx context.Context, allocationID, agentID pgtype.UUID, tokenHash string) error {
	row, err := s.store.ReleaseMountLease(ctx, toUUID(allocationID), toUUID(agentID), tokenHash)
	if err == nil {
		// Revoke the released agent's leaf so a leaked copy can't keep mounting
		// until its TTL lapses (issue #5).
		s.revokeReleasedAgentCert(ctx, toUUID(agentID), row.TenantID)
		return nil
	}
	if !errors.Is(err, storage.ErrNotFound) {
		return fmt.Errorf("release: %w", err)
	}
	cur, gerr := s.store.GetAllocation(ctx, toUUID(allocationID))
	if errors.Is(gerr, storage.ErrNotFound) {
		return ErrNotFound
	}
	if gerr != nil {
		return fmt.Errorf("get after release miss: %w", gerr)
	}
	if cur.BoundAgentID != nil && (*cur.BoundAgentID != toUUID(agentID) || tokenHash != "") {
		return ErrWrongAgent
	}
	return fmt.Errorf("release: zero rows but no guard matched (state=%+v)", cur)
}

// revokeReleasedAgentCert adds the released agent's leaf serial to the cert
// deny-list (issue #5), so a leaked copy is killed at the next handshake instead
// of surviving its full TTL. Best-effort: a missing enrollment or DB failure is
// logged, never fatal to the release. The serial is recorded with the cert's
// own expiry so it can be pruned once the cert would lapse anyway.
func (s *Service) revokeReleasedAgentCert(ctx context.Context, enrollmentID uuid.UUID, tenantID string) {
	if enrollmentID == (uuid.UUID{}) {
		return
	}
	enr, err := s.store.GetAgentEnrollment(ctx, enrollmentID)
	if err != nil {
		if !errors.Is(err, storage.ErrNotFound) {
			s.logger.Warn("cert_revocation_lookup_failed", "error", err)
		}
		return
	}
	if err := s.store.AddCertRevocation(ctx, storage.CertRevocation{
		Serial:    enr.CertSerial,
		TenantID:  tenantID,
		ExpiresAt: enr.CertNotAfter,
		Reason:    "lease_released",
	}); err != nil {
		s.logger.Warn("cert_revocation_add_failed", "error", err, "cert_serial", enr.CertSerial)
		return
	}
	s.logger.Info("cert_revoked", "cert_serial", enr.CertSerial, "reason", "lease_released")
}
