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
// lease, UNCONDITIONALLY taking over any existing lease (only a revoked/missing allocation
// fails, mapped to ErrRevoked/ErrNotFound). An allocation belongs to a single orlop agent,
// so callers the handler authorized (owning user + agent-scoped cert) are always that
// agent; a one-shot pod re-mounts with a fresh enrollment every turn and must take over
// the prior pod's lease — including one a crashed pod leaked, without waiting out the TTL.
// Mount exclusivity is enforced by the handler's ownership check + the data-plane cert.
func (s *Service) AcquireMountLease(ctx context.Context, allocationID, agentID pgtype.UUID, ttl time.Duration) (Allocation, error) {
	row, err := s.store.AcquireMountLease(ctx, toUUID(allocationID), toUUID(agentID), ttl)
	if err == nil {
		return fromStorage(row), nil
	}
	if !errors.Is(err, storage.ErrNotFound) {
		return Allocation{}, fmt.Errorf("acquire: %w", err)
	}
	return Allocation{}, s.classifyLeaseMiss(ctx, allocationID, agentID, true)
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
			return ErrWrongAgent
		}
		if acquired {
			return ErrAlreadyMounted
		}
		// Refresh would succeed in this state, so this branch is unreachable.
		return fmt.Errorf("classify: refresh miss with live lease (state=%+v)", cur)
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
// AcquireMountLease again), ErrWrongAgent if a different agent holds the
// binding, ErrRevoked if the allocation was revoked, or ErrNotFound if the
// allocation id is unknown.
func (s *Service) RefreshMountLease(ctx context.Context, allocationID, agentID pgtype.UUID, ttl time.Duration) (Allocation, error) {
	row, err := s.store.RefreshMountLease(ctx, toUUID(allocationID), toUUID(agentID), ttl)
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
	row, err := s.store.ReleaseMountLease(ctx, toUUID(allocationID), toUUID(agentID))
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
	if cur.BoundAgentID != nil && *cur.BoundAgentID != toUUID(agentID) {
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
