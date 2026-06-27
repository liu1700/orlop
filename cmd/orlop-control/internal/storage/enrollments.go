package storage

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// NewAgentEnrollment records a freshly minted agent leaf: the owning user plus
// the cert's serial and expiry, used later to revoke the serial on lease release.
type NewAgentEnrollment struct {
	UserID       uuid.UUID
	CertSerial   string
	CertNotAfter time.Time
}

// EnrollmentStore is the agent-enrollment data surface the HTTP handlers reach
// directly (outside a lease transaction). The in-transaction GetAgentEnrollment
// lookup lives on AllocationOps.
type EnrollmentStore interface {
	// CreateAgentEnrollment records a minted leaf.
	CreateAgentEnrollment(ctx context.Context, in NewAgentEnrollment) error
	// GetActiveEnrollmentByFingerprint resolves the unexpired enrollment whose
	// cert serial matches fingerprint (case-insensitive), or ErrNotFound.
	GetActiveEnrollmentByFingerprint(ctx context.Context, fingerprint string) (AgentEnrollment, error)
}
