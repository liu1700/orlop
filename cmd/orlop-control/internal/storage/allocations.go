package storage

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

// ErrAlreadyExists is returned when a unique constraint would be violated (e.g.
// placing a tenant that another caller placed concurrently). Adapters map their
// driver's unique-violation onto it.
var ErrAlreadyExists = errors.New("storage: already exists")

// Allocation is a disk_allocations row projection.
type Allocation struct {
	ID             uuid.UUID
	UserID         uuid.UUID
	TenantID       string // per-agent / per-user storage tenant; "" if unset
	AgentID        string // orlop agent id; "" if not agent-scoped
	SizeBytes      int64
	CreatedAt      time.Time
	RevokedAt      *time.Time
	PurgedAt       *time.Time
	BoundAgentID   *uuid.UUID // FK into agent_enrollments
	BoundAt        *time.Time
	LeaseExpiresAt *time.Time
}

// AgentEnrollment is the cert-issuance record bound to an allocation's lease.
type AgentEnrollment struct {
	ID           uuid.UUID
	UserID       uuid.UUID
	CertSerial   string
	CertNotAfter time.Time
}

// ServerVM is a tenant→server placement (server_vms).
type ServerVM struct {
	TenantID string
	DataAddr string
	Status   string
}

// Server is the server_pool fields the allocations workflow reads.
type Server struct {
	ID       uuid.UUID
	DataAddr string
	OpsAddr  string
	Status   string
}

// ChosenServer is the placement target PickBestAvailableServer returns.
type ChosenServer struct {
	ID       uuid.UUID
	DataAddr string
	OpsAddr  string
}

// NewServerVM records a tenant placement.
type NewServerVM struct {
	TenantID string
	DataAddr string
	Status   string
}

// AllocationOps is the read/write surface for disks, leases, placement, and
// capacity, available directly on an AllocationStore and inside a Tx.
type AllocationOps interface {
	// Allocations.
	GetAllocation(ctx context.Context, id uuid.UUID) (Allocation, error)
	InsertAllocation(ctx context.Context, userID uuid.UUID, sizeBytes int64) (Allocation, error)
	ListAllocationsForUser(ctx context.Context, userID uuid.UUID) ([]Allocation, error)
	BindAllocation(ctx context.Context, allocID, userID, agentEnrollmentID uuid.UUID) (Allocation, error)
	RevokeAllocation(ctx context.Context, allocID, userID uuid.UUID) error
	MarkAllocationPurged(ctx context.Context, allocID uuid.UUID) (Allocation, error)
	UpdateAllocationSize(ctx context.Context, allocID, userID uuid.UUID, sizeBytes int64) (Allocation, error)
	CountActiveAllocationsForUser(ctx context.Context, userID uuid.UUID) (int64, error)
	SumActiveAllocationBytes(ctx context.Context, userID uuid.UUID) (int64, error)

	// Mount leases.
	AcquireMountLease(ctx context.Context, allocID, agentEnrollmentID uuid.UUID, ttl time.Duration) (Allocation, error)
	RefreshMountLease(ctx context.Context, allocID, agentEnrollmentID uuid.UUID, ttl time.Duration) (Allocation, error)
	ReleaseMountLease(ctx context.Context, allocID, agentEnrollmentID uuid.UUID) (Allocation, error)
	ForceReleaseMountLease(ctx context.Context, allocID, userID uuid.UUID) error

	// Enrollments + revocation (the lease-release kill switch).
	GetAgentEnrollment(ctx context.Context, id uuid.UUID) (AgentEnrollment, error)
	AddCertRevocation(ctx context.Context, rev CertRevocation) error

	// Users.
	GetUser(ctx context.Context, id uuid.UUID) (User, error)
	GetUserForUpdate(ctx context.Context, id uuid.UUID) (User, error)

	// Placement + capacity.
	GetServerVMByTenant(ctx context.Context, tenantID string) (ServerVM, error)
	CreateServerVM(ctx context.Context, in NewServerVM) error // ErrAlreadyExists on a duplicate tenant
	DeleteServerVM(ctx context.Context, tenantID string) (int64, error)
	GetServerPoolByDataAddr(ctx context.Context, dataAddr string) (Server, error)
	PickBestAvailableServer(ctx context.Context, sizeBytes int64) (ChosenServer, error)
	ReserveCapacity(ctx context.Context, serverID uuid.UUID, bytes int64) error // ErrNotFound when none fits
	ReleaseCapacity(ctx context.Context, serverID uuid.UUID, bytes int64) error
	ReserveCapacityForGrowth(ctx context.Context, serverID uuid.UUID, bytes int64) error // ErrNotFound when full
}

// AllocationStore is the allocations data layer plus transaction control.
type AllocationStore interface {
	AllocationOps
	beginner
}
