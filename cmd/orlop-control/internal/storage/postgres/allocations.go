package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/db/sqlcdb"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
)

var _ storage.AllocationStore = (*Store)(nil)

func allocation(r sqlcdb.DiskAllocation) storage.Allocation {
	a := storage.Allocation{
		ID:             domainUUID(r.ID),
		UserID:         domainUUID(r.UserID),
		SizeBytes:      r.SizeBytes,
		CreatedAt:      timeOrZero(r.CreatedAt),
		RevokedAt:      timePtr(r.RevokedAt),
		PurgedAt:       timePtr(r.PurgedAt),
		BoundAgentID:   domainUUIDPtr(r.BoundAgentID),
		BoundAt:        timePtr(r.BoundAt),
		LeaseExpiresAt: timePtr(r.LeaseExpiresAt),
	}
	if r.TenantID.Valid {
		a.TenantID = r.TenantID.String
	}
	if r.AgentID.Valid {
		a.AgentID = r.AgentID.String
	}
	return a
}

func user(u sqlcdb.User) storage.User {
	return storage.User{
		ID:         domainUUID(u.ID),
		Email:      u.Email,
		TenantID:   u.TenantID,
		Role:       u.Role,
		QuotaBytes: u.QuotaBytes,
		Suspended:  u.SuspendedAt.Valid,
	}
}

// --- allocations ---

func (s *Store) GetAllocation(ctx context.Context, id uuid.UUID) (storage.Allocation, error) {
	row, err := s.q.GetAllocation(ctx, pgUUID(id))
	if err != nil {
		return storage.Allocation{}, mapErr(err)
	}
	return allocation(row), nil
}

func (s *Store) InsertAllocation(ctx context.Context, userID uuid.UUID, sizeBytes int64) (storage.Allocation, error) {
	row, err := s.q.InsertAllocation(ctx, sqlcdb.InsertAllocationParams{UserID: pgUUID(userID), SizeBytes: sizeBytes})
	if err != nil {
		return storage.Allocation{}, mapErr(err)
	}
	return allocation(row), nil
}

func (s *Store) ListAllocationsForUser(ctx context.Context, userID uuid.UUID) ([]storage.Allocation, error) {
	rows, err := s.q.ListAllocationsForUser(ctx, pgUUID(userID))
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]storage.Allocation, len(rows))
	for i, r := range rows {
		out[i] = allocation(r)
	}
	return out, nil
}

func (s *Store) BindAllocation(ctx context.Context, allocID, userID, agentEnrollmentID uuid.UUID) (storage.Allocation, error) {
	row, err := s.q.BindAllocation(ctx, sqlcdb.BindAllocationParams{
		ID:           pgUUID(allocID),
		UserID:       pgUUID(userID),
		BoundAgentID: pgUUID(agentEnrollmentID),
	})
	if err != nil {
		return storage.Allocation{}, mapErr(err)
	}
	return allocation(row), nil
}

func (s *Store) RevokeAllocation(ctx context.Context, allocID, userID uuid.UUID) error {
	_, err := s.q.RevokeAllocation(ctx, sqlcdb.RevokeAllocationParams{ID: pgUUID(allocID), UserID: pgUUID(userID)})
	return mapErr(err)
}

func (s *Store) MarkAllocationPurged(ctx context.Context, allocID uuid.UUID) (storage.Allocation, error) {
	row, err := s.q.MarkAllocationPurged(ctx, pgUUID(allocID))
	if err != nil {
		return storage.Allocation{}, mapErr(err)
	}
	return allocation(row), nil
}

func (s *Store) UpdateAllocationSize(ctx context.Context, allocID, userID uuid.UUID, sizeBytes int64) (storage.Allocation, error) {
	row, err := s.q.UpdateAllocationSize(ctx, sqlcdb.UpdateAllocationSizeParams{
		ID:        pgUUID(allocID),
		UserID:    pgUUID(userID),
		SizeBytes: sizeBytes,
	})
	if err != nil {
		return storage.Allocation{}, mapErr(err)
	}
	return allocation(row), nil
}

func (s *Store) CountActiveAllocationsForUser(ctx context.Context, userID uuid.UUID) (int64, error) {
	n, err := s.q.CountActiveAllocationsForUser(ctx, pgUUID(userID))
	return n, mapErr(err)
}

// --- mount leases ---

func (s *Store) AcquireMountLease(ctx context.Context, allocID, agentEnrollmentID uuid.UUID, ttl time.Duration) (storage.Allocation, error) {
	row, err := s.q.AcquireMountLease(ctx, sqlcdb.AcquireMountLeaseParams{
		ID:           pgUUID(allocID),
		BoundAgentID: pgUUID(agentEnrollmentID),
		Ttl:          ttlInterval(ttl),
	})
	if err != nil {
		return storage.Allocation{}, mapErr(err)
	}
	return allocation(row), nil
}

func (s *Store) RefreshMountLease(ctx context.Context, allocID, agentEnrollmentID uuid.UUID, ttl time.Duration) (storage.Allocation, error) {
	row, err := s.q.RefreshMountLease(ctx, sqlcdb.RefreshMountLeaseParams{
		ID:           pgUUID(allocID),
		BoundAgentID: pgUUID(agentEnrollmentID),
		Ttl:          ttlInterval(ttl),
	})
	if err != nil {
		return storage.Allocation{}, mapErr(err)
	}
	return allocation(row), nil
}

func (s *Store) ReleaseMountLease(ctx context.Context, allocID, agentEnrollmentID uuid.UUID) (storage.Allocation, error) {
	row, err := s.q.ReleaseMountLease(ctx, sqlcdb.ReleaseMountLeaseParams{
		ID:           pgUUID(allocID),
		BoundAgentID: pgUUID(agentEnrollmentID),
	})
	if err != nil {
		return storage.Allocation{}, mapErr(err)
	}
	return allocation(row), nil
}

func (s *Store) ForceReleaseMountLease(ctx context.Context, allocID, userID uuid.UUID) error {
	_, err := s.q.ForceReleaseMountLease(ctx, sqlcdb.ForceReleaseMountLeaseParams{ID: pgUUID(allocID), UserID: pgUUID(userID)})
	return mapErr(err)
}

// --- enrollments + users ---

func (s *Store) GetAgentEnrollment(ctx context.Context, id uuid.UUID) (storage.AgentEnrollment, error) {
	e, err := s.q.GetAgentEnrollment(ctx, pgUUID(id))
	if err != nil {
		return storage.AgentEnrollment{}, mapErr(err)
	}
	return storage.AgentEnrollment{
		ID:           domainUUID(e.ID),
		UserID:       domainUUID(e.UserID),
		CertSerial:   e.CertSerial,
		CertNotAfter: timeOrZero(e.CertNotAfter),
	}, nil
}

func (s *Store) GetUserForUpdate(ctx context.Context, id uuid.UUID) (storage.User, error) {
	u, err := s.q.GetUserForUpdate(ctx, pgUUID(id))
	if err != nil {
		return storage.User{}, mapErr(err)
	}
	return user(u), nil
}

// --- placement + capacity ---

func (s *Store) GetServerVMByTenant(ctx context.Context, tenantID string) (storage.ServerVM, error) {
	vm, err := s.q.GetServerVMByTenant(ctx, tenantID)
	if err != nil {
		return storage.ServerVM{}, mapErr(err)
	}
	return storage.ServerVM{TenantID: vm.TenantID, DataAddr: vm.DataAddr, Status: vm.Status}, nil
}

func (s *Store) CreateServerVM(ctx context.Context, in storage.NewServerVM) error {
	_, err := s.q.CreateServerVM(ctx, sqlcdb.CreateServerVMParams{
		TenantID: in.TenantID,
		DataAddr: in.DataAddr,
		Status:   in.Status,
	})
	if isUniqueViolation(err) {
		return storage.ErrAlreadyExists
	}
	return mapErr(err)
}

func (s *Store) DeleteServerVM(ctx context.Context, tenantID string) (int64, error) {
	n, err := s.q.DeleteServerVM(ctx, tenantID)
	return n, mapErr(err)
}

func (s *Store) GetServerPoolByDataAddr(ctx context.Context, dataAddr string) (storage.Server, error) {
	p, err := s.q.GetServerPoolByDataAddr(ctx, dataAddr)
	if err != nil {
		return storage.Server{}, mapErr(err)
	}
	return storage.Server{ID: domainUUID(p.ID), DataAddr: p.DataAddr, OpsAddr: p.OpsAddr, Status: p.Status}, nil
}

func (s *Store) PickBestAvailableServer(ctx context.Context, sizeBytes int64) (storage.ChosenServer, error) {
	p, err := s.q.PickBestAvailableServer(ctx, sizeBytes)
	if err != nil {
		return storage.ChosenServer{}, mapErr(err)
	}
	return storage.ChosenServer{ID: domainUUID(p.ID), DataAddr: p.DataAddr, OpsAddr: p.OpsAddr}, nil
}

func (s *Store) ReserveCapacity(ctx context.Context, serverID uuid.UUID, bytes int64) error {
	_, err := s.q.ReserveCapacity(ctx, sqlcdb.ReserveCapacityParams{FreeBytes: bytes, ID: pgUUID(serverID)})
	return mapErr(err)
}

func (s *Store) ReleaseCapacity(ctx context.Context, serverID uuid.UUID, bytes int64) error {
	_, err := s.q.ReleaseCapacity(ctx, sqlcdb.ReleaseCapacityParams{FreeBytes: bytes, ID: pgUUID(serverID)})
	return mapErr(err)
}

func (s *Store) ReserveCapacityForGrowth(ctx context.Context, serverID uuid.UUID, bytes int64) error {
	_, err := s.q.ReserveCapacityForGrowth(ctx, sqlcdb.ReserveCapacityForGrowthParams{FreeBytes: bytes, ID: pgUUID(serverID)})
	return mapErr(err)
}
