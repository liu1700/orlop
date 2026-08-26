package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
)

const allocationColumns = `id, user_id, tenant_id, agent_id, size_bytes, created_at,
	revoked_at, purged_at, bound_agent_id, bound_at, lease_expires_at`

func scanAllocation(r rowScanner) (storage.Allocation, error) {
	var a storage.Allocation
	var userID, boundAgent uuid.NullUUID
	var tenantID, agentID sql.NullString
	var created int64
	var revoked, purged, boundAt, leaseExp sql.NullInt64
	if err := r.Scan(&a.ID, &userID, &tenantID, &agentID, &a.SizeBytes, &created,
		&revoked, &purged, &boundAgent, &boundAt, &leaseExp); err != nil {
		return storage.Allocation{}, mapErr(err)
	}
	if userID.Valid {
		a.UserID = userID.UUID
	}
	a.TenantID = tenantID.String
	a.AgentID = agentID.String
	a.CreatedAt = timeFromMicros(created)
	a.RevokedAt = timePtrFromMicros(revoked)
	a.PurgedAt = timePtrFromMicros(purged)
	a.BoundAgentID = ptrUUID(boundAgent)
	a.BoundAt = timePtrFromMicros(boundAt)
	a.LeaseExpiresAt = timePtrFromMicros(leaseExp)
	return a, nil
}

// --- allocations ---

func (s *Store) GetAllocation(ctx context.Context, id uuid.UUID) (storage.Allocation, error) {
	return scanAllocation(s.db.QueryRowContext(ctx,
		`SELECT `+allocationColumns+` FROM disk_allocations WHERE id = ?`, id))
}

func (s *Store) InsertAllocation(ctx context.Context, userID uuid.UUID, sizeBytes int64) (storage.Allocation, error) {
	return scanAllocation(s.db.QueryRowContext(ctx,
		`INSERT INTO disk_allocations (id, user_id, size_bytes, created_at) VALUES (?, ?, ?, ?)
		 RETURNING `+allocationColumns,
		uuid.New(), userID, sizeBytes, nowMicros()))
}

func (s *Store) ListAllocationsForUser(ctx context.Context, userID uuid.UUID) ([]storage.Allocation, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+allocationColumns+` FROM disk_allocations
		 WHERE user_id = ? AND user_id IS NOT NULL AND revoked_at IS NULL
		 ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []storage.Allocation{}
	for rows.Next() {
		a, err := scanAllocation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, mapErr(rows.Err())
}

func (s *Store) BindAllocation(ctx context.Context, allocID, userID, agentEnrollmentID uuid.UUID) (storage.Allocation, error) {
	return scanAllocation(s.db.QueryRowContext(ctx,
		`UPDATE disk_allocations SET bound_agent_id = ?, bound_at = ?
		 WHERE id = ? AND user_id = ? AND revoked_at IS NULL AND bound_agent_id IS NULL
		 RETURNING `+allocationColumns,
		agentEnrollmentID, nowMicros(), allocID, userID))
}

func (s *Store) RevokeAllocation(ctx context.Context, allocID, userID uuid.UUID) error {
	// COALESCE keeps the first revoked_at (idempotent); zero rows means wrong
	// user / missing allocation.
	var id uuid.UUID
	err := s.db.QueryRowContext(ctx,
		`UPDATE disk_allocations SET revoked_at = COALESCE(revoked_at, ?)
		 WHERE id = ? AND user_id = ? RETURNING id`,
		nowMicros(), allocID, userID).Scan(&id)
	return mapErr(err)
}

func (s *Store) MarkAllocationPurged(ctx context.Context, allocID uuid.UUID) (storage.Allocation, error) {
	// CAS the purge: only one caller flips purged_at from NULL on a revoked row.
	return scanAllocation(s.db.QueryRowContext(ctx,
		`UPDATE disk_allocations SET purged_at = ?
		 WHERE id = ? AND revoked_at IS NOT NULL AND purged_at IS NULL
		 RETURNING `+allocationColumns,
		nowMicros(), allocID))
}

func (s *Store) UpdateAllocationSize(ctx context.Context, allocID, userID uuid.UUID, sizeBytes int64) (storage.Allocation, error) {
	return scanAllocation(s.db.QueryRowContext(ctx,
		`UPDATE disk_allocations SET size_bytes = ?
		 WHERE id = ? AND user_id = ? AND revoked_at IS NULL
		 RETURNING `+allocationColumns,
		sizeBytes, allocID, userID))
}

func (s *Store) CountActiveAllocationsForUser(ctx context.Context, userID uuid.UUID) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx,
		`SELECT count(*) FROM disk_allocations WHERE user_id = ? AND revoked_at IS NULL`, userID).Scan(&n)
	return n, mapErr(err)
}

func (s *Store) ListPurgePendingAllocations(ctx context.Context, limit int32) ([]storage.PurgePendingAllocation, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT da.id, da.agent_id
		 FROM disk_allocations da
		 JOIN users u ON u.id = da.user_id
		 WHERE da.revoked_at IS NOT NULL AND da.purged_at IS NULL
		   AND da.agent_id IS NOT NULL AND da.user_id IS NOT NULL
		 ORDER BY da.revoked_at ASC
		 LIMIT ?`, limit)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []storage.PurgePendingAllocation{}
	for rows.Next() {
		var p storage.PurgePendingAllocation
		var agentID sql.NullString
		if err := rows.Scan(&p.AllocationID, &agentID); err != nil {
			return nil, mapErr(err)
		}
		p.AgentID = agentID.String
		out = append(out, p)
	}
	return out, mapErr(rows.Err())
}

// --- mount leases ---

func (s *Store) AcquireMountLease(ctx context.Context, allocID, agentEnrollmentID uuid.UUID, ttl time.Duration, force bool, leaseTokenHash string) (storage.Allocation, error) {
	now := time.Now()
	// bound_at is preserved for a same-agent re-mount, reset otherwise. The
	// CASE sees the pre-update bound_agent_id. Without force, a live lease
	// held by a DIFFERENT enrollment blocks the takeover (issue #93); a
	// released/expired lease — including one a crashed pod leaked — is
	// claimable freely, and force is the explicit crash-recovery override.
	return scanAllocation(s.db.QueryRowContext(ctx,
		`UPDATE disk_allocations
		    SET bound_agent_id   = ?,
		        bound_at         = CASE WHEN bound_agent_id = ? THEN bound_at ELSE ? END,
		        lease_expires_at = ?,
		        mount_lease_token_hash = ?
		  WHERE id = ? AND revoked_at IS NULL
		    AND (? OR bound_agent_id IS NULL OR bound_agent_id = ?
		         OR lease_expires_at IS NULL OR lease_expires_at <= ?)
		  RETURNING `+allocationColumns,
		agentEnrollmentID, agentEnrollmentID, micros(now), micros(now.Add(ttl)), leaseTokenHash, allocID,
		force, agentEnrollmentID, micros(now)))
}

func (s *Store) RefreshMountLease(ctx context.Context, allocID, agentEnrollmentID uuid.UUID, ttl time.Duration, leaseTokenHash, newLeaseTokenHash string) (storage.Allocation, error) {
	now := time.Now()
	// A non-empty token proves continuity across enrollment/cert rotation. A
	// takeover replaces it, so the displaced process cannot reclaim the lease.
	// Empty-token clients retain the enrollment guard for rolling upgrades.
	return scanAllocation(s.db.QueryRowContext(ctx,
		`UPDATE disk_allocations SET bound_agent_id = ?, lease_expires_at = ?,
		    mount_lease_token_hash = CASE WHEN ? <> '' THEN ? ELSE mount_lease_token_hash END
		  WHERE id = ? AND revoked_at IS NULL
		    AND lease_expires_at IS NOT NULL AND lease_expires_at > ?
		    AND ((? <> '' AND mount_lease_token_hash = ?)
		         OR (? = '' AND mount_lease_token_hash IS NULL AND bound_agent_id = ?))
		  RETURNING `+allocationColumns,
		agentEnrollmentID, micros(now.Add(ttl)), newLeaseTokenHash, newLeaseTokenHash, allocID, micros(now),
		leaseTokenHash, leaseTokenHash, leaseTokenHash, agentEnrollmentID))
}

func (s *Store) ReleaseMountLease(ctx context.Context, allocID, agentEnrollmentID uuid.UUID, leaseTokenHash string) (storage.Allocation, error) {
	return scanAllocation(s.db.QueryRowContext(ctx,
		`UPDATE disk_allocations
		    SET bound_agent_id = NULL, bound_at = NULL, lease_expires_at = NULL,
		        mount_lease_token_hash = NULL
		  WHERE id = ? AND (bound_agent_id IS NULL
		    OR (? <> '' AND mount_lease_token_hash = ?)
		    OR (? = '' AND mount_lease_token_hash IS NULL AND bound_agent_id = ?))
		  RETURNING `+allocationColumns,
		allocID, leaseTokenHash, leaseTokenHash, leaseTokenHash, agentEnrollmentID))
}

func (s *Store) ForceReleaseMountLease(ctx context.Context, allocID, userID uuid.UUID) error {
	var id uuid.UUID
	err := s.db.QueryRowContext(ctx,
		`UPDATE disk_allocations SET bound_agent_id = NULL, bound_at = NULL, lease_expires_at = NULL,
		                              mount_lease_token_hash = NULL
		  WHERE id = ? AND user_id = ? AND revoked_at IS NULL RETURNING id`,
		allocID, userID).Scan(&id)
	return mapErr(err)
}

// --- enrollments + revocation (the in-tx kill switch) ---

func (s *Store) GetAgentEnrollment(ctx context.Context, id uuid.UUID) (storage.AgentEnrollment, error) {
	return scanEnrollment(s.db.QueryRowContext(ctx,
		`SELECT id, user_id, cert_serial, cert_not_after FROM agent_enrollments WHERE id = ?`, id))
}

// --- users ---

func (s *Store) GetUserForUpdate(ctx context.Context, id uuid.UUID) (storage.User, error) {
	// SQLite has no SELECT ... FOR UPDATE; the immediate write-lock transaction
	// (and the single-writer pool) already serialize the read-modify-write.
	return scanUser(s.db.QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE id = ?`, id))
}

// --- placement + capacity ---

func (s *Store) GetServerVMByTenant(ctx context.Context, tenantID string) (storage.ServerVM, error) {
	var vm storage.ServerVM
	err := s.db.QueryRowContext(ctx,
		`SELECT tenant_id, data_addr, status FROM server_vms WHERE tenant_id = ?`, tenantID).
		Scan(&vm.TenantID, &vm.DataAddr, &vm.Status)
	if err != nil {
		return storage.ServerVM{}, mapErr(err)
	}
	return vm, nil
}

func (s *Store) CreateServerVM(ctx context.Context, in storage.NewServerVM) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO server_vms (id, tenant_id, data_addr, status, created_at) VALUES (?, ?, ?, ?, ?)`,
		uuid.New(), in.TenantID, in.DataAddr, in.Status, nowMicros())
	return mapErr(err)
}

func (s *Store) DeleteServerVM(ctx context.Context, tenantID string) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM server_vms WHERE tenant_id = ?`, tenantID)
	if err != nil {
		return 0, mapErr(err)
	}
	n, err := res.RowsAffected()
	return n, mapErr(err)
}

func (s *Store) GetServerPoolByDataAddr(ctx context.Context, dataAddr string) (storage.Server, error) {
	var srv storage.Server
	err := s.db.QueryRowContext(ctx,
		`SELECT id, data_addr, ops_addr, status FROM server_pool WHERE data_addr = ?`, dataAddr).
		Scan(&srv.ID, &srv.DataAddr, &srv.OpsAddr, &srv.Status)
	if err != nil {
		return storage.Server{}, mapErr(err)
	}
	return srv, nil
}

func (s *Store) PickBestAvailableServer(ctx context.Context, sizeBytes int64) (storage.ChosenServer, error) {
	var c storage.ChosenServer
	err := s.db.QueryRowContext(ctx,
		`SELECT id, data_addr, ops_addr FROM server_pool
		  WHERE status = 'available' AND free_bytes >= ?
		  ORDER BY free_bytes DESC, data_addr LIMIT 1`, sizeBytes).
		Scan(&c.ID, &c.DataAddr, &c.OpsAddr)
	if err != nil {
		return storage.ChosenServer{}, mapErr(err)
	}
	return c, nil
}

func (s *Store) ReserveCapacity(ctx context.Context, serverID uuid.UUID, bytes int64) error {
	var id uuid.UUID
	err := s.db.QueryRowContext(ctx,
		`UPDATE server_pool SET free_bytes = free_bytes - ?, updated_at = ?
		  WHERE id = ? AND status = 'available' AND free_bytes >= ? RETURNING id`,
		bytes, nowMicros(), serverID, bytes).Scan(&id)
	return mapErr(err)
}

func (s *Store) ReleaseCapacity(ctx context.Context, serverID uuid.UUID, bytes int64) error {
	var id uuid.UUID
	err := s.db.QueryRowContext(ctx,
		`UPDATE server_pool SET free_bytes = MIN(free_bytes + ?, total_bytes), updated_at = ?
		  WHERE id = ? RETURNING id`,
		bytes, nowMicros(), serverID).Scan(&id)
	return mapErr(err)
}

func (s *Store) ReserveCapacityForGrowth(ctx context.Context, serverID uuid.UUID, bytes int64) error {
	var id uuid.UUID
	err := s.db.QueryRowContext(ctx,
		`UPDATE server_pool SET free_bytes = free_bytes - ?, updated_at = ?
		  WHERE id = ? AND status IN ('available', 'draining') AND free_bytes >= ? RETURNING id`,
		bytes, nowMicros(), serverID, bytes).Scan(&id)
	return mapErr(err)
}

func (s *Store) ListOwnerCapacityReservations(ctx context.Context, userID uuid.UUID) ([]storage.OwnerCapacityReservation, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT r.user_id, r.server_id, r.size_bytes, sp.data_addr, sp.ops_addr
		   FROM owner_capacity_reservations r JOIN server_pool sp ON sp.id = r.server_id
		  WHERE r.user_id = ? ORDER BY r.created_at, r.server_id`, userID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var out []storage.OwnerCapacityReservation
	for rows.Next() {
		var r storage.OwnerCapacityReservation
		if err := rows.Scan(&r.UserID, &r.ServerID, &r.SizeBytes, &r.DataAddr, &r.OpsAddr); err != nil {
			return nil, mapErr(err)
		}
		out = append(out, r)
	}
	return out, mapErr(rows.Err())
}

func (s *Store) CreateOwnerCapacityReservation(ctx context.Context, userID, serverID uuid.UUID, sizeBytes int64) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO owner_capacity_reservations (user_id, server_id, size_bytes, created_at) VALUES (?, ?, ?, ?)`,
		userID, serverID, sizeBytes, nowMicros())
	return mapErr(err)
}

func (s *Store) UpdateOwnerCapacityReservationSize(ctx context.Context, userID, serverID uuid.UUID, sizeBytes int64) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE owner_capacity_reservations SET size_bytes = ? WHERE user_id = ? AND server_id = ?`,
		sizeBytes, userID, serverID)
	return mapErr(err)
}

func (s *Store) DeleteOwnerCapacityReservation(ctx context.Context, userID, serverID uuid.UUID) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM owner_capacity_reservations WHERE user_id = ? AND server_id = ?`, userID, serverID)
	if err != nil {
		return 0, mapErr(err)
	}
	n, err := res.RowsAffected()
	return n, mapErr(err)
}

func (s *Store) CountPlacedAllocationsForUserOnServer(ctx context.Context, userID uuid.UUID, dataAddr string) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx,
		`SELECT count(DISTINCT sv.tenant_id)
		   FROM disk_allocations da
		   JOIN users u ON u.id = da.user_id
		   JOIN server_vms sv ON sv.tenant_id = COALESCE(da.tenant_id, u.tenant_id)
		  WHERE da.user_id = ? AND da.purged_at IS NULL AND sv.data_addr = ?`,
		userID, dataAddr).Scan(&n)
	return n, mapErr(err)
}
