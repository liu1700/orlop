package sqlite

import (
	"context"

	"github.com/google/uuid"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
)

var _ storage.EnrollmentStore = (*Store)(nil)

func scanEnrollment(r rowScanner) (storage.AgentEnrollment, error) {
	var e storage.AgentEnrollment
	var notAfter int64
	if err := r.Scan(&e.ID, &e.UserID, &e.CertSerial, &notAfter); err != nil {
		return storage.AgentEnrollment{}, mapErr(err)
	}
	e.CertNotAfter = timeFromMicros(notAfter)
	return e, nil
}

func (s *Store) CreateAgentEnrollment(ctx context.Context, in storage.NewAgentEnrollment) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO agent_enrollments (id, user_id, cert_serial, cert_not_after, enrolled_at)
		 VALUES (?, ?, ?, ?, ?)`,
		uuid.New(), in.UserID, in.CertSerial, micros(in.CertNotAfter), nowMicros())
	return mapErr(err)
}

func (s *Store) GetActiveEnrollmentByFingerprint(ctx context.Context, fingerprint string) (storage.AgentEnrollment, error) {
	return scanEnrollment(s.db.QueryRowContext(ctx,
		`SELECT id, user_id, cert_serial, cert_not_after FROM agent_enrollments
		 WHERE lower(cert_serial) = lower(?) AND cert_not_after > ?`,
		fingerprint, nowMicros()))
}
