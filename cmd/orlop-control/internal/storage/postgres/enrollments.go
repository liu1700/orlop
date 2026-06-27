package postgres

import (
	"context"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/db/sqlcdb"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
)

var _ storage.EnrollmentStore = (*Store)(nil)

func enrollment(e sqlcdb.AgentEnrollment) storage.AgentEnrollment {
	return storage.AgentEnrollment{
		ID:           domainUUID(e.ID),
		UserID:       domainUUID(e.UserID),
		CertSerial:   e.CertSerial,
		CertNotAfter: timeOrZero(e.CertNotAfter),
	}
}

func (s *Store) CreateAgentEnrollment(ctx context.Context, in storage.NewAgentEnrollment) error {
	_, err := s.q.CreateAgentEnrollment(ctx, sqlcdb.CreateAgentEnrollmentParams{
		UserID:       pgUUID(in.UserID),
		CertSerial:   in.CertSerial,
		CertNotAfter: tsPtr(&in.CertNotAfter),
	})
	return mapErr(err)
}

func (s *Store) GetActiveEnrollmentByFingerprint(ctx context.Context, fingerprint string) (storage.AgentEnrollment, error) {
	e, err := s.q.GetActiveEnrollmentByFingerprint(ctx, fingerprint)
	if err != nil {
		return storage.AgentEnrollment{}, mapErr(err)
	}
	return enrollment(e), nil
}
