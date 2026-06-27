package main

import (
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// toUUID / fromUUID bridge the handler layer — which still speaks pgtype.UUID
// via devauth.Identity — and the storage domain layer (uuid.UUID). They go away
// once the handlers and Identity are fully on uuid.UUID.

func toUUID(u pgtype.UUID) uuid.UUID {
	if !u.Valid {
		return uuid.UUID{}
	}
	return uuid.UUID(u.Bytes)
}

func fromUUID(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: true} }
