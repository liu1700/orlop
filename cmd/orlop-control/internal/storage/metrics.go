package storage

import (
	"context"

	"github.com/google/uuid"
)

// ServerPoolCapacity is the bounded, operator-facing projection used by the
// Prometheus collector. ServerID is stable across address changes and is safe
// to use as a metric label.
type ServerPoolCapacity struct {
	ServerID   uuid.UUID
	TotalBytes int64
	FreeBytes  int64
}

// CapacityMetricsStore exposes the current allocator state needed to alert on
// pool exhaustion and a stuck purge backlog. These reads belong behind the
// storage boundary; operators should not need direct database credentials.
type CapacityMetricsStore interface {
	ListServerPoolCapacity(ctx context.Context) ([]ServerPoolCapacity, error)
	CountPurgePendingAllocations(ctx context.Context) (int64, error)
}
