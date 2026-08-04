package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/allocations"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
)

type stubPurgePendingLister struct {
	rows   []storage.PurgePendingAllocation
	err    error
	limits []int32
}

func (s *stubPurgePendingLister) ListPurgePendingAllocations(_ context.Context, limit int32) ([]storage.PurgePendingAllocation, error) {
	s.limits = append(s.limits, limit)
	return append([]storage.PurgePendingAllocation(nil), s.rows...), s.err
}

type stubAllocationPurger struct {
	mu       sync.Mutex
	errors   map[uuid.UUID]error
	calls    []uuid.UUID
	calledCh chan uuid.UUID
}

func (s *stubAllocationPurger) PurgeAllocation(_ context.Context, _ allocations.AgentDataPurger, allocationID pgtype.UUID) error {
	id := uuid.UUID(allocationID.Bytes)
	s.mu.Lock()
	s.calls = append(s.calls, id)
	err := s.errors[id]
	s.mu.Unlock()
	if s.calledCh != nil {
		s.calledCh <- id
	}
	return err
}

type stubAgentDataPurger struct{}

func (stubAgentDataPurger) PurgeAgentData(context.Context, string, string, string) error {
	return nil
}

func (stubAgentDataPurger) UnregisterTenant(context.Context, string, string) error {
	return nil
}

func (stubAgentDataPurger) ClearActiveMountLease(context.Context, string, string, string) error {
	return nil
}

func testPurgeSweepLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestPurgeSweepCountsFailuresWithoutDroppingTheBatch(t *testing.T) {
	okID := uuid.MustParse("f97000ee-ffb6-468e-8eac-df59bb655fc7")
	failID := uuid.MustParse("75e8fc13-8aaf-4d2a-b9bb-7eea54bed2f4")
	lister := &stubPurgePendingLister{rows: []storage.PurgePendingAllocation{
		{AllocationID: okID, AgentID: "ok"},
		{AllocationID: failID, AgentID: "retry"},
	}}
	purger := &stubAllocationPurger{errors: map[uuid.UUID]error{failID: errors.New("temporary outage")}}
	sweeper := newPurgeSweepHandlers(testPurgeSweepLogger(), lister, purger, stubAgentDataPurger{})

	resp, err := sweeper.sweep(context.Background(), 17)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Pending != 2 || resp.Purged != 1 || resp.Failed != 1 {
		t.Fatalf("response = %+v, want pending=2 purged=1 failed=1", resp)
	}
	if len(lister.limits) != 1 || lister.limits[0] != 17 {
		t.Fatalf("list limits = %v, want [17]", lister.limits)
	}
	purger.mu.Lock()
	defer purger.mu.Unlock()
	if len(purger.calls) != 2 {
		t.Fatalf("purge calls = %v, want both allocations", purger.calls)
	}
}

func TestPurgeSweepRunReconcilesImmediatelyAndStopsWithContext(t *testing.T) {
	id := uuid.MustParse("85de18ba-6f31-463f-bbb1-4e09cc217612")
	lister := &stubPurgePendingLister{rows: []storage.PurgePendingAllocation{{AllocationID: id, AgentID: "agent"}}}
	purger := &stubAllocationPurger{calledCh: make(chan uuid.UUID, 1)}
	sweeper := newPurgeSweepHandlers(testPurgeSweepLogger(), lister, purger, stubAgentDataPurger{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		sweeper.Run(ctx, time.Hour)
		close(done)
	}()

	select {
	case got := <-purger.calledCh:
		if got != id {
			t.Fatalf("purged allocation = %s, want %s", got, id)
		}
	case <-time.After(time.Second):
		t.Fatal("startup reconciliation did not run")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("reconciler did not stop after context cancellation")
	}
}
