package main

import (
	"context"
	"errors"
	"testing"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
)

type fakeJournalQueries struct {
	vmErr error
}

func (f *fakeJournalQueries) GetServerVMByTenant(_ context.Context, _ string) (storage.ServerVM, error) {
	return storage.ServerVM{}, f.vmErr
}

func (f *fakeJournalQueries) GetServerPoolByDataAddr(_ context.Context, _ string) (storage.Server, error) {
	return storage.Server{}, errors.New("unexpected GetServerPoolByDataAddr call")
}

// New users have no server_vms row until their first allocation. The adapter
// must return an empty page rather than an error so the dashboard's Recent
// activity widget renders the empty state instead of "Failed to load".
// See #178.
func TestServerapiJournalAdapter_NoServerVMReturnsEmpty(t *testing.T) {
	adapter := &serverapiJournalAdapter{
		queries: &fakeJournalQueries{vmErr: storage.ErrNotFound},
	}

	entries, nextCursor, err := adapter.QueryJournal(context.Background(), "tenant-x", "", 50, "")
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if len(entries) != 0 {
		t.Fatalf("entries = %d, want 0", len(entries))
	}
	if nextCursor != "" {
		t.Fatalf("nextCursor = %q, want empty", nextCursor)
	}
}
