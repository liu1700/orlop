package main

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestJournalPubSubFanOut(t *testing.T) {
	p := newJournalPubSub()
	ctx := context.Background()

	ch1, unsub1 := p.Subscribe(ctx, "alloc1")
	defer unsub1()
	ch2, unsub2 := p.Subscribe(ctx, "alloc1")
	defer unsub2()
	ch3, unsub3 := p.Subscribe(ctx, "alloc1")
	defer unsub3()

	entry := SessionJournalEntry{
		SessionID: "s_a", AllocationID: "alloc1", Seq: 1,
		Path: "/x", Op: SessionOpCreate,
	}
	p.Broadcast("alloc1", entry)

	for i, ch := range []<-chan SessionJournalEntry{ch1, ch2, ch3} {
		select {
		case got := <-ch:
			if got.Seq != entry.Seq || got.Path != entry.Path {
				t.Fatalf("sub %d: got %+v, want seq=%d path=%s", i, got, entry.Seq, entry.Path)
			}
		case <-time.After(time.Second):
			t.Fatalf("sub %d: no entry within 1s", i)
		}
	}
}

func TestJournalPubSubAllocFilter(t *testing.T) {
	p := newJournalPubSub()
	ctx := context.Background()

	chA, unsubA := p.Subscribe(ctx, "alloc1")
	defer unsubA()
	chB, unsubB := p.Subscribe(ctx, "alloc2")
	defer unsubB()

	entry := SessionJournalEntry{
		SessionID: "s_x", AllocationID: "alloc1", Seq: 7, Path: "/y", Op: SessionOpUpdate,
	}
	p.Broadcast("alloc1", entry)

	select {
	case got := <-chA:
		if got.Seq != 7 {
			t.Fatalf("alloc1 sub: seq = %d, want 7", got.Seq)
		}
	case <-time.After(time.Second):
		t.Fatal("alloc1 sub: no entry within 1s")
	}

	select {
	case got := <-chB:
		t.Fatalf("alloc2 sub leaked entry: %+v", got)
	case <-time.After(50 * time.Millisecond):
		// expected: nothing arrived
	}
}

func TestJournalPubSubSlowConsumerDrop(t *testing.T) {
	p := newJournalPubSub()
	ctx := context.Background()

	ch, unsub := p.Subscribe(ctx, "alloc1")
	defer unsub()

	for i := 0; i < journalSubBuffer+1; i++ {
		p.Broadcast("alloc1", SessionJournalEntry{
			SessionID: "s_slow", AllocationID: "alloc1",
			Seq: uint64(i + 1), Path: "/p", Op: SessionOpCreate,
		})
	}

	// Drain what's in the buffer; the read side observes close (ok=false)
	// once the buffered entries are consumed.
	delivered := 0
	closed := false
	deadline := time.After(time.Second)
	for !closed {
		select {
		case _, ok := <-ch:
			if !ok {
				closed = true
				break
			}
			delivered++
		case <-deadline:
			t.Fatalf("channel never closed; delivered=%d", delivered)
		}
	}
	if delivered != journalSubBuffer {
		t.Fatalf("delivered = %d, want %d (the 65th broadcast must trigger drop, not delivery)", delivered, journalSubBuffer)
	}

	// Subscriber must be removed from the map.
	p.mu.RLock()
	remaining := len(p.subs["alloc1"])
	p.mu.RUnlock()
	if remaining != 0 {
		t.Fatalf("dropped subscriber not removed: %d remaining", remaining)
	}
}

func TestJournalPubSubCtxCancelUnsubs(t *testing.T) {
	p := newJournalPubSub()
	ctx, cancel := context.WithCancel(context.Background())
	ch, unsub := p.Subscribe(ctx, "alloc1")
	defer unsub()

	cancel()

	// Channel should close promptly.
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("expected closed channel on ctx cancel")
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("channel did not close within 200ms of ctx cancel")
	}

	// Wait briefly for the watchdog goroutine to finish unregistering.
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		p.mu.RLock()
		n := len(p.subs["alloc1"])
		p.mu.RUnlock()
		if n == 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	p.mu.RLock()
	n := len(p.subs["alloc1"])
	p.mu.RUnlock()
	if n != 0 {
		t.Fatalf("ctx-cancelled subscriber not removed: %d remaining", n)
	}

	// Subsequent broadcast must not panic on the closed channel.
	p.Broadcast("alloc1", SessionJournalEntry{AllocationID: "alloc1", Seq: 99})
}

func TestJournalPubSubNoGoroutineLeak(t *testing.T) {
	p := newJournalPubSub()

	// Warm up: give the runtime a moment to settle.
	runtime.GC()
	time.Sleep(20 * time.Millisecond)
	before := runtime.NumGoroutine()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithCancel(context.Background())
			_, unsub := p.Subscribe(ctx, "alloc1")
			unsub()
			cancel()
		}()
	}
	wg.Wait()

	// Allow watchdog goroutines time to exit after their ctx fires.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		runtime.Gosched()
		if runtime.NumGoroutine()-before <= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	after := runtime.NumGoroutine()
	if diff := after - before; diff > 2 {
		t.Fatalf("goroutine leak: before=%d after=%d diff=%d", before, after, diff)
	}

	// Map should also be empty.
	p.mu.RLock()
	n := len(p.subs)
	p.mu.RUnlock()
	if n != 0 {
		t.Fatalf("subs map not empty: %d allocIDs remain", n)
	}
}
