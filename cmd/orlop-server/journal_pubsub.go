package main

import (
	"context"
	"sync"
)

// journalSub is one subscriber's delivery handle: a buffered channel and the
// context that bounds its lifetime. Bufferring (cap 64) absorbs short
// consumer stalls; a full channel is the signal to drop the subscriber per
// the spec's "bounded loss + browser reconnect/backfill" model.
//
// closeOnce funnels the three close paths (explicit unsub, ctx-cancel,
// slow-consumer drop) through a single close so a channel is never closed
// twice.
type journalSub struct {
	ch        chan SessionJournalEntry
	ctx       context.Context
	closeOnce sync.Once
}

func (s *journalSub) closeChannel() {
	s.closeOnce.Do(func() { close(s.ch) })
}

const journalSubBuffer = 64

// journalPubSub is the in-process fan-out used by SessionJournal to notify
// per-allocation subscribers after a successful journal Append commit. The
// map is keyed by allocation_id so the SSE endpoint and any other consumer
// can subscribe to exactly the allocation the browser cares about.
type journalPubSub struct {
	mu   sync.RWMutex
	subs map[string][]*journalSub
}

func newJournalPubSub() *journalPubSub {
	return &journalPubSub{subs: make(map[string][]*journalSub)}
}

// Subscribe registers a subscriber for allocID and returns a receive-only
// channel plus an unsubscribe func. The channel is closed exactly once: by
// the unsubscribe func, by the ctx-cancel watchdog, or by the slow-consumer
// drop path. Calling the returned unsub more than once is safe.
func (p *journalPubSub) Subscribe(ctx context.Context, allocID string) (<-chan SessionJournalEntry, func()) {
	sub := &journalSub{
		ch:  make(chan SessionJournalEntry, journalSubBuffer),
		ctx: ctx,
	}

	p.mu.Lock()
	p.subs[allocID] = append(p.subs[allocID], sub)
	p.mu.Unlock()

	unsub := func() {
		p.remove(allocID, sub)
		sub.closeChannel()
	}

	go func() {
		<-ctx.Done()
		unsub()
	}()

	return sub.ch, unsub
}

// Broadcast delivers entry to every subscriber registered for allocID. Sends
// are non-blocking: a subscriber whose buffer is full is dropped (channel
// closed, removed from the map) so a slow consumer cannot back up the
// publisher. Lost entries are recovered by the consumer's reconnect+backfill
// path; the in-memory layer does not retry.
//
// RLock is held across the send loop so unsubscribe (which holds the write
// lock before closing the channel) cannot race against an in-flight send.
// Sends are non-blocking, so holding the lock briefly is cheap.
func (p *journalPubSub) Broadcast(allocID string, entry SessionJournalEntry) {
	p.mu.RLock()
	subs := p.subs[allocID]
	var dropped []*journalSub
	for _, sub := range subs {
		select {
		case sub.ch <- entry:
		default:
			dropped = append(dropped, sub)
		}
	}
	p.mu.RUnlock()

	if len(dropped) == 0 {
		return
	}
	p.mu.Lock()
	for _, sub := range dropped {
		p.removeLocked(allocID, sub)
	}
	p.mu.Unlock()
	for _, sub := range dropped {
		sub.closeChannel()
	}
}

// remove takes the write lock and drops sub from allocID's list. No-op if
// sub is not in the list (already dropped or never registered).
func (p *journalPubSub) remove(allocID string, sub *journalSub) {
	p.mu.Lock()
	p.removeLocked(allocID, sub)
	p.mu.Unlock()
}

// removeLocked assumes p.mu is held in write mode.
func (p *journalPubSub) removeLocked(allocID string, sub *journalSub) {
	list := p.subs[allocID]
	for i, s := range list {
		if s == sub {
			p.subs[allocID] = append(list[:i], list[i+1:]...)
			if len(p.subs[allocID]) == 0 {
				delete(p.subs, allocID)
			}
			return
		}
	}
}
