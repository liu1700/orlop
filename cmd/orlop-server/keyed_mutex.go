package main

import "sync"

// keyedMutex provides per-key mutual exclusion: holders of the same key run one
// at a time, holders of different keys run concurrently.
//
// It lets tenant registration serialize same-tenant register/unregister/resize
// (idempotency, no duplicate handles, no registered_tenants.json races) WITHOUT
// taking the server-wide serverState.mu across a new tenant's slow JuiceFS
// filesystem initialization. Holding mu across that I/O serializes every other
// registration and stalls every data-plane tenant lookup (mu.RLock) until the
// cold-cache filesystem work finishes (#119).
//
// Entries are reference-counted and removed once idle, so a churn of
// short-lived keys (anonymous per-session tenants) does not accumulate.
//
// The zero value is ready to use; a keyedMutex must not be copied after first use.
type keyedMutex struct {
	mu    sync.Mutex
	locks map[string]*keyedMutexEntry
}

type keyedMutexEntry struct {
	mu   sync.Mutex
	refs int
}

// lock acquires the mutex for key and returns its release function. The release
// function must be called exactly once (typically via defer).
func (k *keyedMutex) lock(key string) func() {
	k.mu.Lock()
	if k.locks == nil {
		k.locks = make(map[string]*keyedMutexEntry)
	}
	e := k.locks[key]
	if e == nil {
		e = &keyedMutexEntry{}
		k.locks[key] = e
	}
	// Bump the refcount while still holding k.mu, before blocking on e.mu, so a
	// concurrent release cannot delete the entry out from under this waiter.
	e.refs++
	k.mu.Unlock()

	e.mu.Lock()

	return func() {
		e.mu.Unlock()
		k.mu.Lock()
		e.refs--
		if e.refs == 0 {
			delete(k.locks, key)
		}
		k.mu.Unlock()
	}
}
