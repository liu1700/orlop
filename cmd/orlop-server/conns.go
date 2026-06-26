package main

import (
	"errors"
	"sync"
	"sync/atomic"

	"github.com/liu1700/orlop/cmd/orlop-server/dataplane"
)

type connRegistry struct {
	mu      sync.Mutex
	writers map[uint64]*frameWriter
	nextID  atomic.Uint64
}

func newConnRegistry() *connRegistry {
	return &connRegistry{writers: map[uint64]*frameWriter{}}
}

func (r *connRegistry) Register(w *frameWriter) uint64 {
	id := r.nextID.Add(1)
	r.mu.Lock()
	r.writers[id] = w
	r.mu.Unlock()
	return id
}

func (r *connRegistry) Unregister(id uint64) {
	r.mu.Lock()
	delete(r.writers, id)
	r.mu.Unlock()
}

func (r *connRegistry) Push(connID uint64, frame dataplane.Frame) error {
	r.mu.Lock()
	w := r.writers[connID]
	r.mu.Unlock()
	if w == nil {
		return errors.New("conn not registered")
	}
	w.send(frame)
	return nil
}
