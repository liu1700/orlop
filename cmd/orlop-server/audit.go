package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AuditLog is an append-only JSONL writer. The schema mirrors the Rust
// AuditEvent in src/audit.rs so the existing CLI's `orlop audit tail` continues
// to work against the same file.
//
// Writes are pipelined: Record sends the encoded event to a buffered channel
// drained by a single writer goroutine that owns a bufio.Writer wrapping the
// file. Producers do not contend on a mutex and do not pay a syscall per
// event. Backpressure: if the channel fills, Record blocks (we never drop
// audit events). Readers (ReadEvents) call Flush first to make pending
// events visible on disk.
type AuditLog struct {
	file *os.File

	events   chan auditEvent
	flushReq chan chan struct{}
	stop     chan struct{}
	done     chan struct{}
	once     sync.Once
}

const (
	auditChannelBuffer = 1024
	auditFlushInterval = 100 * time.Millisecond
)

func NewAuditLog(path string) (*AuditLog, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create audit dir %s: %w", dir, err)
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open audit log %s: %w", path, err)
	}
	a := &AuditLog{
		file:     f,
		events:   make(chan auditEvent, auditChannelBuffer),
		flushReq: make(chan chan struct{}),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	go a.writeLoop()
	return a, nil
}

// Close drains the in-flight event queue, flushes the bufio writer, and
// closes the underlying file. Safe to call from multiple goroutines; the
// teardown runs at most once.
func (a *AuditLog) Close() error {
	a.once.Do(func() { close(a.stop) })
	<-a.done
	return a.file.Close()
}

func (a *AuditLog) Path() string {
	return a.file.Name()
}

// Flush blocks until all events queued before this call have been written
// to the file's kernel buffer. Used by readers (ReadEvents) to make pending
// writes visible. No-op after Close.
func (a *AuditLog) Flush() {
	if a == nil {
		return
	}
	ack := make(chan struct{})
	select {
	case a.flushReq <- ack:
		<-ack
	case <-a.stop:
	}
}

func (a *AuditLog) writeLoop() {
	defer close(a.done)
	bw := bufio.NewWriter(a.file)
	enc := json.NewEncoder(bw)

	ticker := time.NewTicker(auditFlushInterval)
	defer ticker.Stop()

	drainEvents := func() {
		for {
			select {
			case ev := <-a.events:
				_ = enc.Encode(&ev)
			default:
				return
			}
		}
	}

	for {
		select {
		case ev := <-a.events:
			_ = enc.Encode(&ev)
		case ack := <-a.flushReq:
			drainEvents()
			_ = bw.Flush()
			close(ack)
		case <-ticker.C:
			_ = bw.Flush()
		case <-a.stop:
			drainEvents()
			_ = bw.Flush()
			return
		}
	}
}

// AuditRecord describes a single FS-style event. Fields default to nil/empty;
// the writer omits absent identity fields.
type AuditRecord struct {
	Event       string
	Path        string
	Size        *uint64
	Offset      *int64
	AgentID     string
	TenantID    string
	CertSerial  string
	CertSubject string
	UID         *uint32
	GID         *uint32
	SessionID   *string
	Command     string
	Allowed     bool
	LeaseID     string
	Reason      string

	// Data-plane extensions (issues #81 + #82). All optional; absent fields
	// are omitted from the JSONL line.
	Hash       string  // hex-encoded chunk hash (chunk_*, cache_corrupt)
	Version    *uint64 // manifest version after the op (manifest_*)
	Mode       string  // "read" | "write" (lease_*)
	Count      *uint64 // chunk_has batch size, gc_swept_chunks count
	BytesFreed *uint64 // gc_swept_chunks
	DryRun     *bool   // gc_swept_chunks dry-run mode
	Action     string  // cache_corrupt action (e.g. "drop_and_refetch")
}

type auditEvent struct {
	TS          string  `json:"ts"`
	Event       string  `json:"event"`
	Path        string  `json:"path"`
	Size        *uint64 `json:"size"`
	Offset      *int64  `json:"offset"`
	AgentPID    *uint32 `json:"agent_pid,omitempty"`
	AgentID     string  `json:"agent_id,omitempty"`
	TenantID    string  `json:"tenant_id,omitempty"`
	CertSerial  string  `json:"cert_serial,omitempty"`
	CertSubject string  `json:"cert_subject,omitempty"`
	UID         *uint32 `json:"uid,omitempty"`
	GID         *uint32 `json:"gid,omitempty"`
	SessionID   *string `json:"session_id,omitempty"`
	Command     *string `json:"command"`
	Allowed     bool    `json:"allowed"`
	LeaseID     string  `json:"lease_id,omitempty"`
	Reason      string  `json:"reason,omitempty"`
	Hash        string  `json:"hash,omitempty"`
	Version     *uint64 `json:"version,omitempty"`
	Mode        string  `json:"mode,omitempty"`
	Count       *uint64 `json:"count,omitempty"`
	BytesFreed  *uint64 `json:"bytes_freed,omitempty"`
	DryRun      *bool   `json:"dry_run,omitempty"`
	Action      string  `json:"action,omitempty"`
}

func (a *AuditLog) Record(rec AuditRecord) {
	if a == nil {
		return
	}
	ev := auditEvent{
		TS:          time.Now().UTC().Format(time.RFC3339Nano),
		Event:       rec.Event,
		Path:        rec.Path,
		Size:        rec.Size,
		Offset:      rec.Offset,
		AgentID:     rec.AgentID,
		TenantID:    rec.TenantID,
		CertSerial:  rec.CertSerial,
		CertSubject: rec.CertSubject,
		UID:         rec.UID,
		GID:         rec.GID,
		SessionID:   rec.SessionID,
		Allowed:     rec.Allowed,
		LeaseID:     rec.LeaseID,
		Reason:      rec.Reason,
		Hash:        rec.Hash,
		Version:     rec.Version,
		Mode:        rec.Mode,
		Count:       rec.Count,
		BytesFreed:  rec.BytesFreed,
		DryRun:      rec.DryRun,
		Action:      rec.Action,
	}
	if rec.Command != "" {
		ev.Command = &rec.Command
	}
	select {
	case a.events <- ev:
	case <-a.stop:
	}
}

// ReadEvents reads the audit log line-by-line as parsed JSON values. Used by
// the /audit endpoint to filter and tail events. Flushes pending writes
// first so callers see the latest events.
func (a *AuditLog) ReadEvents() ([]map[string]any, error) {
	a.Flush()
	return readEventsFrom(a.Path())
}

// ReadEvents (free function) reads a JSONL audit file at path. Tests use
// this against fixture files; production callers use the *AuditLog method.
func ReadEvents(path string) ([]map[string]any, error) {
	return readEventsFrom(path)
}

func readEventsFrom(path string) ([]map[string]any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var events []map[string]any
	for _, line := range splitLines(raw) {
		if len(line) == 0 {
			continue
		}
		var v map[string]any
		if err := json.Unmarshal(line, &v); err != nil {
			continue
		}
		events = append(events, v)
	}
	return events, nil
}

// RecordLease emits a lease-lifecycle audit event.
// event is one of: lease_grant, lease_refresh, lease_release, lease_revoke,
// lease_violation. holder is the agent ID. mode is "read" or "write" (empty
// allowed for legacy callers). reason is the contention/eviction cause
// (empty for grant).
func (a *AuditLog) RecordLease(event, holder, path string, leaseID []byte, mode, reason string) {
	if a == nil {
		return
	}
	a.Record(AuditRecord{
		Event:   event,
		Path:    path,
		AgentID: holder,
		LeaseID: hex.EncodeToString(leaseID),
		Mode:    mode,
		Reason:  reason,
		Allowed: true,
	})
}

func splitLines(b []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, c := range b {
		if c == '\n' {
			out = append(out, b[start:i])
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, b[start:])
	}
	return out
}
