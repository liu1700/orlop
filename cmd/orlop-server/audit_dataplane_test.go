package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestDataPlaneAuditShapes verifies that the new event types from issue #82
// land with the documented field shape. We assert just the fields that
// dashboards / `orlop audit tail --event` will key on so the test stays
// resistant to additive changes elsewhere.
func TestDataPlaneAuditShapes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	a, err := NewAuditLog(path)
	if err != nil {
		t.Fatal(err)
	}

	// chunk_get / chunk_put / chunk_has
	hash := []byte("01234567890123456789012345678901")
	size := uint64(4096)
	a.Record(AuditRecord{Event: "chunk_get", Hash: "deadbeef", Size: &size, Allowed: true})
	a.Record(AuditRecord{Event: "chunk_put", Hash: "cafebabe", Size: &size, Allowed: true})
	count := uint64(8)
	a.Record(AuditRecord{Event: "chunk_has", Count: &count, Allowed: true})
	_ = hash

	// manifest_get / manifest_put with version
	v := uint64(7)
	a.Record(AuditRecord{Event: "manifest_get", Path: "/x", Size: &size, Version: &v, Allowed: true})
	a.Record(AuditRecord{Event: "manifest_put", Path: "/x", Size: &size, Version: &v, Allowed: true})

	// lease lifecycle — must include mode + reason
	a.RecordLease("lease_grant", "agent-a", "/x", []byte("0123456789abcdef"), "write", "")
	a.RecordLease("lease_refresh", "agent-a", "/x", []byte("0123456789abcdef"), "write", "")
	a.RecordLease("lease_revoke", "agent-a", "/x", []byte("0123456789abcdef"), "write", "contention")
	a.RecordLease("lease_release", "agent-a", "/x", []byte("0123456789abcdef"), "write", "client")
	a.RecordLease("lease_violation", "agent-a", "/x", []byte("0123456789abcdef"), "write", "revoke_timeout")

	// gc_swept_chunks — emitted directly by gc.go in production. This stand-
	// in verifies the JSONL shape so dashboards (and `orlop audit tail
	// --event gc_swept_chunks`) stay aligned with what the sweeper writes.
	gcCount := uint64(42)
	gcBytes := uint64(1 << 20)
	dry := false
	a.Record(AuditRecord{
		Event:      "gc_swept_chunks",
		TenantID:   "tenant-1",
		Count:      &gcCount,
		BytesFreed: &gcBytes,
		DryRun:     &dry,
		Allowed:    true,
	})

	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := splitLines(bytes)

	type rec struct {
		Event      string  `json:"event"`
		Path       string  `json:"path"`
		Hash       string  `json:"hash"`
		Size       *uint64 `json:"size"`
		Version    *uint64 `json:"version"`
		Mode       string  `json:"mode"`
		Reason     string  `json:"reason"`
		LeaseID    string  `json:"lease_id"`
		Count      *uint64 `json:"count"`
		BytesFreed *uint64 `json:"bytes_freed"`
		TenantID   string  `json:"tenant_id"`
		Allowed    bool    `json:"allowed"`
	}
	parsed := make([]rec, 0, len(lines))
	for _, l := range lines {
		if len(l) == 0 {
			continue
		}
		var r rec
		if err := json.Unmarshal(l, &r); err != nil {
			t.Fatalf("bad jsonl line %q: %v", string(l), err)
		}
		parsed = append(parsed, r)
	}

	byEvent := map[string]rec{}
	for _, p := range parsed {
		byEvent[p.Event] = p
	}

	if r := byEvent["chunk_get"]; r.Hash != "deadbeef" || r.Size == nil {
		t.Errorf("chunk_get shape wrong: %+v", r)
	}
	if r := byEvent["chunk_put"]; r.Hash != "cafebabe" || r.Size == nil {
		t.Errorf("chunk_put shape wrong: %+v", r)
	}
	if r := byEvent["chunk_has"]; r.Count == nil || *r.Count != 8 {
		t.Errorf("chunk_has shape wrong: %+v", r)
	}
	if r := byEvent["manifest_get"]; r.Version == nil || *r.Version != 7 || r.Path != "/x" {
		t.Errorf("manifest_get shape wrong: %+v", r)
	}
	if r := byEvent["manifest_put"]; r.Version == nil || *r.Version != 7 {
		t.Errorf("manifest_put shape wrong: %+v", r)
	}
	for _, name := range []string{"lease_grant", "lease_refresh", "lease_revoke", "lease_release", "lease_violation"} {
		r := byEvent[name]
		if r.Mode != "write" || r.LeaseID == "" {
			t.Errorf("%s missing mode/lease_id: %+v", name, r)
		}
	}
	if r := byEvent["lease_revoke"]; r.Reason != "contention" {
		t.Errorf("lease_revoke reason wrong: %+v", r)
	}
	if r := byEvent["gc_swept_chunks"]; r.Count == nil || *r.Count != 42 || r.BytesFreed == nil || *r.BytesFreed != 1<<20 || r.TenantID != "tenant-1" {
		t.Errorf("gc_swept_chunks shape wrong: %+v", r)
	}
}
