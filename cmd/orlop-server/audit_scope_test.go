package main

import "testing"

// filterAuditForCaller must return only the caller's own tenant records (audit
// P1-4: the global JSONL otherwise leaks every tenant's paths/cert-subjects), and
// when the cert is agent-scoped, only that agent's records. Un-attributed /
// server-level entries (no tenant) are never exposed to an agent cert.
func TestFilterAuditForCaller(t *testing.T) {
	events := []map[string]any{
		{"event": "read", "tenant_id": "t1", "agent_id": "a1", "path": "/a1/x"},
		{"event": "read", "tenant_id": "t1", "agent_id": "a2", "path": "/a2/y"},
		{"event": "read", "tenant_id": "t2", "agent_id": "a9", "path": "/a9/z"},
		{"event": "gc_swept", "path": "/internal"}, // no tenant attribution
	}

	t.Run("tenant scope only", func(t *testing.T) {
		got := filterAuditForCaller(events, "t1", "")
		if len(got) != 2 {
			t.Fatalf("t1 records = %d, want 2", len(got))
		}
		for _, e := range got {
			if e["tenant_id"] != "t1" {
				t.Fatalf("leaked cross-tenant record: %v", e)
			}
		}
	})

	t.Run("tenant + agent scope", func(t *testing.T) {
		got := filterAuditForCaller(events, "t1", "a1")
		if len(got) != 1 || got[0]["agent_id"] != "a1" {
			t.Fatalf("a1-scoped records = %v, want exactly a1", got)
		}
	})

	t.Run("other tenant sees only its own", func(t *testing.T) {
		got := filterAuditForCaller(events, "t2", "")
		if len(got) != 1 || got[0]["tenant_id"] != "t2" {
			t.Fatalf("t2 records = %v, want exactly t2", got)
		}
	})

	t.Run("unknown tenant sees nothing", func(t *testing.T) {
		if got := filterAuditForCaller(events, "nope", ""); len(got) != 0 {
			t.Fatalf("unknown tenant leaked %d records", len(got))
		}
	})

	t.Run("un-attributed entries never leak to an agent", func(t *testing.T) {
		for _, e := range filterAuditForCaller(events, "t1", "") {
			if e["event"] == "gc_swept" {
				t.Fatal("server-level entry exposed to an agent cert")
			}
		}
	})
}
