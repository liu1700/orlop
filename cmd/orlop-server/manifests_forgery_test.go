package main

import (
	"encoding/hex"
	"strings"
	"testing"
)

// TestManifestPutRejectsForgedSessionID confirms the server refuses a
// session_id that does not match the calling connection's active lease.
func TestManifestPutRejectsForgedSessionID(t *testing.T) {
	db := openTestDB(t)
	store := NewManifestStore(db, nil)

	activeLeaseHex := hex.EncodeToString([]byte("aaaaaaaaaaaaaaaa")) // 16-byte hex
	forgedSessionID := "mount:" + hex.EncodeToString([]byte("bbbbbbbbbbbbbbbb"))

	_, err := store.PutWithLeaseCheck(
		"/foo",
		0,
		Manifest{Path: "/foo", Size: 0, Mode: 0o644},
		forgedSessionID,
		"alloc_test",
		"agent_test",
		activeLeaseHex,
	)
	if err == nil {
		t.Fatal("expected EACCES on forged session_id, got nil")
	}
	if !strings.Contains(err.Error(), "session_id mismatch") {
		t.Fatalf("expected session_id mismatch error, got: %v", err)
	}
}

// TestManifestPutAcceptsValidSessionID confirms the normal path still works
// when the session_id matches the active lease's hex form.
func TestManifestPutAcceptsValidSessionID(t *testing.T) {
	db := openTestDB(t)
	store := NewManifestStore(db, nil)

	leaseHex := hex.EncodeToString([]byte("aaaaaaaaaaaaaaaa"))
	validSessionID := "mount:" + leaseHex

	if _, err := store.PutWithLeaseCheck(
		"/foo",
		0,
		Manifest{Path: "/foo", Size: 4, Mode: 0o644},
		validSessionID,
		"alloc_test",
		"agent_test",
		leaseHex,
	); err != nil {
		t.Fatalf("valid session_id rejected: %v", err)
	}
}

// TestManifestDeleteRejectsForgedSessionID confirms the same check on Delete.
func TestManifestDeleteRejectsForgedSessionID(t *testing.T) {
	db := openTestDB(t)
	store := NewManifestStore(db, nil)

	// Seed a manifest so Delete has something to operate on. Use the LeaseCheck
	// entry with a matching session_id so the seed itself is not rejected.
	leaseHex := hex.EncodeToString([]byte("aaaaaaaaaaaaaaaa"))
	validSessionID := "mount:" + leaseHex
	if _, err := store.PutWithLeaseCheck(
		"/foo", 0, Manifest{Path: "/foo", Size: 0, Mode: 0o644},
		validSessionID, "alloc_test", "agent_test", leaseHex,
	); err != nil {
		t.Fatalf("seed put failed: %v", err)
	}

	forged := "mount:" + hex.EncodeToString([]byte("bbbbbbbbbbbbbbbb"))
	err := store.DeleteWithLeaseCheck("/foo", 1, forged, "alloc_test", "agent_test", leaseHex)
	if err == nil {
		t.Fatal("expected EACCES on forged session_id during Delete, got nil")
	}
	if !strings.Contains(err.Error(), "session_id mismatch") {
		t.Fatalf("expected session_id mismatch error, got: %v", err)
	}
}

// TestManifestRenameRejectsForgedSessionID confirms the same check on Rename.
func TestManifestRenameRejectsForgedSessionID(t *testing.T) {
	db := openTestDB(t)
	store := NewManifestStore(db, nil)

	leaseHex := hex.EncodeToString([]byte("aaaaaaaaaaaaaaaa"))
	validSessionID := "mount:" + leaseHex
	if _, err := store.PutWithLeaseCheck(
		"/from", 0, Manifest{Path: "/from", Size: 0, Mode: 0o644},
		validSessionID, "alloc_test", "agent_test", leaseHex,
	); err != nil {
		t.Fatalf("seed put failed: %v", err)
	}

	forged := "mount:" + hex.EncodeToString([]byte("bbbbbbbbbbbbbbbb"))
	_, err := store.RenameWithLeaseCheck("/from", "/to", 1, 0, forged, "alloc_test", "agent_test", leaseHex)
	if err == nil {
		t.Fatal("expected EACCES on forged session_id during Rename, got nil")
	}
	if !strings.Contains(err.Error(), "session_id mismatch") {
		t.Fatalf("expected session_id mismatch error, got: %v", err)
	}
}
