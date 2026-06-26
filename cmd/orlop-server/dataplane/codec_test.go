package dataplane

import (
	"bytes"
	"testing"

	"github.com/vmihailenco/msgpack/v5"
)

func TestFrameRoundTrip(t *testing.T) {
	in := Frame{Op: OpStat, Flags: 0, RID: 0x1234_5678_9abc_def0, Payload: []byte("hello")}
	var buf bytes.Buffer
	if err := WriteFrame(&buf, in); err != nil {
		t.Fatalf("write: %v", err)
	}
	if buf.Len() != HeaderLen+5 {
		t.Fatalf("len=%d want %d", buf.Len(), HeaderLen+5)
	}
	out, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if out.Op != OpStat || out.Flags != 0 || out.RID != in.RID {
		t.Fatalf("header mismatch: %+v", out)
	}
	if !bytes.Equal(out.Payload, in.Payload) {
		t.Fatalf("payload mismatch")
	}
}

func TestResponseFlags(t *testing.T) {
	in := Frame{Op: OpStat, Flags: FlagResponse | FlagError, RID: 7, Payload: []byte("nope")}
	var buf bytes.Buffer
	if err := WriteFrame(&buf, in); err != nil {
		t.Fatalf("write: %v", err)
	}
	out, _ := ReadFrame(&buf)
	if !out.IsResponse() || !out.IsError() {
		t.Fatalf("flags lost: %+v", out)
	}
}

func TestEmptyPayload(t *testing.T) {
	in := Frame{Op: OpPing, RID: 1}
	var buf bytes.Buffer
	if err := WriteFrame(&buf, in); err != nil {
		t.Fatalf("write: %v", err)
	}
	if buf.Len() != HeaderLen {
		t.Fatalf("len=%d want %d", buf.Len(), HeaderLen)
	}
	out, _ := ReadFrame(&buf)
	if len(out.Payload) != 0 {
		t.Fatalf("payload not empty: %v", out.Payload)
	}
}

func TestRejectsUnknownOp(t *testing.T) {
	hdr := make([]byte, HeaderLen)
	hdr[0] = 0xff
	if _, err := ReadFrame(bytes.NewReader(hdr)); err == nil {
		t.Fatal("expected error for unknown op")
	}
}

func TestRejectsNonZeroReserved(t *testing.T) {
	hdr := make([]byte, HeaderLen)
	hdr[0] = byte(OpPing)
	hdr[10] = 1
	if _, err := ReadFrame(bytes.NewReader(hdr)); err == nil {
		t.Fatal("expected error for reserved bytes")
	}
}

func TestMessagesEncodeWithFieldNames(t *testing.T) {
	resp := ListResponse{Entries: []EntryWire{
		{Name: "a", Kind: "file", Size: 7},
		{Name: "b", Kind: "dir", Size: 0},
	}}
	encoded, err := msgpack.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded ListResponse
	if err := msgpack.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Entries[0].Name != "a" || decoded.Entries[1].Kind != "dir" {
		t.Fatalf("decode mismatch: %+v", decoded)
	}
}

func TestNewOpsValid(t *testing.T) {
	for _, op := range []Op{OpLeaseGrant, OpLeaseRefresh, OpLeaseRelease, OpLeaseRevoke} {
		if !op.Valid() {
			t.Fatalf("op %s should be valid", op)
		}
	}
	if ErrnoEBUSY != 16 {
		t.Fatalf("EBUSY=%d want 16", ErrnoEBUSY)
	}
}

func TestLeaseMessagesRoundTrip(t *testing.T) {
	in := LeaseGrantResponse{
		LeaseID:         bytes.Repeat([]byte{7}, 16),
		ExpiresAtUnixMs: 1_700_000_000_000,
		ModeGranted:     LeaseExclusiveWrite,
	}
	enc, err := msgpack.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out LeaseGrantResponse
	if err := msgpack.Unmarshal(enc, &out); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(in.LeaseID, out.LeaseID) || in.ExpiresAtUnixMs != out.ExpiresAtUnixMs {
		t.Fatalf("round trip: got %+v want %+v", out, in)
	}
}

// Issue #103: ErrorPayload may carry an optional structured RecoveryHint.
// The wire field is omitted when nil so old Rust clients ignore it.
func TestErrorPayloadRecoveryHintRoundTrip(t *testing.T) {
	yourV := uint64(5)
	currV := uint64(7)
	hint := &RecoveryHint{
		Kind:            RecoveryKindCasConflict,
		YourVersion:     &yourV,
		CurrentVersion:  &currV,
		SuggestedAction: "re-put with expected=7",
	}
	in := ErrESTALE("manifest version conflict").WithRecovery(hint)
	enc, err := msgpack.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out ErrorPayload
	if err := msgpack.Unmarshal(enc, &out); err != nil {
		t.Fatal(err)
	}
	if out.Errno != ErrnoESTALE {
		t.Fatalf("errno = %d, want %d", out.Errno, ErrnoESTALE)
	}
	if out.Recovery == nil {
		t.Fatalf("recovery hint must round-trip")
	}
	if out.Recovery.Kind != RecoveryKindCasConflict {
		t.Fatalf("kind = %q, want %q", out.Recovery.Kind, RecoveryKindCasConflict)
	}
	if out.Recovery.CurrentVersion == nil || *out.Recovery.CurrentVersion != 7 {
		t.Fatalf("current_version = %v, want 7", out.Recovery.CurrentVersion)
	}
	if out.Recovery.YourVersion == nil || *out.Recovery.YourVersion != 5 {
		t.Fatalf("your_version = %v, want 5", out.Recovery.YourVersion)
	}
}

// An ErrorPayload without recovery must encode to the same bytes a legacy
// (recovery-less) server would emit — i.e. the field is omitted, not encoded
// as msgpack-nil.
func TestErrorPayloadWithoutRecoveryOmitsField(t *testing.T) {
	in := ErrENOENT("missing")
	enc, err := msgpack.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	// Decode into a generic map to confirm the `recovery` key is absent on
	// the wire (rather than serialized as a nil pointer).
	var generic map[string]any
	if err := msgpack.Unmarshal(enc, &generic); err != nil {
		t.Fatal(err)
	}
	if _, present := generic["recovery"]; present {
		t.Fatalf("recovery key must be omitted when nil; got map %v", generic)
	}
}
