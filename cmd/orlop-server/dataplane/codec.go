package dataplane

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Frame is one logical request or response on the wire.
type Frame struct {
	Op      Op
	Flags   uint8
	RID     uint64
	Payload []byte
}

// IsResponse reports whether the FlagResponse bit is set.
func (f Frame) IsResponse() bool { return f.Flags&FlagResponse != 0 }

// IsError reports whether the FlagError bit is set (only meaningful on responses).
func (f Frame) IsError() bool { return f.Flags&FlagError != 0 }

// WriteFrame serialises f to w. Returns the number of bytes written.
func WriteFrame(w io.Writer, f Frame) error {
	if uint64(len(f.Payload)) > uint64(MaxPayloadLen) {
		return fmt.Errorf("frame payload %d exceeds MaxPayloadLen %d", len(f.Payload), MaxPayloadLen)
	}
	var hdr [HeaderLen]byte
	hdr[0] = uint8(f.Op)
	hdr[1] = f.Flags
	binary.BigEndian.PutUint64(hdr[2:10], f.RID)
	// hdr[10..12] reserved, zero.
	binary.BigEndian.PutUint32(hdr[12:16], uint32(len(f.Payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(f.Payload) > 0 {
		if _, err := w.Write(f.Payload); err != nil {
			return err
		}
	}
	return nil
}

// ReadFrame parses a single frame from r. Returns io.EOF if r is closed
// cleanly between frames; io.ErrUnexpectedEOF if r closes mid-frame.
func ReadFrame(r io.Reader) (Frame, error) {
	var hdr [HeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Frame{}, err
	}
	op := Op(hdr[0])
	if !op.Valid() {
		return Frame{}, fmt.Errorf("unknown op 0x%02x", hdr[0])
	}
	flags := hdr[1]
	rid := binary.BigEndian.Uint64(hdr[2:10])
	if hdr[10] != 0 || hdr[11] != 0 {
		return Frame{}, fmt.Errorf("non-zero reserved bytes in header")
	}
	plen := binary.BigEndian.Uint32(hdr[12:16])
	if plen > MaxPayloadLen {
		return Frame{}, fmt.Errorf("frame payload %d exceeds MaxPayloadLen %d", plen, MaxPayloadLen)
	}
	var payload []byte
	if plen > 0 {
		payload = make([]byte, plen)
		if _, err := io.ReadFull(r, payload); err != nil {
			return Frame{}, err
		}
	}
	return Frame{Op: op, Flags: flags, RID: rid, Payload: payload}, nil
}
