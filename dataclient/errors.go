package dataclient

import (
	"errors"
	"fmt"

	wire "github.com/liu1700/orlop/cmd/orlop-server/dataplane"
)

// Sentinel errors returned by data-plane operations. Match them with
// errors.Is; the concrete *DataError carries the wire errno and server message,
// and CAS conflicts surface as *StaleError (which is-a ErrStale).
var (
	ErrNotFound     = errors.New("orlop: not found")           // ENOENT
	ErrExists       = errors.New("orlop: already exists")      // EEXIST
	ErrNotEmpty     = errors.New("orlop: directory not empty") // ENOTEMPTY
	ErrNotDir       = errors.New("orlop: not a directory")     // ENOTDIR
	ErrIsDir        = errors.New("orlop: is a directory")      // EISDIR
	ErrAccessDenied = errors.New("orlop: access denied")       // EACCES
	ErrStale        = errors.New("orlop: version conflict")    // ESTALE
	ErrBusy         = errors.New("orlop: resource busy")       // EBUSY
	// ErrInvalid covers EINVAL: a malformed request, an over-cap chunk, a bad
	// hash, and — notably — a quota-exceeded write. Inspect (*DataError).Message
	// to distinguish; the errno alone cannot.
	ErrInvalid = errors.New("orlop: invalid argument")
)

// DataError is a data-plane protocol error carrying the wire errno and the
// server's message. Receiving a *DataError means the request reached the server
// and was rejected at the protocol layer; the connection remains usable.
type DataError struct {
	Errno    int32
	Message  string
	sentinel error // one of the Err* sentinels, or nil
}

func (e *DataError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("orlop dataplane: %s (errno %d)", e.Message, e.Errno)
	}
	return fmt.Sprintf("orlop dataplane: errno %d", e.Errno)
}

// Unwrap exposes the matching sentinel so errors.Is(err, ErrNotFound) works.
func (e *DataError) Unwrap() error { return e.sentinel }

// StaleError is returned when a compare-and-swap write (WriteFile, Delete,
// Rename) loses to a concurrent version. It carries the server's current
// version so the caller can re-read and retry, plus a best-effort hint at who
// wrote the conflicting version. errors.Is(err, ErrStale) is true.
type StaleError struct {
	DataError
	YourVersion         uint64
	CurrentVersion      uint64
	LastWriterAgentID   string
	LastWriterSessionID string
}

func sentinelFor(errno int32) error {
	switch errno {
	case wire.ErrnoENOENT:
		return ErrNotFound
	case wire.ErrnoEEXIST:
		return ErrExists
	case wire.ErrnoENOTEMPTY:
		return ErrNotEmpty
	case wire.ErrnoENOTDIR:
		return ErrNotDir
	case wire.ErrnoEISDIR:
		return ErrIsDir
	case wire.ErrnoEACCES:
		return ErrAccessDenied
	case wire.ErrnoESTALE:
		return ErrStale
	case wire.ErrnoEBUSY:
		return ErrBusy
	case wire.ErrnoEINVAL:
		return ErrInvalid
	}
	return nil
}

// errorFromPayload maps a wire error frame to a typed Go error.
func errorFromPayload(ep wire.ErrorPayload) error {
	base := DataError{Errno: ep.Errno, Message: ep.Message, sentinel: sentinelFor(ep.Errno)}
	if ep.Errno != wire.ErrnoESTALE {
		return &base
	}
	se := &StaleError{DataError: base}
	if r := ep.Recovery; r != nil {
		if r.YourVersion != nil {
			se.YourVersion = *r.YourVersion
		}
		if r.CurrentVersion != nil {
			se.CurrentVersion = *r.CurrentVersion
		}
		if r.LastWriter != nil {
			if r.LastWriter.AgentID != nil {
				se.LastWriterAgentID = *r.LastWriter.AgentID
			}
			if r.LastWriter.SessionID != nil {
				se.LastWriterSessionID = *r.LastWriter.SessionID
			}
		}
	}
	return se
}
