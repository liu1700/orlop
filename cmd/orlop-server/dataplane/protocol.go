// Package dataplane implements the data-plane binary-framed protocol for orlop-server.
//
// Companion client: src/backend/dataplane/ in the Rust crate. Frame layout,
// op codes, and msgpack message shapes are mirrored on both sides; keep them
// in sync. See docs/design-data-plane.md Layer 2.
package dataplane

const (
	// HeaderLen is the wire size of every frame header.
	HeaderLen = 16

	// MaxPayloadLen caps a single frame's payload (64 MiB). Server and client
	// both reject larger frames. Layer 3 (chunks) moves large reads off this
	// path entirely.
	MaxPayloadLen uint32 = 64 * 1024 * 1024
)

// Op identifies the request kind. Same value identifies the response;
// the response is distinguished by FlagResponse on the flags byte.
type Op uint8

const (
	OpList              Op = 0x01
	OpStat              Op = 0x02
	OpPing              Op = 0x04
	OpClose             Op = 0x05
	OpManifestGet       Op = 0x06
	OpManifestPut       Op = 0x07
	OpChunkGet          Op = 0x08
	OpChunkHas          Op = 0x09
	OpChunkPut          Op = 0x0A
	OpManifestDelete    Op = 0x0B
	OpManifestRename    Op = 0x0C
	OpDirCreate         Op = 0x0D
	OpDirRemove         Op = 0x0E
	OpSetattr           Op = 0x0F
	OpLeaseGrant        Op = 0x10
	OpLeaseRefresh      Op = 0x11
	OpLeaseRelease      Op = 0x12
	OpLeaseRevoke       Op = 0x13
	OpJournalQuery      Op = 0x15
	OpSymlink           Op = 0x16
	OpReadlink          Op = 0x17
	OpJournalRevertPath Op = 0x18
	OpMknod             Op = 0x19
)

// String returns the canonical name for log lines.
func (o Op) String() string {
	switch o {
	case OpList:
		return "LIST"
	case OpStat:
		return "STAT"
	case OpPing:
		return "PING"
	case OpClose:
		return "CLOSE"
	case OpManifestGet:
		return "MANIFEST_GET"
	case OpManifestPut:
		return "MANIFEST_PUT"
	case OpChunkGet:
		return "CHUNK_GET"
	case OpChunkHas:
		return "CHUNK_HAS"
	case OpChunkPut:
		return "CHUNK_PUT"
	case OpManifestDelete:
		return "MANIFEST_DELETE"
	case OpManifestRename:
		return "MANIFEST_RENAME"
	case OpDirCreate:
		return "DIR_CREATE"
	case OpDirRemove:
		return "DIR_REMOVE"
	case OpSetattr:
		return "SETATTR"
	case OpSymlink:
		return "SYMLINK"
	case OpReadlink:
		return "READLINK"
	case OpMknod:
		return "MKNOD"
	case OpLeaseGrant:
		return "LEASE_GRANT"
	case OpLeaseRefresh:
		return "LEASE_REFRESH"
	case OpLeaseRelease:
		return "LEASE_RELEASE"
	case OpLeaseRevoke:
		return "LEASE_REVOKE"
	case OpJournalQuery:
		return "JOURNAL_QUERY"
	case OpJournalRevertPath:
		return "JOURNAL_REVERT_PATH"
	default:
		return "UNKNOWN"
	}
}

// Valid reports whether the op code is one we recognise.
func (o Op) Valid() bool {
	switch o {
	case OpList, OpStat, OpPing, OpClose,
		OpManifestGet, OpManifestPut, OpChunkGet, OpChunkHas, OpChunkPut,
		OpManifestDelete, OpManifestRename, OpDirCreate, OpDirRemove,
		OpSetattr, OpSymlink, OpReadlink, OpMknod,
		OpLeaseGrant, OpLeaseRefresh, OpLeaseRelease, OpLeaseRevoke,
		OpJournalQuery, OpJournalRevertPath:
		return true
	}
	return false
}

// Flag bits for the second header byte.
const (
	FlagResponse uint8 = 0b0000_0001
	FlagError    uint8 = 0b0000_0010
)

// Errno wire codes. Mirror libc errnos so the FUSE layer translates directly.
// Defined here (not pulling in syscall) so values match across platforms.
const (
	ErrnoEIO       int32 = 5
	ErrnoEACCES    int32 = 13
	ErrnoENOENT    int32 = 2
	ErrnoEINVAL    int32 = 22
	ErrnoEROFS     int32 = 30
	ErrnoEEXIST    int32 = 17
	ErrnoEXDEV     int32 = 18
	ErrnoENOTDIR   int32 = 20
	ErrnoEISDIR    int32 = 21
	ErrnoENOTEMPTY int32 = 39
	ErrnoESTALE    int32 = 116
	ErrnoEBUSY     int32 = 16
)
