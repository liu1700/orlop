//! data-plane wire protocol — frame header, op codes, flags.
//!
//! Frame layout:
//!
//! ```text
//! +--------+--------+----------+----------+----------+
//! | op (1) | flags  |  rid (8) | rsv (2)  | len (4)  |  payload (len bytes)
//! +--------+--------+----------+----------+----------+
//! ```
//!
//! Multi-byte fields are big-endian. `rsv` is reserved (must be zero).
//! `len` is the size of the payload in bytes (max 64 MiB to bound memory).

pub const HEADER_LEN: usize = 16;

/// Cap on per-frame payload size (server and client both reject larger).
/// 64 MiB — comfortably above whole-file READ responses we'll ship over the data plane.
/// Layer 3 (chunks) will move large reads off this path entirely.
pub const MAX_PAYLOAD_LEN: u32 = 64 * 1024 * 1024;

/// Op code byte. Same value identifies the request and its response;
/// the response is distinguished by `Flags::RESPONSE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Op {
    List = 0x01,
    Stat = 0x02,
    Ping = 0x04,
    Close = 0x05,
    ManifestGet = 0x06,
    ManifestPut = 0x07,
    ChunkGet = 0x08,
    ChunkHas = 0x09,
    ChunkPut = 0x0A,
    ManifestDelete = 0x0B,
    ManifestRename = 0x0C,
    DirCreate = 0x0D,
    DirRemove = 0x0E,
    Setattr = 0x0F,
    LeaseGrant = 0x10,
    LeaseRefresh = 0x11,
    LeaseRelease = 0x12,
    LeaseRevoke = 0x13,
    JournalQuery = 0x15,
    Symlink = 0x16,
    Readlink = 0x17,
    JournalRevertPath = 0x18,
    Mknod = 0x19,
}

impl Op {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Op::List),
            0x02 => Some(Op::Stat),
            0x04 => Some(Op::Ping),
            0x05 => Some(Op::Close),
            0x06 => Some(Op::ManifestGet),
            0x07 => Some(Op::ManifestPut),
            0x08 => Some(Op::ChunkGet),
            0x09 => Some(Op::ChunkHas),
            0x0A => Some(Op::ChunkPut),
            0x0B => Some(Op::ManifestDelete),
            0x0C => Some(Op::ManifestRename),
            0x0D => Some(Op::DirCreate),
            0x0E => Some(Op::DirRemove),
            0x0F => Some(Op::Setattr),
            0x10 => Some(Op::LeaseGrant),
            0x11 => Some(Op::LeaseRefresh),
            0x12 => Some(Op::LeaseRelease),
            0x13 => Some(Op::LeaseRevoke),
            0x15 => Some(Op::JournalQuery),
            0x16 => Some(Op::Symlink),
            0x17 => Some(Op::Readlink),
            0x18 => Some(Op::JournalRevertPath),
            0x19 => Some(Op::Mknod),
            _ => None,
        }
    }
}

/// Flag bits in the header.
pub mod flags {
    /// Set on responses; clear on requests.
    pub const RESPONSE: u8 = 0b0000_0001;
    /// Set on responses that carry an error payload (`messages::ErrorPayload`).
    pub const ERROR: u8 = 0b0000_0010;
}

/// Errno-shaped error wire codes. Mirror libc errnos so the FUSE layer can
/// translate directly. We define our own constants to avoid a libc dependency
/// in the message types and so the Go side has identical numeric values.
pub mod errno {
    pub const EIO: i32 = 5;
    pub const EACCES: i32 = 13;
    pub const ENOENT: i32 = 2;
    pub const EINVAL: i32 = 22;
    pub const EROFS: i32 = 30;
    /// Stale file handle / stale version on MANIFEST_PUT CAS conflict.
    pub const ESTALE: i32 = 116;
    pub const EEXIST: i32 = 17;
    pub const EXDEV: i32 = 18;
    pub const ENOTDIR: i32 = 20;
    pub const EISDIR: i32 = 21;
    pub const ENOTEMPTY: i32 = 39;
    pub const EBUSY: i32 = 16;
    /// Custom: stale or unknown lease id (maps to EINVAL on the FUSE layer).
    pub const LEASE_UNKNOWN: i32 = 100;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn op_round_trips() {
        for &op in &[
            Op::List,
            Op::Stat,
            Op::Ping,
            Op::Close,
            Op::ManifestGet,
            Op::ManifestPut,
            Op::ChunkGet,
            Op::ChunkHas,
            Op::ChunkPut,
            Op::ManifestDelete,
            Op::ManifestRename,
            Op::DirCreate,
            Op::DirRemove,
            Op::Setattr,
            Op::LeaseGrant,
            Op::LeaseRefresh,
            Op::LeaseRelease,
            Op::LeaseRevoke,
            Op::JournalQuery,
            Op::Symlink,
            Op::Readlink,
            Op::JournalRevertPath,
            Op::Mknod,
        ] {
            assert_eq!(Op::from_u8(op as u8), Some(op));
        }
    }

    #[test]
    fn ebusy_errno_value() {
        assert_eq!(errno::EBUSY, 16);
    }

    #[test]
    fn unknown_op_is_none() {
        assert_eq!(Op::from_u8(0x00), None);
        assert_eq!(Op::from_u8(0x42), None);
    }
}
