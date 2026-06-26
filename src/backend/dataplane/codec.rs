//! Frame encode/decode for the data-plane binary protocol.

use std::io::{self, Read, Write};

use anyhow::{anyhow, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::protocol::{flags, Op, HEADER_LEN, MAX_PAYLOAD_LEN};

#[derive(Debug, Clone)]
pub struct Frame {
    pub op: Op,
    pub flags: u8,
    pub rid: u64,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn request(op: Op, rid: u64, payload: Vec<u8>) -> Self {
        Self {
            op,
            flags: 0,
            rid,
            payload,
        }
    }

    pub fn response(op: Op, rid: u64, payload: Vec<u8>) -> Self {
        Self {
            op,
            flags: flags::RESPONSE,
            rid,
            payload,
        }
    }

    pub fn error_response(op: Op, rid: u64, payload: Vec<u8>) -> Self {
        Self {
            op,
            flags: flags::RESPONSE | flags::ERROR,
            rid,
            payload,
        }
    }

    pub fn is_response(&self) -> bool {
        self.flags & flags::RESPONSE != 0
    }

    pub fn is_error(&self) -> bool {
        self.flags & flags::ERROR != 0
    }
}

pub fn write_frame<W: Write>(w: &mut W, f: &Frame) -> Result<()> {
    let len = u32::try_from(f.payload.len())
        .map_err(|_| anyhow!("frame payload too large: {} bytes", f.payload.len()))?;
    if len > MAX_PAYLOAD_LEN {
        return Err(anyhow!(
            "frame payload {} exceeds MAX_PAYLOAD_LEN {}",
            len,
            MAX_PAYLOAD_LEN
        ));
    }
    let mut header = [0u8; HEADER_LEN];
    header[0] = f.op as u8;
    header[1] = f.flags;
    header[2..10].copy_from_slice(&f.rid.to_be_bytes());
    // header[10..12] reserved, zero.
    header[12..16].copy_from_slice(&len.to_be_bytes());
    w.write_all(&header)?;
    if !f.payload.is_empty() {
        w.write_all(&f.payload)?;
    }
    Ok(())
}

pub fn read_frame<R: Read>(r: &mut R) -> Result<Frame> {
    let mut header = [0u8; HEADER_LEN];
    read_exact_eof(r, &mut header)?;
    let op = Op::from_u8(header[0]).ok_or_else(|| anyhow!("unknown op 0x{:02x}", header[0]))?;
    let flag_bits = header[1];
    let rid = u64::from_be_bytes(header[2..10].try_into().unwrap());
    if header[10] != 0 || header[11] != 0 {
        return Err(anyhow!("non-zero reserved bytes in header"));
    }
    let len = u32::from_be_bytes(header[12..16].try_into().unwrap());
    if len > MAX_PAYLOAD_LEN {
        return Err(anyhow!(
            "frame payload {} exceeds MAX_PAYLOAD_LEN {}",
            len,
            MAX_PAYLOAD_LEN
        ));
    }
    let mut payload = vec![0u8; len as usize];
    if len > 0 {
        read_exact_eof(r, &mut payload)?;
    }
    Ok(Frame {
        op,
        flags: flag_bits,
        rid,
        payload,
    })
}

fn read_exact_eof<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<()> {
    match r.read_exact(buf) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
            Err(anyhow!("connection closed mid-frame"))
        }
        Err(e) => Err(e.into()),
    }
}

pub async fn write_frame_async<W: AsyncWrite + Unpin>(w: &mut W, f: &Frame) -> Result<()> {
    let len = u32::try_from(f.payload.len())
        .map_err(|_| anyhow!("frame payload too large: {} bytes", f.payload.len()))?;
    if len > MAX_PAYLOAD_LEN {
        return Err(anyhow!(
            "frame payload {} exceeds MAX_PAYLOAD_LEN {}",
            len,
            MAX_PAYLOAD_LEN
        ));
    }
    let mut header = [0u8; HEADER_LEN];
    header[0] = f.op as u8;
    header[1] = f.flags;
    header[2..10].copy_from_slice(&f.rid.to_be_bytes());
    header[12..16].copy_from_slice(&len.to_be_bytes());
    w.write_all(&header).await?;
    if !f.payload.is_empty() {
        w.write_all(&f.payload).await?;
    }
    Ok(())
}

pub async fn read_frame_async<R: AsyncRead + Unpin>(r: &mut R) -> Result<Frame> {
    let mut header = [0u8; HEADER_LEN];
    r.read_exact(&mut header).await?;
    let op = Op::from_u8(header[0]).ok_or_else(|| anyhow!("unknown op 0x{:02x}", header[0]))?;
    let flag_bits = header[1];
    let rid = u64::from_be_bytes(header[2..10].try_into().unwrap());
    if header[10] != 0 || header[11] != 0 {
        return Err(anyhow!("non-zero reserved bytes in header"));
    }
    let len = u32::from_be_bytes(header[12..16].try_into().unwrap());
    if len > MAX_PAYLOAD_LEN {
        return Err(anyhow!(
            "frame payload {} exceeds MAX_PAYLOAD_LEN {}",
            len,
            MAX_PAYLOAD_LEN
        ));
    }
    let mut payload = vec![0u8; len as usize];
    if len > 0 {
        r.read_exact(&mut payload).await?;
    }
    Ok(Frame {
        op,
        flags: flag_bits,
        rid,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_request() {
        let f = Frame::request(Op::Stat, 0x1234_5678_9abc_def0, b"hello".to_vec());
        let mut buf = Vec::new();
        write_frame(&mut buf, &f).unwrap();
        assert_eq!(buf.len(), HEADER_LEN + 5);
        let parsed = read_frame(&mut buf.as_slice()).unwrap();
        assert_eq!(parsed.op, Op::Stat);
        assert_eq!(parsed.flags, 0);
        assert_eq!(parsed.rid, 0x1234_5678_9abc_def0);
        assert_eq!(parsed.payload, b"hello");
    }

    #[test]
    fn round_trip_response_with_error_flag() {
        let f = Frame::error_response(Op::Stat, 7, b"nope".to_vec());
        let mut buf = Vec::new();
        write_frame(&mut buf, &f).unwrap();
        let parsed = read_frame(&mut buf.as_slice()).unwrap();
        assert!(parsed.is_response());
        assert!(parsed.is_error());
    }

    #[test]
    fn empty_payload_round_trips() {
        let f = Frame::request(Op::Ping, 1, Vec::new());
        let mut buf = Vec::new();
        write_frame(&mut buf, &f).unwrap();
        assert_eq!(buf.len(), HEADER_LEN);
        let parsed = read_frame(&mut buf.as_slice()).unwrap();
        assert_eq!(parsed.payload.len(), 0);
    }

    #[test]
    fn rejects_non_zero_reserved() {
        let mut buf = vec![0u8; HEADER_LEN];
        buf[0] = Op::Ping as u8;
        buf[10] = 1;
        let err = read_frame(&mut buf.as_slice()).unwrap_err();
        assert!(err.to_string().contains("reserved"));
    }

    #[test]
    fn rejects_oversize_payload_on_write() {
        let f = Frame::request(Op::Stat, 1, vec![0; (MAX_PAYLOAD_LEN + 1) as usize]);
        let err = write_frame(&mut Vec::new(), &f).unwrap_err();
        assert!(err.to_string().contains("MAX_PAYLOAD_LEN"));
    }

    #[test]
    fn rejects_unknown_op() {
        let mut buf = vec![0u8; HEADER_LEN];
        buf[0] = 0xff;
        let err = read_frame(&mut buf.as_slice()).unwrap_err();
        assert!(err.to_string().contains("unknown op"));
    }
}
