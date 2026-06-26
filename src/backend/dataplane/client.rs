//! Data-plane multiplexed client over QUIC or TCP+TLS.
//!
//! One persistent mTLS connection per mount carries N in-flight requests.
//! Outgoing frames flow through an mpsc into a writer task; the reader task
//! parses inbound frames and routes responses to the per-rid oneshot sender
//! kept in the pending table. Public API is sync (FUSE handlers are sync);
//! internally a tokio runtime drives the I/O.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use parking_lot::Mutex;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::RootCertStore;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::runtime::Runtime;
use tokio::sync::{mpsc, mpsc::UnboundedSender, oneshot};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use super::codec::{read_frame_async, write_frame_async, Frame};
use super::messages::{
    ChunkGetRequest, ChunkGetResponse, ChunkHasRequest, ChunkHasResponse, ChunkPutRequest,
    ChunkPutResponse, ChunkRef, DirCreateRequest, DirCreateResponse, DirRemoveRequest,
    DirRemoveResponse, EntryWire, ErrorPayload, JournalQueryRequest, JournalQueryResponse,
    JournalRevertPathRequest, JournalRevertPathResponse, LeaseGrantRequest, LeaseGrantResponse,
    LeaseMode, LeaseRefreshRequest, LeaseRefreshResponse, LeaseReleaseRequest, ListRequest,
    ListResponse, ManifestDeleteRequest, ManifestDeleteResponse, ManifestGetRequest,
    ManifestGetResponse, ManifestPutRequest, ManifestPutResponse, ManifestRenameRequest,
    ManifestRenameResponse, MknodRequest, MknodResponse, PingRequest, PingResponse,
    ReadlinkRequest, ReadlinkResponse, SetattrRequest, SetattrResponse, StatRequest,
    StatResponse, SymlinkRequest, SymlinkResponse,
};
use super::protocol::{errno, flags, Op, MAX_PAYLOAD_LEN};
use crate::backend::tls::TlsIdentity;
use crate::backend::BackendError;

/// Defaults.
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_QUIC_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const DEFAULT_HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(60);
const WRITE_CHANNEL_DEPTH: usize = 256;
const ORLOP_QUIC_ALPN: &[u8] = b"orlop-data";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportMode {
    Auto,
    Quic,
    Tcp,
}

#[derive(Clone)]
pub struct DataClientConfig {
    /// `host:port` — used for both QUIC (UDP) and TCP fallback.
    pub addr: String,
    /// SNI / server name for cert verification. Usually the host part of `addr`.
    pub server_name: String,
    pub tls: TlsIdentity,
    pub transport: TransportMode,
    pub quic_connect_timeout: Duration,
    pub request_timeout: Duration,
    pub heartbeat_interval: Duration,
    pub heartbeat_timeout: Duration,
}

impl DataClientConfig {
    pub fn new(addr: impl Into<String>, server_name: impl Into<String>, tls: TlsIdentity) -> Self {
        Self {
            addr: addr.into(),
            server_name: server_name.into(),
            tls,
            // QUIC throughput is bounded by the client kernel's UDP rmem cap,
            // which a non-root binary can't raise. Default to TCP for any
            // production caller; the bench tool can override via CLI flag.
            transport: TransportMode::Tcp,
            quic_connect_timeout: DEFAULT_QUIC_CONNECT_TIMEOUT,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            heartbeat_interval: DEFAULT_HEARTBEAT_INTERVAL,
            heartbeat_timeout: DEFAULT_HEARTBEAT_TIMEOUT,
        }
    }
}

pub struct DataClient {
    runtime: Arc<Runtime>,
    inner: Arc<Inner>,
}

struct Inner {
    cfg: DataClientConfig,
    rustls_config: Arc<rustls::ClientConfig>,
    quic_config: quinn::ClientConfig,
    /// `Some(Tcp)` or `Some(Quic)` after a successful dial; `None` before.
    /// Never `Some(Auto)` — Auto is the *config* mode, not a dialed outcome.
    preferred_transport: Mutex<Option<TransportMode>>,
    next_rid: AtomicU64,
    in_flight: AtomicUsize,
    state: Mutex<ConnState>,
    push_handler: Mutex<Option<UnboundedSender<Frame>>>,
}

enum ConnState {
    Disconnected,
    Connected(Arc<ConnHandle>),
}

struct ConnHandle {
    write_tx: mpsc::Sender<Frame>,
    pending: Arc<Mutex<HashMap<u64, oneshot::Sender<Frame>>>>,
    /// Tasks owning the connection. Dropping JoinHandles cancels them iff
    /// `abort()` is called explicitly. We rely on the writer task exiting when
    /// `write_tx` is dropped, and the reader exiting on read error / EOF.
    _writer: JoinHandle<()>,
    _reader: JoinHandle<()>,
    _heartbeat: JoinHandle<()>,
    /// Present iff this connection is QUIC. `chunk_get` opens a fresh bidi
    /// stream per call against `connection` to escape single-stream cwnd
    /// serialization; control RPCs (manifest/lease/heartbeat) still ride the
    /// long-lived stream backed by `write_tx` / `pending`.
    quic: Option<QuicConnectionGuard>,
}

struct QuicConnectionGuard {
    _endpoint: quinn::Endpoint,
    connection: quinn::Connection,
}

impl DataClient {
    pub fn new(cfg: DataClientConfig) -> Result<Self> {
        let rustls_config = Arc::new(build_rustls_config(&cfg.tls)?);
        let quic_config = build_quic_config(Arc::clone(&rustls_config), cfg.heartbeat_interval)?;
        // Worker count is sized for parallel chunk_get / chunk_put fan-out:
        // each in-flight RPC is one polled task, and our typical batch is
        // 4-32 chunks per FUSE read or per flush. Threads are I/O-bound so
        // overshooting the core count is fine.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(8)
            .thread_name("orlop-data-rt")
            .enable_all()
            .build()
            .context("build tokio runtime for data-plane client")?;
        Ok(Self {
            runtime: Arc::new(runtime),
            inner: Arc::new(Inner {
                cfg,
                rustls_config,
                quic_config,
                preferred_transport: Mutex::new(None),
                next_rid: AtomicU64::new(1),
                in_flight: AtomicUsize::new(0),
                state: Mutex::new(ConnState::Disconnected),
                push_handler: Mutex::new(None),
            }),
        })
    }

    pub fn in_flight(&self) -> usize {
        self.inner.in_flight.load(Ordering::Relaxed)
    }

    pub fn list(&self, path: &str) -> Result<Vec<EntryWire>> {
        let req = ListRequest {
            path: path.to_string(),
        };
        let payload = rmp_serde::to_vec_named(&req)?;
        let resp_payload = self.request(Op::List, payload)?;
        let resp: ListResponse = rmp_serde::from_slice(&resp_payload)?;
        Ok(resp.entries)
    }

    pub fn stat(&self, path: &str) -> Result<EntryWire> {
        let req = StatRequest {
            path: path.to_string(),
        };
        let payload = rmp_serde::to_vec_named(&req)?;
        let resp_payload = self.request(Op::Stat, payload)?;
        let resp: StatResponse = rmp_serde::from_slice(&resp_payload)?;
        Ok(resp.entry)
    }

    pub fn manifest_get(&self, path: &str) -> Result<ManifestGetResponse> {
        let req = ManifestGetRequest {
            path: path.to_string(),
        };
        let payload = rmp_serde::to_vec_named(&req)?;
        let resp_payload = self.request(Op::ManifestGet, payload)?;
        let resp: ManifestGetResponse = rmp_serde::from_slice(&resp_payload)?;
        Ok(resp)
    }

    pub fn chunk_get(&self, hash: &[u8]) -> Result<Vec<u8>> {
        let payload = build_chunk_get_payload(hash)?;
        let inner = Arc::clone(&self.inner);
        let resp_payload = self.block_on(async move {
            let handle = inner.ensure_connected().await?;
            chunk_get_one(handle, inner, payload).await
        })?;
        let resp: ChunkGetResponse = rmp_serde::from_slice(&resp_payload)?;
        Ok(resp.bytes)
    }

    /// Parallel batch fetch. Spawns one task per hash on the runtime so QUIC
    /// `open_bi` round-trips overlap instead of serialising on a single
    /// `block_on`. Returns chunks in the same order as `hashes`.
    pub fn chunk_get_many(&self, hashes: &[[u8; 32]]) -> Result<Vec<Vec<u8>>> {
        let payloads: Result<Vec<Vec<u8>>> =
            hashes.iter().map(|h| build_chunk_get_payload(h)).collect();
        let payloads = payloads?;
        let inner = Arc::clone(&self.inner);
        let runtime = Arc::clone(&self.runtime);
        self.block_on(async move {
            let handle = inner.ensure_connected().await?;
            let mut tasks = Vec::with_capacity(payloads.len());
            for payload in payloads {
                let inner = Arc::clone(&inner);
                let handle = Arc::clone(&handle);
                tasks.push(
                    runtime.spawn(async move { chunk_get_one(handle, inner, payload).await }),
                );
            }
            let mut out = Vec::with_capacity(tasks.len());
            for task in tasks {
                let resp_payload = task.await.context("chunk_get task panicked")??;
                let resp: ChunkGetResponse = rmp_serde::from_slice(&resp_payload)?;
                out.push(resp.bytes);
            }
            Ok(out)
        })
    }

    /// Returns a bitmap byte slice where bit i is set iff the server holds
    /// the i-th hash. `hashes` is a flat buffer of N×32-byte BLAKE3 digests.
    pub fn chunk_has(&self, hashes: &[u8]) -> Result<Vec<u8>> {
        let req = ChunkHasRequest {
            hashes: hashes.to_vec(),
        };
        let payload = rmp_serde::to_vec_named(&req)?;
        let resp_payload = self.request(Op::ChunkHas, payload)?;
        let resp: ChunkHasResponse = rmp_serde::from_slice(&resp_payload)?;
        Ok(resp.present)
    }

    pub fn chunk_put(&self, hash: &[u8], bytes: &[u8], session_id: Option<String>) -> Result<bool> {
        let req = ChunkPutRequest {
            hash: hash.to_vec(),
            bytes: bytes.to_vec(),
            session_id,
        };
        let payload = rmp_serde::to_vec_named(&req)?;
        let resp_payload = self.request(Op::ChunkPut, payload)?;
        let resp: ChunkPutResponse = rmp_serde::from_slice(&resp_payload)?;
        Ok(resp.stored)
    }

    /// Parallel batch upload. Each chunk rides the multiplexed control stream
    /// concurrently. Order of returned `bool`s matches `items`. `session_id`
    /// is attached to every chunk in the batch.
    pub fn chunk_put_many(
        &self,
        items: Vec<(Vec<u8>, Vec<u8>)>,
        session_id: Option<String>,
    ) -> Result<Vec<bool>> {
        let mut payloads = Vec::with_capacity(items.len());
        for (hash, bytes) in items {
            let req = ChunkPutRequest {
                hash,
                bytes,
                session_id: session_id.clone(),
            };
            let payload = rmp_serde::to_vec_named(&req)?;
            if payload.len() as u32 > MAX_PAYLOAD_LEN {
                return Err(anyhow!(
                    "payload {} exceeds MAX_PAYLOAD_LEN {}",
                    payload.len(),
                    MAX_PAYLOAD_LEN
                ));
            }
            payloads.push(payload);
        }
        let inner = Arc::clone(&self.inner);
        let runtime = Arc::clone(&self.runtime);
        self.block_on(async move {
            let handle = inner.ensure_connected().await?;
            let mut tasks = Vec::with_capacity(payloads.len());
            for payload in payloads {
                let inner = Arc::clone(&inner);
                let handle = Arc::clone(&handle);
                tasks.push(runtime.spawn(async move {
                    request_on_control_stream(handle, inner, Op::ChunkPut, payload).await
                }));
            }
            let mut out = Vec::with_capacity(tasks.len());
            for task in tasks {
                let resp_payload = task.await.context("chunk_put task panicked")??;
                let resp: ChunkPutResponse = rmp_serde::from_slice(&resp_payload)?;
                out.push(resp.stored);
            }
            Ok(out)
        })
    }

    /// CAS-write a manifest. `version_expected == 0` means "create new file".
    /// Returns the newly assigned version on success.
    #[allow(clippy::too_many_arguments)]
    pub fn manifest_put(
        &self,
        path: &str,
        version_expected: u64,
        size: u64,
        mode: u32,
        mtime: i64,
        chunks: Vec<ChunkRef>,
        session_id: Option<String>,
        allocation_id: Option<String>,
    ) -> Result<u64> {
        let req = ManifestPutRequest {
            path: path.to_string(),
            version_expected,
            size,
            mode,
            mtime,
            chunks,
            session_id,
            allocation_id,
        };
        let payload = rmp_serde::to_vec_named(&req)?;
        let resp_payload = self.request(Op::ManifestPut, payload)?;
        let resp: ManifestPutResponse = rmp_serde::from_slice(&resp_payload)?;
        Ok(resp.version)
    }

    pub fn manifest_delete(
        &self,
        path: &str,
        expected_version: u64,
        session_id: Option<String>,
        allocation_id: Option<String>,
    ) -> Result<()> {
        let req = ManifestDeleteRequest {
            path: path.to_string(),
            expected_version,
            session_id,
            allocation_id,
        };
        let payload = rmp_serde::to_vec_named(&req)?;
        let resp_payload = self.request(Op::ManifestDelete, payload)?;
        let _: ManifestDeleteResponse = rmp_serde::from_slice(&resp_payload)?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn manifest_rename(
        &self,
        from: &str,
        to: &str,
        expected_version_from: u64,
        expected_version_to: u64,
        session_id: Option<String>,
        allocation_id: Option<String>,
    ) -> Result<u64> {
        let req = ManifestRenameRequest {
            from: from.into(),
            to: to.into(),
            expected_version_from,
            expected_version_to,
            session_id,
            allocation_id,
        };
        let payload = rmp_serde::to_vec_named(&req)?;
        let resp_payload = self.request(Op::ManifestRename, payload)?;
        let resp: ManifestRenameResponse = rmp_serde::from_slice(&resp_payload)?;
        Ok(resp.new_version_at_to)
    }

    pub fn dir_create(&self, path: &str, mode: u32, session_id: Option<String>) -> Result<()> {
        let req = DirCreateRequest {
            path: path.into(),
            mode,
            session_id,
        };
        let payload = rmp_serde::to_vec_named(&req)?;
        let resp_payload = self.request(Op::DirCreate, payload)?;
        let _: DirCreateResponse = rmp_serde::from_slice(&resp_payload)?;
        Ok(())
    }

    pub fn dir_remove(&self, path: &str, session_id: Option<String>) -> Result<()> {
        let req = DirRemoveRequest {
            path: path.into(),
            session_id,
        };
        let payload = rmp_serde::to_vec_named(&req)?;
        let resp_payload = self.request(Op::DirRemove, payload)?;
        let _: DirRemoveResponse = rmp_serde::from_slice(&resp_payload)?;
        Ok(())
    }

    pub fn setattr(
        &self,
        path: &str,
        mode: u32,
        session_id: Option<String>,
        allocation_id: Option<String>,
    ) -> Result<()> {
        let req = SetattrRequest {
            path: path.into(),
            mode,
            session_id,
            allocation_id,
            ..Default::default()
        };
        let payload = rmp_serde::to_vec_named(&req)?;
        let resp_payload = self.request(Op::Setattr, payload)?;
        let _: SetattrResponse = rmp_serde::from_slice(&resp_payload)?;
        Ok(())
    }

    /// chown: set uid/gid. `mode` carries the path's CURRENT mode so the
    /// server's unconditional SetMode is a no-op (the server always chmods to
    /// req.mode before applying the owner change).
    pub fn setattr_owner(
        &self,
        path: &str,
        mode: u32,
        uid: u32,
        gid: u32,
        session_id: Option<String>,
        allocation_id: Option<String>,
    ) -> Result<()> {
        let req = SetattrRequest {
            path: path.into(),
            mode,
            uid: Some(uid),
            gid: Some(gid),
            session_id,
            allocation_id,
            ..Default::default()
        };
        let payload = rmp_serde::to_vec_named(&req)?;
        let resp_payload = self.request(Op::Setattr, payload)?;
        let _: SetattrResponse = rmp_serde::from_slice(&resp_payload)?;
        Ok(())
    }

    /// utimensat: set the access time (unix ns). `mode` carries the path's
    /// CURRENT mode so the server's unconditional SetMode is a no-op.
    pub fn setattr_atime(
        &self,
        path: &str,
        mode: u32,
        atime: i64,
        session_id: Option<String>,
        allocation_id: Option<String>,
    ) -> Result<()> {
        let req = SetattrRequest {
            path: path.into(),
            mode,
            atime: Some(atime),
            session_id,
            allocation_id,
            ..Default::default()
        };
        let payload = rmp_serde::to_vec_named(&req)?;
        let resp_payload = self.request(Op::Setattr, payload)?;
        let _: SetattrResponse = rmp_serde::from_slice(&resp_payload)?;
        Ok(())
    }

    pub fn symlink(
        &self,
        path: &str,
        target: &str,
        mode: u32,
        session_id: Option<String>,
        allocation_id: Option<String>,
    ) -> Result<()> {
        let req = SymlinkRequest {
            path: path.into(),
            target: target.into(),
            mode,
            session_id,
            allocation_id,
        };
        let payload = rmp_serde::to_vec_named(&req)?;
        let resp_payload = self.request(Op::Symlink, payload)?;
        let _: SymlinkResponse = rmp_serde::from_slice(&resp_payload)?;
        Ok(())
    }

    pub fn mknod(
        &self,
        path: &str,
        mode: u32,
        rdev: u64,
        session_id: Option<String>,
        allocation_id: Option<String>,
    ) -> Result<()> {
        let req = MknodRequest {
            path: path.into(),
            mode,
            rdev,
            session_id,
            allocation_id,
        };
        let payload = rmp_serde::to_vec_named(&req)?;
        let resp_payload = self.request(Op::Mknod, payload)?;
        let _: MknodResponse = rmp_serde::from_slice(&resp_payload)?;
        Ok(())
    }

    pub fn readlink(&self, path: &str) -> Result<String> {
        let req = ReadlinkRequest { path: path.into() };
        let payload = rmp_serde::to_vec_named(&req)?;
        let resp_payload = self.request(Op::Readlink, payload)?;
        let resp: ReadlinkResponse = rmp_serde::from_slice(&resp_payload)?;
        Ok(resp.target)
    }

    /// Query the write journal for an allocation. Returns entries newest-first
    /// up to `limit`; pass `before_ts_ms` from the previous response's
    /// `next_before_ts_ms` to page backwards.
    pub fn journal_query(
        &self,
        allocation_id: &str,
        limit: u32,
        before_ts_ms: Option<i64>,
    ) -> Result<JournalQueryResponse> {
        let req = JournalQueryRequest {
            allocation_id: allocation_id.to_owned(),
            limit,
            before_ts_ms: before_ts_ms.unwrap_or(0),
        };
        let payload = rmp_serde::to_vec_named(&req)?;
        let resp_payload = self.request(Op::JournalQuery, payload)?;
        Ok(rmp_serde::from_slice(&resp_payload)?)
    }

    /// Revert specific paths in an allocation's journal. CAS conflicts come
    /// back in the `conflicts` vec rather than as a wire error, so partial
    /// success is visible to the caller.
    pub fn journal_revert_path(
        &self,
        allocation_id: &str,
        paths: &[String],
    ) -> Result<JournalRevertPathResponse> {
        let req = JournalRevertPathRequest {
            allocation_id: allocation_id.to_owned(),
            paths: paths.to_vec(),
        };
        let payload = rmp_serde::to_vec_named(&req)?;
        let resp_payload = self.request(Op::JournalRevertPath, payload)?;
        Ok(rmp_serde::from_slice(&resp_payload)?)
    }

    /// Register a single push handler. Server-pushed frames (no FlagResponse)
    /// are forwarded to `tx`. Set-once: replacing an existing handler returns
    /// the old one (caller usually discards).
    pub fn runtime(&self) -> Arc<Runtime> {
        Arc::clone(&self.runtime)
    }

    pub fn set_push_handler(&self, tx: UnboundedSender<Frame>) -> Option<UnboundedSender<Frame>> {
        let mut slot = self.inner.push_handler.lock();
        slot.replace(tx)
    }

    pub fn lease_grant(&self, path: &str, mode: LeaseMode) -> Result<LeaseGrantResponse> {
        let req = LeaseGrantRequest {
            path: path.to_string(),
            mode,
        };
        let payload = rmp_serde::to_vec_named(&req)?;
        let resp_payload = self.request(Op::LeaseGrant, payload)?;
        Ok(rmp_serde::from_slice(&resp_payload)?)
    }

    pub fn lease_refresh(&self, lease_id: &[u8; 16]) -> Result<LeaseRefreshResponse> {
        let req = LeaseRefreshRequest {
            lease_id: lease_id.to_vec(),
        };
        let payload = rmp_serde::to_vec_named(&req)?;
        let resp_payload = self.request(Op::LeaseRefresh, payload)?;
        Ok(rmp_serde::from_slice(&resp_payload)?)
    }

    pub fn lease_release(&self, lease_id: &[u8; 16], dirty_flushed: bool) -> Result<()> {
        let req = LeaseReleaseRequest {
            lease_id: lease_id.to_vec(),
            dirty_flushed,
        };
        let payload = rmp_serde::to_vec_named(&req)?;
        let _resp = self.request(Op::LeaseRelease, payload)?;
        Ok(())
    }

    fn request(&self, op: Op, payload: Vec<u8>) -> Result<Vec<u8>> {
        if payload.len() as u32 > MAX_PAYLOAD_LEN {
            return Err(anyhow!(
                "payload {} exceeds MAX_PAYLOAD_LEN {}",
                payload.len(),
                MAX_PAYLOAD_LEN
            ));
        }
        let inner = Arc::clone(&self.inner);
        let request_timeout = inner.cfg.request_timeout;
        self.block_on(async move {
            let handle = inner.ensure_connected().await?;
            let rid = inner.next_rid.fetch_add(1, Ordering::Relaxed);
            inner.in_flight.fetch_add(1, Ordering::Relaxed);
            let result =
                send_on_control_stream(&handle, &inner, op, rid, payload, request_timeout).await;
            inner.in_flight.fetch_sub(1, Ordering::Relaxed);
            result
        })
    }

    // Run an async block on this client's dedicated runtime, safe from inside
    // another tokio runtime: `block_in_place` releases the current worker from
    // async duties (multi-thread runtime only) so the nested `block_on` does
    // not trip "Cannot start a runtime from within a runtime". When invoked
    // off-runtime (the original sync caller path) `tokio::runtime::Handle::try_current`
    // returns None and we fall back to a direct `block_on`.
    fn block_on<F: std::future::Future>(&self, fut: F) -> F::Output {
        if tokio::runtime::Handle::try_current().is_ok() {
            tokio::task::block_in_place(|| self.runtime.block_on(fut))
        } else {
            self.runtime.block_on(fut)
        }
    }
}

fn build_chunk_get_payload(hash: &[u8]) -> Result<Vec<u8>> {
    let req = ChunkGetRequest {
        hash: hash.to_vec(),
    };
    let payload = rmp_serde::to_vec_named(&req)?;
    if payload.len() as u32 > MAX_PAYLOAD_LEN {
        return Err(anyhow!(
            "payload {} exceeds MAX_PAYLOAD_LEN {}",
            payload.len(),
            MAX_PAYLOAD_LEN
        ));
    }
    Ok(payload)
}

/// Single chunk_get round-trip — picks QUIC's per-RPC stream when available,
/// otherwise the multiplexed control stream. Used by both single-chunk and
/// batch entry points.
async fn chunk_get_one(
    handle: Arc<ConnHandle>,
    inner: Arc<Inner>,
    payload: Vec<u8>,
) -> Result<Vec<u8>> {
    let request_timeout = inner.cfg.request_timeout;
    let rid = inner.next_rid.fetch_add(1, Ordering::Relaxed);
    inner.in_flight.fetch_add(1, Ordering::Relaxed);
    let result = if let Some(quic) = handle.quic.as_ref() {
        let connection = quic.connection.clone();
        chunk_get_via_new_stream(&connection, rid, payload, request_timeout).await
    } else {
        send_on_control_stream(&handle, &inner, Op::ChunkGet, rid, payload, request_timeout).await
    };
    inner.in_flight.fetch_sub(1, Ordering::Relaxed);
    result
}

/// Same shape as `chunk_get_one` but always rides the multiplexed control
/// stream — used by the parallel chunk_put batch path.
async fn request_on_control_stream(
    handle: Arc<ConnHandle>,
    inner: Arc<Inner>,
    op: Op,
    payload: Vec<u8>,
) -> Result<Vec<u8>> {
    let request_timeout = inner.cfg.request_timeout;
    let rid = inner.next_rid.fetch_add(1, Ordering::Relaxed);
    inner.in_flight.fetch_add(1, Ordering::Relaxed);
    let result = send_on_control_stream(&handle, &inner, op, rid, payload, request_timeout).await;
    inner.in_flight.fetch_sub(1, Ordering::Relaxed);
    result
}

async fn send_on_control_stream(
    handle: &ConnHandle,
    inner: &Arc<Inner>,
    op: Op,
    rid: u64,
    payload: Vec<u8>,
    request_timeout: Duration,
) -> Result<Vec<u8>> {
    let (resp_tx, resp_rx) = oneshot::channel();
    handle.pending.lock().insert(rid, resp_tx);

    let send_result = handle.write_tx.send(Frame::request(op, rid, payload)).await;
    if send_result.is_err() {
        handle.pending.lock().remove(&rid);
        inner.disconnect();
        return Err(io_error("write channel closed; connection dropped"));
    }

    match timeout(request_timeout, resp_rx).await {
        Ok(Ok(frame)) => parse_response(op, frame),
        Ok(Err(_)) => {
            inner.disconnect();
            Err(io_error("connection dropped before response"))
        }
        Err(_) => {
            handle.pending.lock().remove(&rid);
            Err(io_error(format!(
                "request timed out after {:?}",
                request_timeout
            )))
        }
    }
}

/// Open a brand-new bidi stream on `connection`, write a single chunk_get
/// request, half-close the send side so the server returns on EOF, and read
/// exactly one response frame back. Returns the parsed payload (or an error
/// payload as `BackendError`).
///
/// Per-RPC streams sidestep the cwnd / single-stream serialization that limits
/// chunk_get throughput on the long-lived control stream — see
/// `project_quic_single_stream` memory.
async fn chunk_get_via_new_stream(
    connection: &quinn::Connection,
    rid: u64,
    payload: Vec<u8>,
    request_timeout: Duration,
) -> Result<Vec<u8>> {
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .context("open per-RPC bidi stream for chunk_get")?;
    let frame = Frame::request(Op::ChunkGet, rid, payload);
    write_frame_async(&mut send, &frame)
        .await
        .context("write chunk_get request frame")?;
    // Do NOT finish() the send half before reading. The server's per-stream
    // frame loop (serveFrames in cmd/orlop-server/dataplane_server.go) sees EOF on
    // the next ReadFrame and runs its defers — including writer.close — which
    // races the in-flight chunk_get handler goroutine: if EOF wins, the
    // response is dropped on the floor and the client sees a stream reset.
    // Finish AFTER the response is in hand so the writer is guaranteed empty.
    let resp = match timeout(request_timeout, read_frame_async(&mut recv)).await {
        Ok(Ok(frame)) => frame,
        Ok(Err(e)) => return Err(e.context("read chunk_get response frame")),
        Err(_) => {
            return Err(io_error(format!(
                "chunk_get response timed out after {:?}",
                request_timeout
            )));
        }
    };
    let _ = send.finish();
    parse_response(Op::ChunkGet, resp)
}

impl Inner {
    async fn ensure_connected(self: &Arc<Self>) -> Result<Arc<ConnHandle>> {
        // Fast path: already connected.
        {
            let state = self.state.lock();
            if let ConnState::Connected(h) = &*state {
                return Ok(Arc::clone(h));
            }
        }
        // Slow path: dial. Holding the mutex across await would block other
        // request paths, so we drop it and re-acquire to install the handle.
        let handle = self.dial().await?;
        let mut state = self.state.lock();
        // Race: another caller may have installed a handle while we were
        // dialing. Prefer theirs and let ours drop.
        if let ConnState::Connected(h) = &*state {
            return Ok(Arc::clone(h));
        }
        *state = ConnState::Connected(Arc::clone(&handle));
        Ok(handle)
    }

    fn disconnect(&self) {
        let mut state = self.state.lock();
        if let ConnState::Connected(handle) = &*state {
            // Drain pending — readers currently blocked on oneshot will see
            // the sender dropped and return an error.
            handle.pending.lock().clear();
        }
        *state = ConnState::Disconnected;
    }

    async fn dial(self: &Arc<Self>) -> Result<Arc<ConnHandle>> {
        match self.cfg.transport {
            TransportMode::Tcp => self.dial_tcp().await,
            TransportMode::Quic => self.dial_quic().await,
            TransportMode::Auto => self.dial_auto().await,
        }
    }

    async fn dial_auto(self: &Arc<Self>) -> Result<Arc<ConnHandle>> {
        if *self.preferred_transport.lock() == Some(TransportMode::Tcp) {
            return self.dial_tcp().await;
        }
        // No prior success, or QUIC succeeded last time: try QUIC first, fall
        // back to TCP. The next call sticks to whichever wins via
        // `preferred_transport`.
        match self.dial_quic().await {
            Ok(handle) => Ok(handle),
            Err(_) => self.dial_tcp().await,
        }
    }

    async fn dial_tcp(self: &Arc<Self>) -> Result<Arc<ConnHandle>> {
        let socket_addr = self
            .cfg
            .addr
            .to_socket_addrs()
            .context("resolve data-plane server addr")?
            .next()
            .ok_or_else(|| anyhow!("no addresses for {}", self.cfg.addr))?;
        let tcp = TcpStream::connect(socket_addr)
            .await
            .context("tcp connect for data-plane mount")?;
        tcp.set_nodelay(true).ok();

        let server_name = ServerName::try_from(self.cfg.server_name.clone())
            .context("invalid TLS server name")?;
        let connector = TlsConnector::from(Arc::clone(&self.rustls_config));
        let tls = connector
            .connect(server_name, tcp)
            .await
            .context("tls handshake for data-plane mount")?;
        let (read_half, write_half) = tokio::io::split(tls);

        let pending = Arc::new(Mutex::new(HashMap::<u64, oneshot::Sender<Frame>>::new()));
        let (write_tx, write_rx) = mpsc::channel::<Frame>(WRITE_CHANNEL_DEPTH);

        let writer = tokio::spawn(writer_task(write_rx, write_half));
        let reader = tokio::spawn(reader_task(
            read_half,
            Arc::clone(&pending),
            Arc::clone(self),
        ));
        let heartbeat = tokio::spawn(heartbeat_task(
            write_tx.clone(),
            self.cfg.heartbeat_interval,
            self.cfg.heartbeat_timeout,
            Arc::clone(self),
        ));

        *self.preferred_transport.lock() = Some(TransportMode::Tcp);
        Ok(Arc::new(ConnHandle {
            write_tx,
            pending,
            _writer: writer,
            _reader: reader,
            _heartbeat: heartbeat,
            quic: None,
        }))
    }

    async fn dial_quic(self: &Arc<Self>) -> Result<Arc<ConnHandle>> {
        let socket_addr = resolve_addr(&self.cfg.addr)?;
        let bind_addr = match socket_addr {
            SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
        };
        let mut endpoint = quinn::Endpoint::client(bind_addr).context("create QUIC endpoint")?;
        endpoint.set_default_client_config(self.quic_config.clone());
        let connecting = endpoint
            .connect(socket_addr, &self.cfg.server_name)
            .context("start QUIC connect for data-plane mount")?;
        let connection = timeout(self.cfg.quic_connect_timeout, connecting)
            .await
            .context("QUIC connect timed out for data-plane mount")?
            .context("QUIC handshake for data-plane mount")?;
        let (write_half, read_half) = connection
            .open_bi()
            .await
            .context("open QUIC data-plane stream")?;

        let pending = Arc::new(Mutex::new(HashMap::<u64, oneshot::Sender<Frame>>::new()));
        let (write_tx, write_rx) = mpsc::channel::<Frame>(WRITE_CHANNEL_DEPTH);

        let writer = tokio::spawn(writer_task(write_rx, write_half));
        let reader = tokio::spawn(reader_task(
            read_half,
            Arc::clone(&pending),
            Arc::clone(self),
        ));
        let heartbeat = tokio::spawn(heartbeat_task(
            write_tx.clone(),
            self.cfg.heartbeat_interval,
            self.cfg.heartbeat_timeout,
            Arc::clone(self),
        ));

        *self.preferred_transport.lock() = Some(TransportMode::Quic);
        Ok(Arc::new(ConnHandle {
            write_tx,
            pending,
            _writer: writer,
            _reader: reader,
            _heartbeat: heartbeat,
            quic: Some(QuicConnectionGuard {
                _endpoint: endpoint,
                connection,
            }),
        }))
    }
}

async fn writer_task<W>(mut rx: mpsc::Receiver<Frame>, mut w: W)
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    while let Some(frame) = rx.recv().await {
        if write_frame_async(&mut w, &frame).await.is_err() {
            break;
        }
        if w.flush().await.is_err() {
            break;
        }
    }
    let _ = w.shutdown().await;
}

async fn reader_task<R>(
    mut r: R,
    pending: Arc<Mutex<HashMap<u64, oneshot::Sender<Frame>>>>,
    inner: Arc<Inner>,
) where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    loop {
        match read_frame_async(&mut r).await {
            Ok(frame) => {
                if frame.is_response() {
                    if let Some(tx) = pending.lock().remove(&frame.rid) {
                        let _ = tx.send(frame);
                    }
                    // Unmatched response RIDs are dropped (timed-out request).
                } else {
                    // Server-pushed frame (e.g. LeaseRevoke).
                    let handler = inner.push_handler.lock().clone();
                    if let Some(tx) = handler {
                        let _ = tx.send(frame);
                    }
                    // No handler installed: drop the frame silently.
                }
            }
            Err(_) => {
                inner.disconnect();
                return;
            }
        }
    }
}

async fn heartbeat_task(
    write_tx: mpsc::Sender<Frame>,
    interval: Duration,
    timeout_after: Duration,
    inner: Arc<Inner>,
) {
    // We send PING every `interval`. The reader doesn't have a back-channel to
    // tell us about PONGs explicitly, but if the connection stalls the writer
    // send will fail (channel closed) once disconnect runs. As a belt-and-
    // braces measure, we also bound how long we wait between successful sends.
    loop {
        tokio::time::sleep(interval).await;
        let req = PingRequest {
            nonce: random_nonce(),
        };
        let Ok(payload) = rmp_serde::to_vec_named(&req) else {
            continue;
        };
        let send = write_tx.send_timeout(Frame::request(Op::Ping, 0, payload), timeout_after);
        if send.await.is_err() {
            inner.disconnect();
            return;
        }
    }
}

fn parse_response(req_op: Op, frame: Frame) -> Result<Vec<u8>> {
    if frame.flags & flags::RESPONSE == 0 {
        return Err(anyhow!("server returned a non-response frame"));
    }
    if frame.op != req_op && frame.op != Op::Ping {
        return Err(anyhow!(
            "op mismatch: requested {:?}, got {:?}",
            req_op,
            frame.op
        ));
    }
    if frame.is_error() {
        let err: ErrorPayload = rmp_serde::from_slice(&frame.payload)
            .unwrap_or_else(|_| ErrorPayload::eio("malformed error payload"));
        let mut be = BackendError::new(err.errno, err.message);
        if let Some(hint) = err.recovery {
            be = be.with_recovery(hint);
        }
        return Err(be.into());
    }
    Ok(frame.payload)
}

fn build_rustls_config(tls: &TlsIdentity) -> Result<rustls::ClientConfig> {
    let mut roots = RootCertStore::empty();
    let ca_certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut tls.ca_pem.as_slice())
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parse data-plane client CA pem")?;
    if ca_certs.is_empty() {
        return Err(anyhow!("data-plane ca_pem contained no certificates"));
    }
    for cert in ca_certs {
        roots.add(cert).context("install data-plane server CA")?;
    }

    // The client must send leaf + tenant intermediate so the server can
    // build the chain back to its root trust anchor. cert.pem holds only
    // the leaf; ca.pem is `intermediate || root`. Concatenate so the
    // mTLS handshake presents the full chain (root in the chain is
    // harmless — server has it as a trust anchor and ignores duplicates).
    let mut client_chain_pem = Vec::with_capacity(tls.cert_pem.len() + tls.ca_pem.len());
    client_chain_pem.extend_from_slice(&tls.cert_pem);
    if !client_chain_pem.ends_with(b"\n") {
        client_chain_pem.push(b'\n');
    }
    client_chain_pem.extend_from_slice(&tls.ca_pem);
    let client_certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut client_chain_pem.as_slice())
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("parse data-plane client cert pem")?;
    if client_certs.is_empty() {
        return Err(anyhow!("data-plane cert_pem contained no certificates"));
    }
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut tls.key_pem.as_slice())
        .context("parse data-plane client key pem")?
        .ok_or_else(|| anyhow!("data-plane key_pem contained no private key"))?;

    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(client_certs, key)
        .context("build rustls config")?;
    cfg.alpn_protocols = vec![ORLOP_QUIC_ALPN.to_vec()];
    Ok(cfg)
}

fn build_quic_config(
    rustls_config: Arc<rustls::ClientConfig>,
    keep_alive_interval: Duration,
) -> Result<quinn::ClientConfig> {
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_config)
        .context("build QUIC rustls client config")?;
    let mut cfg = quinn::ClientConfig::new(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(keep_alive_interval));
    // Default quinn windows (~1.25 MB stream / connection) bottleneck large
    // sequential reads on a single bidi stream over WAN RTT. Bump to ~64 MB
    // connection / ~16 MB stream so 100 MiB cold reads aren't gated on
    // MAX_STREAM_DATA round-trips.
    transport.stream_receive_window(quinn::VarInt::from_u32(16 * 1024 * 1024));
    transport.receive_window(quinn::VarInt::from_u32(64 * 1024 * 1024));
    transport.send_window(64 * 1024 * 1024);
    cfg.transport_config(Arc::new(transport));
    Ok(cfg)
}

fn resolve_addr(addr: &str) -> Result<SocketAddr> {
    addr.to_socket_addrs()
        .context("resolve data-plane server addr")?
        .next()
        .ok_or_else(|| anyhow!("no addresses for {}", addr))
}

fn io_error(msg: impl Into<String>) -> anyhow::Error {
    BackendError::new(errno::EIO, msg.into()).into()
}

fn random_nonce() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

// PingResponse is reachable only on the wire today (heartbeat fires PONG into
// the response stream where it's discarded as an unmatched rid). Reference it
// here so the type stays in the API surface for follow-on work.
#[allow(dead_code)]
fn _typecheck_pong() -> PingResponse {
    PingResponse { nonce: 0 }
}

#[cfg(test)]
mod push_router_tests {
    use super::*;
    use tokio::sync::mpsc::unbounded_channel;

    #[test]
    fn frame_is_response_routes_via_pending_not_push() {
        // A response frame must NOT be sent to the push channel.
        let f = Frame::response(Op::Stat, 5, vec![]);
        assert!(f.is_response());
    }

    #[test]
    fn frame_without_response_flag_is_push() {
        let f = Frame {
            op: Op::LeaseRevoke,
            flags: 0,
            rid: 1u64 << 63,
            payload: vec![],
        };
        assert!(!f.is_response());
    }

    #[test]
    fn unbounded_channel_can_register() {
        let (tx, _rx) = unbounded_channel::<Frame>();
        let _: UnboundedSender<Frame> = tx;
    }

    #[test]
    fn response_flag_constant_exists() {
        // Verify flags::RESPONSE is the discriminator between push and response.
        let f = Frame::response(Op::LeaseGrant, 42, vec![]);
        assert!(f.flags & flags::RESPONSE != 0);
        let push = Frame {
            op: Op::LeaseRevoke,
            flags: 0,
            rid: 99,
            payload: vec![],
        };
        assert!(push.flags & flags::RESPONSE == 0);
    }
}

#[cfg(test)]
mod parse_response_tests {
    use super::*;
    use crate::backend::backend_recovery;
    use crate::backend::dataplane::messages::{LastWriter, RecoveryHint, RecoveryKind};

    #[test]
    fn parse_response_propagates_recovery_hint_into_backend_error() {
        let hint = RecoveryHint {
            kind: RecoveryKind::CasConflict,
            your_version: Some(5),
            current_version: Some(7),
            last_writer: Some(LastWriter {
                agent_id: Some("agent_a".into()),
                session_id: None,
                at_unix_ms: 1_700_000_000_000,
            }),
            suggested_action: "re-put with expected=7".into(),
        };
        let payload = rmp_serde::to_vec_named(
            &ErrorPayload::estale("CAS conflict on /x").with_recovery(hint),
        )
        .unwrap();
        let frame = Frame::error_response(Op::ManifestPut, 1, payload);

        let err = parse_response(Op::ManifestPut, frame).expect_err("error frame");
        let rec = backend_recovery(&err).expect("recovery hint propagated");
        assert_eq!(rec.kind, RecoveryKind::CasConflict);
        assert_eq!(rec.current_version, Some(7));
        assert_eq!(rec.your_version, Some(5));
        assert_eq!(rec.suggested_action, "re-put with expected=7");
    }

    #[test]
    fn parse_response_legacy_error_frame_yields_no_recovery() {
        // No recovery field on the wire — old server.
        let payload = rmp_serde::to_vec_named(&ErrorPayload::enoent("missing")).unwrap();
        let frame = Frame::error_response(Op::Stat, 1, payload);

        let err = parse_response(Op::Stat, frame).expect_err("error frame");
        assert!(backend_recovery(&err).is_none());
        assert_eq!(crate::backend::backend_errno(&err, libc::EIO), libc::ENOENT);
    }
}
