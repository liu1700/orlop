use std::sync::Arc;

use anyhow::anyhow;

use crate::backend::dataplane::messages::RecoveryHint;
use crate::config::MountConfig;
use crate::policy::Policy;

#[path = "backend/tls.rs"]
pub mod tls;

pub mod dataplane;

pub use tls::{shared_tls_identity, SharedTlsIdentity, TlsIdentity};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Dir,
    Symlink,
    /// POSIX special nodes (mknod / mkfifo / unix-socket bind).
    Fifo,
    Socket,
    CharDev,
    BlockDev,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub kind: EntryKind,
    pub size: u64,
    /// Stable backend inode identity for regular files. Zero means unknown.
    pub inode_id: u64,
    /// POSIX hard-link count. Zero means unknown and callers fall back to one.
    pub nlink: u32,
    /// POSIX permission + type bits as stored server-side. 0 means the server
    /// did not report a mode (old server) — callers fall back to a kind default.
    pub mode: u32,
    /// POSIX owner uid/gid as stored server-side. 0/0 (root) is the correct
    /// fallback on a single-identity mount (also what an old server reports).
    pub uid: u32,
    pub gid: u32,
    /// Access time, unix nanoseconds. 0 means the server did not report one —
    /// callers fall back to mtime/now.
    pub atime: i64,
    /// Device number for block/char special files; 0 for every other kind.
    pub rdev: u64,
    /// Modification time, unix nanoseconds, populated for regular files.
    /// 0 means the server did not report one (old server) — callers fall
    /// back to a manifest fetch.
    pub mtime: i64,
    /// Manifest CAS version, files only. 0 means unreported (old server).
    pub version: u64,
}

pub struct MountedStore {
    pub mount_name: String,
    pub policy: Policy,
    pub store: Arc<dyn crate::store::Store>,
    pub leases: Option<Arc<crate::lease::LeaseManager>>,
}

pub fn build_stores(
    configs: &[MountConfig],
    tls: Option<&TlsIdentity>,
    chunk_cache: Arc<dataplane::ChunkCache>,
) -> anyhow::Result<Vec<MountedStore>> {
    let shared_tls = tls.map(|identity| shared_tls_identity(identity.clone()));
    build_stores_shared(configs, shared_tls.as_ref(), chunk_cache)
}

/// Build stores whose future data-plane connections observe certificate
/// renewal through a shared identity source.
pub fn build_stores_shared(
    configs: &[MountConfig],
    tls: Option<&SharedTlsIdentity>,
    chunk_cache: Arc<dataplane::ChunkCache>,
) -> anyhow::Result<Vec<MountedStore>> {
    configs
        .iter()
        .map(|cfg| {
            let mount_name = cfg.mount.trim_matches('/').to_string();
            // A nested mount path is allowed (e.g. `agents/<id>`, so an
            // agent-scoped mount targets its /agents/<id> subtree) — but every
            // segment must be clean: reject empty/`.`/`..` to keep the server
            // prefix canonical and traversal-free.
            if mount_name
                .split('/')
                .any(|seg| seg.is_empty() || seg == "." || seg == "..")
                && !mount_name.is_empty()
            {
                anyhow::bail!("mount must be `/` or a clean relative path: {}", cfg.mount);
            }
            // Empty mount_name means the mount is the disk root — server-side
            // paths get no prefix.
            let server_prefix = if mount_name.is_empty() {
                String::new()
            } else {
                format!("/{mount_name}")
            };

            // Every mount is remote — the data plane is the only backend.
            let addr = cfg
                .addr
                .clone()
                .ok_or_else(|| anyhow!("remote mount {} requires addr", cfg.name))?;
            let server_name = cfg
                .server_name
                .clone()
                .or_else(|| host_part(&addr).map(str::to_string))
                .ok_or_else(|| {
                    anyhow!(
                        "remote mount {}: cannot derive server_name from addr {}",
                        cfg.name,
                        addr
                    )
                })?;
            let tls_id = tls
                .cloned()
                .ok_or_else(|| anyhow!("remote mount {} requires a TLS identity", cfg.name))?;
            let dp_cfg =
                dataplane::DataClientConfig::new_shared(addr.clone(), server_name, tls_id)?;
            let client = Arc::new(dataplane::DataClient::new(dp_cfg)?);
            let leases = Some(crate::lease::LeaseManager::new(Arc::clone(&client)));
            let mut data_store = dataplane::DataStore::new(
                Arc::clone(&client),
                server_prefix.clone(),
                Arc::clone(&chunk_cache),
            );
            // Metadata mirror (issue #122): default on, ORLOP_METADATA_MIRROR=0
            // is the kill switch. Failure to start is never fatal — the mount
            // just runs the pre-mirror wire path.
            if dataplane::mirror::mirror_enabled_from_env() {
                let key = format!("{addr}|{server_prefix}");
                match dataplane::MetadataMirror::start(client, chunk_cache.root(), &key) {
                    Ok(m) => data_store.set_mirror(m),
                    Err(e) => eprintln!(
                        "orlop: metadata mirror unavailable ({e:#}); continuing without it"
                    ),
                }
            }
            let store: Arc<dyn crate::store::Store> = Arc::new(data_store);

            Ok(MountedStore {
                mount_name,
                policy: Policy::with_readonly(&cfg.allow, &cfg.deny, cfg.readonly)?,
                store,
                leases,
            })
        })
        .collect()
}

#[derive(Debug)]
pub struct BackendError {
    errno: i32,
    message: String,
    recovery: Option<RecoveryHint>,
}

impl BackendError {
    pub fn new(errno: i32, message: impl Into<String>) -> Self {
        Self {
            errno,
            message: message.into(),
            recovery: None,
        }
    }

    pub fn with_recovery(mut self, hint: RecoveryHint) -> Self {
        self.recovery = Some(hint);
        self
    }

    pub fn errno(&self) -> i32 {
        self.errno
    }

    pub fn recovery(&self) -> Option<&RecoveryHint> {
        self.recovery.as_ref()
    }
}

impl std::fmt::Display for BackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for BackendError {}

pub fn backend_errno(err: &anyhow::Error, default_errno: i32) -> i32 {
    err.downcast_ref::<BackendError>()
        .map(BackendError::errno)
        .unwrap_or(default_errno)
}

pub fn backend_recovery(err: &anyhow::Error) -> Option<&RecoveryHint> {
    err.downcast_ref::<BackendError>()
        .and_then(BackendError::recovery)
}

fn host_part(addr: &str) -> Option<&str> {
    addr.rsplit_once(':').map(|(host, _)| host)
}
