use std::fs::File;
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub mountpoint: Option<PathBuf>,
    #[serde(default = "default_audit_log")]
    pub audit_log: PathBuf,
    pub cache: Option<CacheConfig>,
    #[serde(default)]
    pub fuse: FuseConfig,
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub mounts: Vec<MountConfig>,
    /// When present, `orlop mount` enrolls against the control plane and dials
    /// the per-tenant `orlop-server` over mTLS. Absent → existing local-only
    /// flow.
    pub hosted: Option<HostedConfig>,
    #[serde(default)]
    pub chunk_cache: ChunkCacheConfig,
    /// What to do with the mountpoint when the mount lease is lost
    /// involuntarily (revoked, expired, or taken over by another agent).
    /// `None` → mode default: `abort` for `--from-env` (hosted/agent) mounts,
    /// `unmount` for interactive ones. See [`EvictionAction`].
    #[serde(default)]
    pub on_eviction: Option<EvictionAction>,
}

/// Teardown behavior for an INVOLUNTARY eviction (lease revoked/lost/taken
/// over), as opposed to a voluntary `orlop unmount`.
///
/// `Unmount` (the historical behavior) runs a clean unmount, which restores
/// whatever the mountpoint was covering — under a container typically an
/// empty writable scratch dir, so a still-running workload keeps "succeeding"
/// at writes that go nowhere (issue #92). `Abort` instead kills the FUSE
/// connection and exits without unmounting, so every subsequent syscall on
/// the mountpoint fails loudly with ENOTCONN. The stale mountpoint must then
/// be cleaned up out of band (`orlop unmount --stale`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvictionAction {
    Abort,
    Unmount,
}

impl std::str::FromStr for EvictionAction {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "abort" => Ok(Self::Abort),
            "unmount" => Ok(Self::Unmount),
            other => Err(format!(
                "invalid eviction action {other:?}: expected \"abort\" or \"unmount\""
            )),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ChunkCacheConfig {
    /// Soft cap for the persistent data-plane chunk cache. LRU prune evicts down
    /// to this size. Default 2 GiB.
    #[serde(default = "default_chunk_cache_max_bytes")]
    pub max_bytes: u64,
}

impl Default for ChunkCacheConfig {
    fn default() -> Self {
        Self {
            max_bytes: default_chunk_cache_max_bytes(),
        }
    }
}

fn default_chunk_cache_max_bytes() -> u64 {
    2 * 1024 * 1024 * 1024
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct HostedConfig {
    /// Falls back to the `control_plane_url` baked into `~/.config/orlop/credentials.json`.
    pub control_plane_url: Option<String>,
    /// Override the cert directory (default `~/.config/orlop`).
    pub cert_dir: Option<PathBuf>,
    /// Data-plane subtree to mount as the FUSE root. Default "/" (the whole
    /// tenant store). The in-pod env-mounter sets it to `/agents/<agent_id>` so
    /// the mount is confined to the agent's disk and matches the agent-scoped
    /// cert's per-agent authorization at orlop-server.
    #[serde(default)]
    pub mount_root: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FuseConfig {
    #[serde(default = "default_fuse_attr_ttl")]
    pub attr_ttl_seconds: u64,
    #[serde(default = "default_fuse_attr_ttl")]
    pub entry_ttl_seconds: u64,
    /// Mount with the kernel's `default_permissions` so the VFS enforces POSIX
    /// uid/gid/mode access checks (using the attrs we return from getattr).
    /// OFF by default: the product is a single-identity agent disk where the
    /// nonroot executor must read root-owned files via `allow_other`, so the
    /// default must NOT enforce. Only conformance/test mounts (pjdfstest) turn
    /// it on. See docs/design/pjdfstest-a-class-posix-plan.md (B-class).
    #[serde(default)]
    pub enforce_permissions: bool,
}

impl Default for FuseConfig {
    fn default() -> Self {
        Self {
            attr_ttl_seconds: default_fuse_attr_ttl(),
            entry_ttl_seconds: default_fuse_attr_ttl(),
            enforce_permissions: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CacheConfig {
    #[serde(default = "default_write_buffer_bytes")]
    pub write_buffer_bytes: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            write_buffer_bytes: default_write_buffer_bytes(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PolicyConfig {
    #[serde(default = "default_true")]
    pub readonly: bool,
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default)]
    pub allow: Vec<String>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            readonly: true,
            deny: Vec::new(),
            allow: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct MountConfig {
    pub name: String,
    pub mount: String,
    #[serde(default = "default_true")]
    pub readonly: bool,
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default)]
    pub allow: Vec<String>,

    /// `host:port` for the data-plane binary listener.
    pub addr: Option<String>,
    /// SNI / cert verification name. Default: host part of `addr`.
    pub server_name: Option<String>,
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let file = File::open(path)?;
        let cfg: Self = serde_yaml::from_reader(file)
            .with_context(|| format!("invalid config {}", path.display()))?;
        Ok(cfg)
    }
}

fn default_audit_log() -> PathBuf {
    PathBuf::from("./audit.log")
}

fn default_write_buffer_bytes() -> u64 {
    64 * 1024 * 1024 // 64 MiB
}

fn default_true() -> bool {
    true
}

fn default_fuse_attr_ttl() -> u64 {
    30
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_remote_mount_config() {
        // `type: remote` is what older configs carried; serde ignores the
        // now-removed key so they keep loading.
        let cfg: Config = serde_yaml::from_str(
            r#"
mounts:
  - name: hosted
    type: remote
    mount: /entities
    addr: "tenant.orlop-server.example.ts.net:7879"
"#,
        )
        .unwrap();

        let mount = &cfg.mounts[0];
        assert_eq!(
            mount.addr.as_deref(),
            Some("tenant.orlop-server.example.ts.net:7879"),
        );
    }

    #[test]
    fn repository_example_configs_load() {
        Config::load(Path::new("config.example.yaml")).unwrap();
        Config::load(Path::new("config.full.yaml")).unwrap();
    }

    #[test]
    fn on_eviction_defaults_to_none_and_parses_both_values() {
        let cfg: Config = serde_yaml::from_str("mountpoint: /mnt/orlop\n").unwrap();
        assert_eq!(cfg.on_eviction, None);

        let cfg: Config =
            serde_yaml::from_str("mountpoint: /mnt/orlop\non_eviction: abort\n").unwrap();
        assert_eq!(cfg.on_eviction, Some(EvictionAction::Abort));

        let cfg: Config =
            serde_yaml::from_str("mountpoint: /mnt/orlop\non_eviction: unmount\n").unwrap();
        assert_eq!(cfg.on_eviction, Some(EvictionAction::Unmount));
    }

    #[test]
    fn eviction_action_from_str_round_trips_and_rejects_garbage() {
        assert_eq!("abort".parse(), Ok(EvictionAction::Abort));
        assert_eq!("unmount".parse(), Ok(EvictionAction::Unmount));
        assert!("Abort".parse::<EvictionAction>().is_err());
        assert!("".parse::<EvictionAction>().is_err());
    }

    #[test]
    fn hosted_config_loads() {
        let cfg: Config = serde_yaml::from_str(
            r#"
mountpoint: /mnt/orlop
hosted:
  control_plane_url: https://control.orlop.example
"#,
        )
        .unwrap();

        assert!(cfg.hosted.is_some());
        assert_eq!(
            cfg.hosted.as_ref().unwrap().control_plane_url.as_deref(),
            Some("https://control.orlop.example"),
        );
    }
}
