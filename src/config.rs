use std::fs::File;
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
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
}

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Default, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
pub struct FuseConfig {
    #[serde(default = "default_fuse_attr_ttl")]
    pub attr_ttl_seconds: u64,
    #[serde(default = "default_fuse_attr_ttl")]
    pub entry_ttl_seconds: u64,
    #[serde(default = "default_remote_metadata_ttl")]
    pub remote_metadata_ttl_seconds: u64,
    #[serde(default = "default_remote_metadata_capacity")]
    pub remote_metadata_capacity: u64,
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
            remote_metadata_ttl_seconds: default_remote_metadata_ttl(),
            remote_metadata_capacity: default_remote_metadata_capacity(),
            enforce_permissions: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct CacheConfig {
    #[serde(default = "default_cache_entries")]
    pub max_entries: usize,
    #[serde(default = "default_cache_ttl")]
    pub ttl_seconds: u64,
    #[serde(default = "default_write_buffer_bytes")]
    pub write_buffer_bytes: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_entries: default_cache_entries(),
            ttl_seconds: default_cache_ttl(),
            write_buffer_bytes: default_write_buffer_bytes(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MountConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: MountKind,
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

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MountKind {
    Remote,
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let file = File::open(path)?;
        let cfg: Self = serde_yaml::from_reader(file)?;
        cfg.validate()
            .with_context(|| format!("invalid config {}", path.display()))?;
        Ok(cfg)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        Ok(())
    }

    pub fn fuse_mountpoint(&self) -> Option<PathBuf> {
        self.mountpoint.clone()
    }

    pub fn fuse_mounts(&self) -> anyhow::Result<Vec<MountConfig>> {
        Ok(self.mounts.clone())
    }
}

/// Canonical user config path (`~/.config/orlop/config.yaml`). Lives next
/// to `credentials.json` so both share one directory.
pub fn default_config_path() -> anyhow::Result<PathBuf> {
    Ok(crate::util::home_dir()?.join(".config/orlop/config.yaml"))
}

/// YAML body seeded as the default config when none exists yet. Mountpoint
/// defaults under `$HOME` so first-time `orlop mount` doesn't require sudo;
/// `hosted: {}` is the minimum needed to take the hosted code path —
/// control_plane_url + cert_dir fall back to values from credentials.json.
/// Policy defaults to read-write because the whole product premise is "save
/// your stuff to a durable disk"; PolicyConfig's struct-level default of
/// readonly=true is a defensive value for non-hosted / shared mounts, not a
/// sensible default for a personal hosted disk.
pub fn default_config_yaml(home: &Path) -> String {
    let mountpoint = home.join(".orlop/mnt");
    // Raw string (no `\` line-continuation): `\` would otherwise eat the
    // newline AND any leading whitespace, dropping the 2-space indent on
    // `readonly: false` so the YAML parses as {policy: null, readonly: false}.
    format!(
        r#"# Auto-generated default Orlop config. Edit to customize.

# `mountpoint` is where the FUSE filesystem appears. Default lives under
# $HOME so `orlop mount` works without sudo. Move it (e.g. to /mnt/orlop
# after `sudo mkdir /mnt/orlop && sudo chown $USER /mnt/orlop`) if preferred.
mountpoint: {mp}

# Personal disk defaults to read-write. Flip to `readonly: true` if you
# want a safety belt against agents writing to it, then remount.
policy:
  readonly: false

# `hosted: {{}}` is the minimum needed for the hosted control plane.
# control_plane_url and cert_dir both fall back to credentials.json when
# omitted, so an empty mapping is enough for the standard setup.
hosted: {{}}
"#,
        mp = mountpoint.display()
    )
}

/// Write the default hosted config at `path` if no file exists there yet.
/// Returns `Ok(true)` when a file was written, `Ok(false)` when one was
/// already present (caller decides whether to log "wrote" vs "left alone").
pub fn write_default_if_missing(path: &Path) -> anyhow::Result<bool> {
    if path.exists() {
        return Ok(false);
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let body = default_config_yaml(&crate::util::home_dir()?);
    std::fs::write(path, body).with_context(|| format!("write {}", path.display()))?;
    Ok(true)
}

fn default_audit_log() -> PathBuf {
    PathBuf::from("./audit.log")
}

fn default_write_buffer_bytes() -> u64 {
    64 * 1024 * 1024 // 64 MiB
}

fn default_cache_entries() -> usize {
    1024
}

fn default_cache_ttl() -> u64 {
    300
}

fn default_true() -> bool {
    true
}

fn default_fuse_attr_ttl() -> u64 {
    30
}

fn default_remote_metadata_ttl() -> u64 {
    30
}

fn default_remote_metadata_capacity() -> u64 {
    4096
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_remote_mount_config() {
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

        cfg.validate().unwrap();
        let mount = &cfg.fuse_mounts().unwrap()[0];
        assert!(matches!(mount.kind, MountKind::Remote));
        assert_eq!(
            mount.addr.as_deref(),
            Some("tenant.orlop-server.example.ts.net:7879"),
        );
    }

    #[test]
    fn repository_example_configs_load() {
        Config::load(Path::new("config.example.yaml")).unwrap();
        Config::load(Path::new("config.local.yaml")).unwrap();
    }

    #[test]
    fn default_config_yaml_parses_with_policy_readonly_false() {
        // Regression for #157: line-continuation `\` in the format! literal
        // was eating the leading whitespace on `readonly: false`, parsing
        // as {policy: null, readonly: false} — making fresh-user mounts ro.
        let body = default_config_yaml(Path::new("/home/test"));
        let parsed: serde_yaml::Value = serde_yaml::from_str(&body).unwrap();
        let policy = parsed.get("policy").expect("policy key present");
        assert!(
            policy.is_mapping(),
            "policy must be a mapping, got: {policy:?}\n---\n{body}",
        );
        let readonly = policy
            .get("readonly")
            .expect("policy.readonly present")
            .as_bool()
            .expect("policy.readonly is bool");
        assert!(!readonly, "policy.readonly must default to false");
        // And the spurious top-level `readonly` key must NOT exist.
        assert!(
            parsed.get("readonly").is_none(),
            "no top-level readonly key (would mean the indent broke again)",
        );
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

        cfg.validate().unwrap();
        assert!(cfg.hosted.is_some());
        assert_eq!(
            cfg.hosted.as_ref().unwrap().control_plane_url.as_deref(),
            Some("https://control.orlop.example"),
        );
    }
}
