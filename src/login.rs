//! Credential storage and token management for the hosted mount paths.
//!
//! Persists the control-plane URL plus an agent's bearer / refresh token to
//! `~/.config/orlop/credentials.json` with mode `0600`, and exposes
//! [`TokenManager`], which hands out a fresh access token to the enroll path
//! (`/agent/enroll`) — refreshing it against `/auth/token/refresh` when it is
//! close to expiry. There is no interactive login: credentials are minted out
//! of band (an enroll token via `orlop mount --from-env`, or a refresh-token
//! exchange) and dropped here for the mount engine to consume.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context};
use chrono::{DateTime, Utc};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};

use crate::util;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credentials {
    pub access_token: String,
    #[serde(rename = "access_expires_at", alias = "expires_at")]
    pub access_expires_at: DateTime<Utc>,
    pub refresh_token: String,
    pub refresh_expires_at: DateTime<Utc>,
    pub control_plane_url: String,
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub allocation_id: Option<String>,
    #[serde(default)]
    pub size_bytes: Option<u64>,
    #[serde(default)]
    pub server_addr: Option<String>,
}

impl Credentials {
    /// `control_plane_url` with any trailing slashes stripped — the canonical
    /// form for joining `/auth/...` / `/agent/...` paths.
    pub fn control_plane_base(&self) -> &str {
        self.control_plane_url.trim_end_matches('/')
    }

    /// Minimal credentials for the in-pod env-driven mount (`orlop mount
    /// --from-env`): a control-plane URL plus a control-plane-minted,
    /// agent-scoped enroll bearer token. The token is used verbatim as the
    /// `access_token` for `POST /agent/enroll`; there is no refresh token, so
    /// `access_expires_at` is parked far in the future to keep
    /// [`TokenManager::access_token`] from ever attempting a refresh, and
    /// `refresh_expires_at` is left in the past so an accidental refresh fails
    /// fast with a clear message rather than hitting the network.
    pub fn for_enroll(control_plane_url: String, enroll_token: String) -> Self {
        let now = Utc::now();
        Self {
            access_token: enroll_token,
            access_expires_at: now + chrono::Duration::days(3650),
            refresh_token: String::new(),
            refresh_expires_at: now - chrono::Duration::seconds(1),
            control_plane_url,
            user_id: None,
            allocation_id: None,
            size_bytes: None,
            server_addr: None,
        }
    }
}

pub fn credentials_path() -> anyhow::Result<PathBuf> {
    Ok(util::home_dir()?.join(".config/orlop/credentials.json"))
}

/// Load the credentials file, bailing with a re-enroll hint if it's missing.
/// Returns the path alongside so callers that need to pass it back to
/// `TokenManager::new` don't have to recompute it.
pub fn require_credentials() -> anyhow::Result<(PathBuf, Credentials)> {
    let path = credentials_path()?;
    let creds = load(&path)?.ok_or_else(|| {
        anyhow!(
            "no credentials at {} — the host must re-enroll the agent \
             (mint a fresh enroll token and re-run `orlop mount --from-env`)",
            path.display()
        )
    })?;
    Ok((path, creds))
}

pub fn load(path: &Path) -> anyhow::Result<Option<Credentials>> {
    match fs::read(path) {
        Ok(bytes) => {
            // Treat an empty file the same as a missing one. A `--credentials
            // <path>` override is commonly driven with `mktemp`, which returns
            // a fresh 0-byte file; a strict parse would error out before the
            // mount path could populate it.
            if bytes.is_empty() {
                return Ok(None);
            }
            let creds: Credentials = serde_json::from_slice(&bytes)
                .with_context(|| format!("parse credentials at {}", path.display()))?;
            Ok(Some(creds))
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).with_context(|| format!("read credentials at {}", path.display())),
    }
}

/// Best-effort `chmod 0700` on the credentials parent directory.
///
/// The file itself is opened with mode `0o600`, which is the actual
/// confidentiality boundary; the parent chmod is defense-in-depth for the
/// default `~/.config/orlop` case where we own and effectively created the
/// dir. When `--credentials` points at a system-shared directory we don't
/// own (e.g. `/tmp`), we'd either fail with EPERM or wrongly tighten a dir
/// other users rely on — so skip the chmod and rely on the file mode. See
/// issue #180.
fn tighten_parent_perms(parent: &Path) -> anyhow::Result<()> {
    let meta = fs::metadata(parent)
        .with_context(|| format!("stat {}", parent.display()))?;
    let our_uid = unsafe { libc::getuid() };
    if meta.uid() != our_uid {
        return Ok(());
    }
    let mut perms = meta.permissions();
    perms.set_mode(0o700);
    fs::set_permissions(parent, perms)
        .with_context(|| format!("chmod 0700 {}", parent.display()))
}

pub fn save(path: &Path, creds: &Credentials) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        tighten_parent_perms(parent)?;
    }
    let body = serde_json::to_vec_pretty(creds).context("serialize credentials")?;
    let tmp = tmp_path(path);
    {
        let mut f = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("open {}", tmp.display()))?;
        f.write_all(&body)
            .with_context(|| format!("write {}", tmp.display()))?;
        f.sync_all()
            .with_context(|| format!("fsync {}", tmp.display()))?;
    }
    fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_else(|| std::ffi::OsString::from("credentials.json"));
    name.push(".tmp");
    path.with_file_name(name)
}

#[derive(Deserialize)]
struct TokenOk {
    access_token: String,
    #[serde(default)]
    access_expires_at: Option<DateTime<Utc>>,
    refresh_token: String,
    refresh_expires_at: DateTime<Utc>,
    #[serde(default)]
    control_plane_url: Option<String>,
    #[serde(default)]
    user_id: Option<String>,
    #[serde(default)]
    allocation_id: Option<String>,
    #[serde(default)]
    size_bytes: Option<u64>,
    #[serde(default)]
    expires_in: i64,
}

#[derive(Deserialize)]
struct OAuthErr {
    error: String,
    #[serde(default)]
    error_description: Option<String>,
}

pub struct TokenManager {
    path: PathBuf,
    creds: Credentials,
    client: reqwest::blocking::Client,
    safety_window: chrono::Duration,
}

impl TokenManager {
    pub fn load(path: PathBuf) -> anyhow::Result<Self> {
        let creds = load(&path)?.ok_or_else(|| {
            anyhow!(
                "no credentials found; the host must re-enroll the agent \
                 (mint a fresh enroll token and re-run `orlop mount --from-env`)"
            )
        })?;
        Ok(Self::new(path, creds))
    }

    pub fn new(path: PathBuf, creds: Credentials) -> Self {
        let client = util::http_client(Duration::from_secs(30))
            .expect("failed to build token refresh HTTP client");
        Self {
            path,
            creds,
            client,
            safety_window: chrono::Duration::minutes(5),
        }
    }

    pub fn access_token(&mut self) -> anyhow::Result<String> {
        let now = Utc::now();
        if self.creds.access_expires_at > now + self.safety_window {
            return Ok(self.creds.access_token.clone());
        }
        self.refresh()
    }

    pub fn credentials(&self) -> &Credentials {
        &self.creds
    }

    fn refresh(&mut self) -> anyhow::Result<String> {
        if self.creds.refresh_expires_at <= Utc::now() {
            bail!(
                "refresh token expired locally at {}; the host must re-enroll \
                 the agent (mint a fresh enroll token and re-run \
                 `orlop mount --from-env`)",
                self.creds.refresh_expires_at.to_rfc3339()
            );
        }
        let base = self.creds.control_plane_base().to_string();
        let resp = self
            .client
            .post(format!("{base}/auth/token/refresh"))
            .bearer_auth(&self.creds.refresh_token)
            .send()
            .with_context(|| format!("POST {base}/auth/token/refresh"))?;
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            let err: OAuthErr = serde_json::from_str(&body).unwrap_or_else(|_| OAuthErr {
                error: format!("http_{}", status.as_u16()),
                error_description: Some(body.clone()),
            });
            let detail = err.error_description.as_deref().unwrap_or("no detail");
            bail!(
                "control plane rejected refresh: {} {} ({}); the host must \
                 re-enroll the agent (mint a fresh enroll token and re-run \
                 `orlop mount --from-env`)",
                status.as_u16(),
                err.error,
                detail
            );
        }
        if !status.is_success() {
            bail!("token refresh failed: {status} {body}");
        }
        let tr: TokenOk = serde_json::from_str(&body).context("decode refresh response")?;
        let access_expires_at = tr
            .access_expires_at
            .unwrap_or_else(|| Utc::now() + chrono::Duration::seconds(tr.expires_in));
        self.creds = Credentials {
            access_token: tr.access_token,
            access_expires_at,
            refresh_token: tr.refresh_token,
            refresh_expires_at: tr.refresh_expires_at,
            control_plane_url: tr.control_plane_url.unwrap_or(base),
            user_id: self.creds.user_id.clone().or(tr.user_id),
            allocation_id: self.creds.allocation_id.clone().or(tr.allocation_id),
            size_bytes: self.creds.size_bytes.or(tr.size_bytes),
            server_addr: self.creds.server_addr.clone(),
        };
        save(&self.path, &self.creds)?;
        Ok(self.creds.access_token.clone())
    }

    pub fn update_allocation(
        &mut self,
        allocation_id: Option<String>,
        size_bytes: Option<u64>,
    ) -> anyhow::Result<()> {
        let mut changed = false;
        if allocation_id.is_some() && self.creds.allocation_id != allocation_id {
            self.creds.allocation_id = allocation_id;
            changed = true;
        }
        if size_bytes.is_some() && self.creds.size_bytes != size_bytes {
            self.creds.size_bytes = size_bytes;
            changed = true;
        }
        if changed {
            save(&self.path, &self.creds)?;
        }
        Ok(())
    }

    pub fn update_server_addr(&mut self, server_addr: &str) -> anyhow::Result<()> {
        if self.creds.server_addr.as_deref() == Some(server_addr) {
            return Ok(());
        }
        self.creds.server_addr = Some(server_addr.to_string());
        save(&self.path, &self.creds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;
    use std::os::unix::fs::MetadataExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    struct Tmp(PathBuf);

    impl Tmp {
        fn new() -> Self {
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let p =
                std::env::temp_dir().join(format!("orlop-login-test-{}-{}", std::process::id(), n));
            fs::create_dir_all(&p).unwrap();
            Self(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn sample(now: DateTime<Utc>) -> Credentials {
        Credentials {
            access_token: "tok_xyz".into(),
            access_expires_at: now + chrono::Duration::hours(1),
            refresh_token: "rt_xyz".into(),
            refresh_expires_at: now + chrono::Duration::days(30),
            control_plane_url: "https://control.example".into(),
            user_id: Some("user_123".into()),
            allocation_id: Some("alloc_123".into()),
            size_bytes: Some(5 * 1024 * 1024 * 1024),
            server_addr: Some("data-srv-1.example.com:6363".into()),
        }
    }

    #[test]
    fn load_missing_returns_none() {
        let dir = Tmp::new();
        let path = dir.path().join("missing.json");
        assert!(load(&path).unwrap().is_none());
    }

    #[test]
    fn load_empty_file_returns_none() {
        // A `--credentials $(mktemp)` override lands here: mktemp creates a
        // 0-byte file that we must treat as "no credentials yet" so the mount
        // path can populate it.
        let dir = Tmp::new();
        let path = dir.path().join("empty.json");
        fs::write(&path, b"").unwrap();
        assert!(load(&path).unwrap().is_none());
    }

    #[test]
    fn save_writes_file_with_mode_0600() {
        let dir = Tmp::new();
        let path = dir.path().join("creds.json");
        save(&path, &sample(Utc::now())).unwrap();
        let mode = fs::metadata(&path).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o600, "got mode {mode:o}");
    }

    #[test]
    fn save_load_roundtrip_preserves_fields() {
        let dir = Tmp::new();
        let path = dir.path().join("creds.json");
        let now = Utc::now();
        let creds = sample(now);
        save(&path, &creds).unwrap();
        let got = load(&path).unwrap().unwrap();
        assert_eq!(got.access_token, creds.access_token);
        assert_eq!(got.refresh_token, creds.refresh_token);
        assert_eq!(got.control_plane_url, creds.control_plane_url);
        assert_eq!(got.access_expires_at, creds.access_expires_at);
        assert_eq!(got.refresh_expires_at, creds.refresh_expires_at);
    }

    #[test]
    fn save_overwrites_existing_atomically() {
        let dir = Tmp::new();
        let path = dir.path().join("creds.json");
        save(&path, &sample(Utc::now())).unwrap();
        let mut updated = sample(Utc::now());
        updated.access_token = "tok_new".into();
        save(&path, &updated).unwrap();
        let got = load(&path).unwrap().unwrap();
        assert_eq!(got.access_token, "tok_new");
        let leftover = path.with_file_name("creds.json.tmp");
        assert!(
            !leftover.exists(),
            "tmp file leaked: {}",
            leftover.display()
        );
    }

    #[test]
    fn save_creates_parent_with_mode_0700() {
        let dir = Tmp::new();
        let nested = dir.path().join("config/orlop");
        let path = nested.join("credentials.json");
        save(&path, &sample(Utc::now())).unwrap();
        let mode = fs::metadata(&nested).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o700, "parent mode {mode:o}");
    }

    // When the user passes --credentials at a path whose parent is system-
    // shared (e.g. /tmp), the saved file's 0600 mode is the actual
    // confidentiality boundary; chmod'ing the parent would either fail with
    // EPERM or wrongly affect other users. The saved file still gets 0600.
    // See issue #180.
    #[test]
    fn save_skips_parent_chmod_when_we_dont_own_it() {
        // /tmp is the canonical system-shared dir; on every Unix it's
        // mode 1777 and owned by root.
        let parent = std::path::Path::new("/tmp");
        let parent_mode_before = fs::metadata(parent).unwrap().mode() & 0o7777;
        let our_uid = unsafe { libc::getuid() };
        let parent_uid = fs::metadata(parent).unwrap().uid();
        if parent_uid == our_uid {
            // Sandbox or container where /tmp happens to be owned by us;
            // the test premise doesn't hold here, so the test is vacuous.
            return;
        }

        let path = parent.join(format!("orlop-test-{}.json", std::process::id()));
        let _cleanup = scopeguard(|| {
            let _ = fs::remove_file(&path);
        });
        save(&path, &sample(Utc::now())).expect("save should not fail on system-shared parent");

        let file_mode = fs::metadata(&path).unwrap().mode() & 0o777;
        assert_eq!(file_mode, 0o600, "file mode {file_mode:o}");

        let parent_mode_after = fs::metadata(parent).unwrap().mode() & 0o7777;
        assert_eq!(
            parent_mode_before, parent_mode_after,
            "parent mode changed: {parent_mode_before:o} -> {parent_mode_after:o}",
        );
    }

    // Tiny scopeguard equivalent so we don't pull in a dep just for the test.
    fn scopeguard<F: FnOnce()>(f: F) -> impl Drop {
        struct G<F: FnOnce()>(Option<F>);
        impl<F: FnOnce()> Drop for G<F> {
            fn drop(&mut self) {
                if let Some(f) = self.0.take() {
                    f();
                }
            }
        }
        G(Some(f))
    }

    #[test]
    fn token_manager_reuses_fresh_access_token() {
        let dir = Tmp::new();
        let path = dir.path().join("creds.json");
        let creds = sample(Utc::now());
        let mut mgr = TokenManager::new(path, creds.clone());
        assert_eq!(mgr.access_token().unwrap(), creds.access_token);
    }

    /// Spawn a one-shot mock control plane on `listener`. Asserts the incoming
    /// request is `POST /auth/token/refresh` with `Authorization: Bearer rt_old`
    /// (every test below uses the same fixture refresh token).
    fn serve_once(listener: TcpListener, status_line: &'static str, body: &'static str) {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut request_line = String::new();
        reader.read_line(&mut request_line).unwrap();
        let mut saw_auth = false;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if line == "\r\n" {
                break;
            }
            if line
                .trim()
                .eq_ignore_ascii_case("authorization: Bearer rt_old")
            {
                saw_auth = true;
            }
        }
        assert!(
            request_line.starts_with("POST /auth/token/refresh "),
            "unexpected request line: {request_line}"
        );
        assert!(saw_auth, "missing refresh bearer token");
        write!(
            stream,
            "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
    }

    fn creds_about_to_expire(url: String) -> Credentials {
        let now = Utc::now();
        Credentials {
            access_token: "at_old".into(),
            access_expires_at: now + chrono::Duration::minutes(1),
            refresh_token: "rt_old".into(),
            refresh_expires_at: now + chrono::Duration::days(1),
            control_plane_url: url,
            user_id: None,
            allocation_id: None,
            size_bytes: None,
            server_addr: None,
        }
    }

    #[test]
    fn token_manager_refreshes_and_persists_expiring_access_token() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let join = thread::spawn(move || {
            serve_once(
                listener,
                "200 OK",
                r#"{"access_token":"at_new","access_expires_at":"2026-04-30T13:00:00Z","refresh_token":"rt_new","refresh_expires_at":"2026-05-30T12:00:00Z","control_plane_url":"http://control.example","token_type":"Bearer","expires_in":3600}"#,
            );
        });

        let dir = Tmp::new();
        let path = dir.path().join("creds.json");
        save(&path, &creds_about_to_expire(url)).unwrap();
        let mut mgr = TokenManager::load(path.clone()).unwrap();
        assert_eq!(mgr.access_token().unwrap(), "at_new");
        assert_eq!(mgr.credentials().refresh_token, "rt_new");
        let saved = load(&path).unwrap().unwrap();
        assert_eq!(saved.access_token, "at_new");
        assert_eq!(saved.refresh_token, "rt_new");
        join.join().unwrap();
    }

    #[test]
    fn token_manager_surfaces_invalid_token_on_401() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let join = thread::spawn(move || {
            serve_once(
                listener,
                "401 Unauthorized",
                r#"{"error":"invalid_token","error_description":"token revoked"}"#,
            );
        });

        let mut mgr = TokenManager::new(PathBuf::from("/dev/null"), creds_about_to_expire(url));
        let err = mgr.access_token().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("401"), "got: {msg}");
        assert!(msg.contains("invalid_token"), "got: {msg}");
        assert!(msg.contains("token revoked"), "got: {msg}");
        assert!(msg.contains("re-enroll"), "got: {msg}");
        join.join().unwrap();
    }

    #[test]
    fn token_manager_surfaces_access_denied_on_403() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let join = thread::spawn(move || {
            serve_once(listener, "403 Forbidden", r#"{"error":"access_denied"}"#);
        });

        let mut mgr = TokenManager::new(PathBuf::from("/dev/null"), creds_about_to_expire(url));
        let err = mgr.access_token().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("403"), "got: {msg}");
        assert!(msg.contains("access_denied"), "got: {msg}");
        assert!(msg.contains("re-enroll"), "got: {msg}");
        join.join().unwrap();
    }

    #[test]
    fn token_manager_local_refresh_expired_includes_timestamp() {
        let now = Utc::now();
        let creds = Credentials {
            access_token: "at_old".into(),
            access_expires_at: now - chrono::Duration::seconds(1),
            refresh_token: "rt_old".into(),
            refresh_expires_at: now - chrono::Duration::seconds(1),
            control_plane_url: "http://127.0.0.1:1".into(),
            user_id: None,
            allocation_id: None,
            size_bytes: None,
            server_addr: None,
        };
        let mut mgr = TokenManager::new(PathBuf::from("/dev/null"), creds);
        let err = mgr.access_token().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("refresh token expired locally"), "got: {msg}");
        assert!(msg.contains("re-enroll"), "got: {msg}");
    }
}
