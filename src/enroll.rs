//! `orlop mount` enrollment against the hosted control plane.
//!
//! `enroll` POSTs `/agent/enroll` with the bearer token persisted by `orlop
//! login`, writes the returned cert / key / CA chain to disk under
//! `~/.config/orlop/{cert,key,ca}.pem` (mode 0600), and returns the metadata
//! the mount handler needs to dial the per-tenant `orlop-server` over mTLS.
//! `shred` overwrites and removes those files on `orlop unmount`.

use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::backend::TlsIdentity;
use crate::login::Credentials;
use crate::util;

const FILE_CERT: &str = "cert.pem";
const FILE_KEY: &str = "key.pem";
const FILE_CA: &str = "ca.pem";
/// Pre-enrolled mode sidecar. When this file exists in `cert_dir`, the
/// mount path skips the HTTP `/agent/enroll` round-trip entirely and treats
/// the cert/key already on disk as the session identity (Phase 2 anonymous
/// sandbox: control mints the leaf cert and the spawner bundles it in).
pub const FILE_ENROLLMENT: &str = "enrollment.json";

#[derive(Debug, Clone)]
pub struct EnrolledCert {
    pub cert_dir: PathBuf,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub ca_path: PathBuf,
    pub server_addr: String,
    pub cert_serial: String,
    pub expires_at: DateTime<Utc>,
    pub allocation_id: Option<String>,
    pub size_bytes: Option<u64>,
}

/// `~/.config/orlop`.
pub fn default_cert_dir() -> anyhow::Result<PathBuf> {
    Ok(util::home_dir()?.join(".config/orlop"))
}

#[derive(Deserialize)]
struct EnrollResp {
    client_cert_pem: String,
    client_key_pem: String,
    ca_chain_pem: String,
    server_addr: String,
    expires_at: DateTime<Utc>,
    #[serde(default)]
    allocation_id: Option<String>,
    #[serde(default)]
    size_bytes: Option<u64>,
}

/// POST `/agent/enroll` with the credentials from `orlop login`, persist the
/// returned PEMs to `cert_dir`, and return metadata for the dial.
pub fn enroll(creds: &Credentials, cert_dir: &Path) -> anyhow::Result<EnrolledCert> {
    let url = format!("{}/agent/enroll", creds.control_plane_base());
    let client = util::http_client(Duration::from_secs(30))?;

    let resp = post_enroll(&client, &url, &creds.access_token)?;
    let status = resp.status();

    if status == reqwest::StatusCode::UNAUTHORIZED {
        bail!("/agent/enroll returned 401 — run `orlop login` to refresh credentials");
    }
    if status == reqwest::StatusCode::FORBIDDEN {
        // orlop-control returns `{"error":"access_denied","error_description":"<reason>"}`.
        // The description disambiguates revoke vs. suspension so we surface the
        // recovery the user actually needs.
        let desc = read_oauth_error_description(resp);
        let hint = match desc.as_deref() {
            Some("allocation_revoked") => {
                "your allocation was revoked. Visit https://example.com/dashboard \
                or run `orlop login` to allocate a new disk"
            }
            Some("allocation_not_found") => {
                "the allocation cached locally is no longer accessible. \
                Run `orlop login` to re-enroll"
            }
            Some("tenant_suspended") => {
                "tenant is suspended; contact support@example.com"
            }
            Some("tenant_not_found") => {
                "the tenant on this credential is unknown — run `orlop login --force`"
            }
            _ => "access denied (tenant or user suspended)",
        };
        bail!("/agent/enroll returned 403 — {hint}");
    }
    if status == reqwest::StatusCode::SERVICE_UNAVAILABLE {
        let retry_after = parse_retry_after(&resp);
        let secs = retry_after.unwrap_or(2).min(30);
        std::thread::sleep(Duration::from_secs(secs));
        let retry = post_enroll(&client, &url, &creds.access_token)?;
        let retry_status = retry.status();
        if !retry_status.is_success() {
            bail!(
                "/agent/enroll still {retry_status} after {secs}s Retry-After — server VM unavailable"
            );
        }
        let body: EnrollResp = retry.json().context("decode enroll retry response")?;
        return persist(cert_dir, body);
    }
    if !status.is_success() {
        let body = resp.text().unwrap_or_default();
        bail!("/agent/enroll failed: {status} {body}");
    }

    let body: EnrollResp = resp.json().context("decode enroll response")?;
    persist(cert_dir, body)
}

fn post_enroll(
    client: &reqwest::blocking::Client,
    url: &str,
    token: &str,
) -> anyhow::Result<reqwest::blocking::Response> {
    client
        .post(url)
        .bearer_auth(token)
        .send()
        .with_context(|| format!("POST {url}"))
}

fn read_oauth_error_description(resp: reqwest::blocking::Response) -> Option<String> {
    #[derive(Deserialize)]
    struct OAuthErr {
        #[serde(default)]
        error_description: Option<String>,
    }
    resp.json::<OAuthErr>().ok().and_then(|e| e.error_description)
}

fn parse_retry_after(resp: &reqwest::blocking::Response) -> Option<u64> {
    resp.headers()
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .parse()
        .ok()
}

fn persist(cert_dir: &Path, body: EnrollResp) -> anyhow::Result<EnrolledCert> {
    create_secure_dir(cert_dir)?;
    let cert_path = cert_dir.join(FILE_CERT);
    let key_path = cert_dir.join(FILE_KEY);
    let ca_path = cert_dir.join(FILE_CA);
    write_secret(&cert_path, body.client_cert_pem.as_bytes())?;
    write_secret(&key_path, body.client_key_pem.as_bytes())?;
    write_secret(&ca_path, body.ca_chain_pem.as_bytes())?;
    let cert_serial = parse_serial(body.client_cert_pem.as_bytes());
    Ok(EnrolledCert {
        cert_dir: cert_dir.to_path_buf(),
        cert_path,
        key_path,
        ca_path,
        server_addr: body.server_addr,
        cert_serial,
        expires_at: body.expires_at,
        allocation_id: body.allocation_id,
        size_bytes: body.size_bytes,
    })
}

fn create_secure_dir(dir: &Path) -> anyhow::Result<()> {
    fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let mut perms = fs::metadata(dir)
        .with_context(|| format!("stat {}", dir.display()))?
        .permissions();
    perms.set_mode(0o700);
    fs::set_permissions(dir, perms).with_context(|| format!("chmod 0700 {}", dir.display()))?;
    Ok(())
}

fn write_secret(path: &Path, body: &[u8]) -> anyhow::Result<()> {
    let tmp = tmp_path(path);
    {
        let mut f = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("open {}", tmp.display()))?;
        f.write_all(body)
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
        .unwrap_or_else(|| std::ffi::OsString::from("orlop.tmp"));
    name.push(".tmp");
    path.with_file_name(name)
}

/// Pre-enrolled cert sidecar written by the spawner / control for Phase 2
/// anonymous sessions. Mirrors the subset of `EnrolledCert` fields needed
/// to drive the mount path; `expires_at` is omitted because the session
/// (5 min) expires well before the cert (5 min, same TTL).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentSidecar {
    pub allocation_id: String,
    pub server_addr: String,
    pub cert_serial: String,
    #[serde(default)]
    pub size_bytes: Option<u64>,
    /// RFC3339 UTC; informational only — the renewal task is suppressed
    /// in pre-enrolled mode (session TTL <= cert TTL by construction).
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Load an `enrollment.json` sidecar from `cert_dir`. Returns `Ok(None)`
/// when the file is absent — that signals the caller to fall back to the
/// normal device-flow + `/agent/enroll` path. Returns `Err` only on a
/// present-but-unparseable file (corruption / wrong shape).
pub fn load_enrollment_sidecar(cert_dir: &Path) -> anyhow::Result<Option<EnrolledCert>> {
    let path = cert_dir.join(FILE_ENROLLMENT);
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("read {}", path.display()))?;
    let parsed: EnrollmentSidecar = serde_json::from_str(&raw)
        .with_context(|| format!("parse {}", path.display()))?;
    // Defaulted to 1h ahead when the sidecar omits expires_at; this field
    // is only read by `orlop status`. The renewal task does NOT run in
    // pre-enrolled mode (see CertManager::start).
    let expires_at = parsed.expires_at.unwrap_or_else(|| Utc::now() + chrono::Duration::hours(1));
    Ok(Some(EnrolledCert {
        cert_dir: cert_dir.to_path_buf(),
        cert_path: cert_dir.join(FILE_CERT),
        key_path: cert_dir.join(FILE_KEY),
        ca_path: cert_dir.join(FILE_CA),
        server_addr: parsed.server_addr,
        cert_serial: parsed.cert_serial,
        expires_at,
        allocation_id: Some(parsed.allocation_id),
        size_bytes: parsed.size_bytes,
    }))
}

pub fn cert_serial_from_dir(cert_dir: &Path) -> anyhow::Result<String> {
    let cert_path = cert_dir.join(FILE_CERT);
    let cert_pem = fs::read(&cert_path).with_context(|| format!("read {}", cert_path.display()))?;
    Ok(parse_serial(&cert_pem))
}

fn parse_serial(cert_pem: &[u8]) -> String {
    use x509_parser::pem::parse_x509_pem;
    let Ok((_, pem)) = parse_x509_pem(cert_pem) else {
        return "unknown".to_string();
    };
    let Ok(cert) = pem.parse_x509() else {
        return "unknown".to_string();
    };
    // Match Go's `hex.EncodeToString(big.Int.Bytes())`: byte-wise encoding,
    // preserving the leading nibble of the first byte. `format!("{:x}", BigUint)`
    // would drop a leading zero nibble (~50% of certs), causing the server's
    // `WHERE lower(cert_serial) = lower($1)` lookup to miss and return 401.
    cert.tbs_certificate
        .serial
        .to_bytes_be()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

/// Best-effort overwrite of cert / key / CA files, then unlink. Linux + macOS;
/// safe to call when files do not exist.
pub fn shred(cert_dir: &Path) -> anyhow::Result<()> {
    for name in [FILE_CERT, FILE_KEY, FILE_CA, FILE_ENROLLMENT] {
        let path = cert_dir.join(name);
        if !path.exists() {
            continue;
        }
        if let Err(err) = shred_file(&path) {
            eprintln!("warning: shred {} failed: {err:#}", path.display());
        }
    }
    Ok(())
}

fn shred_file(path: &Path) -> anyhow::Result<()> {
    // Concurrent shredders (mount-process Drop + explicit `orlop unmount`)
    // can race on the same cert dir. Treat ENOENT at any stage as
    // already-shredded — that's the desired end state anyway.
    let len = match fs::metadata(path) {
        Ok(meta) => meta.len(),
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err).with_context(|| format!("stat {}", path.display())),
    };
    {
        let mut f = match fs::OpenOptions::new().write(true).open(path) {
            Ok(f) => f,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(err) => {
                return Err(err).with_context(|| format!("open {} for shred", path.display()))
            }
        };
        let mut buf = vec![0u8; 4096];
        let mut written = 0u64;
        let mut rand = fs::File::open("/dev/urandom").ok();
        while written < len {
            let take = ((len - written) as usize).min(buf.len());
            if let Some(src) = rand.as_mut() {
                if src.read_exact(&mut buf[..take]).is_err() {
                    rand = None;
                    buf[..take].fill(0);
                }
            } else {
                buf[..take].fill(0);
            }
            f.write_all(&buf[..take])
                .with_context(|| format!("write shred bytes {}", path.display()))?;
            written += take as u64;
        }
        f.sync_all()
            .with_context(|| format!("fsync {}", path.display()))?;
    }
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("remove {}", path.display())),
    }
}

pub fn load_identity(enrolled: &EnrolledCert) -> anyhow::Result<TlsIdentity> {
    load_identity_from_paths(&enrolled.cert_path, &enrolled.key_path, &enrolled.ca_path)
}

pub fn load_identity_from_dir(cert_dir: &Path) -> anyhow::Result<TlsIdentity> {
    load_identity_from_paths(
        &cert_dir.join(FILE_CERT),
        &cert_dir.join(FILE_KEY),
        &cert_dir.join(FILE_CA),
    )
}

fn load_identity_from_paths(
    cert_path: &Path,
    key_path: &Path,
    ca_path: &Path,
) -> anyhow::Result<TlsIdentity> {
    let cert_pem = fs::read(cert_path).with_context(|| format!("read {}", cert_path.display()))?;
    let key_pem = fs::read(key_path).with_context(|| format!("read {}", key_path.display()))?;
    let ca_pem = fs::read(ca_path).with_context(|| format!("read {}", ca_path.display()))?;
    Ok(TlsIdentity {
        cert_pem,
        key_pem,
        ca_pem,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    struct Tmp(PathBuf);

    impl Tmp {
        fn new() -> Self {
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let p =
                std::env::temp_dir().join(format!("orlop-enroll-test-{}-{}", std::process::id(), n));
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

    fn sample_resp() -> EnrollResp {
        EnrollResp {
            client_cert_pem: SAMPLE_CERT.to_string(),
            client_key_pem: "-----BEGIN PRIVATE KEY-----\nMIIFAKE\n-----END PRIVATE KEY-----\n"
                .to_string(),
            ca_chain_pem: "-----BEGIN CERTIFICATE-----\nMIICA\n-----END CERTIFICATE-----\n"
                .to_string(),
            server_addr: "tenant-acme.orlop.example.com".to_string(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            allocation_id: Some("alloc_123".to_string()),
            size_bytes: Some(5 * 1024 * 1024 * 1024),
        }
    }

    // Real self-signed cert with serial 0x0d. Generated once with
    //   openssl req -x509 -nodes -newkey rsa:2048 -set_serial 13 \
    //     -subj '/CN=orlop-test' -keyout key.pem -out cert.pem
    // We only need it to exercise parse_serial; the key is discarded.
    const SAMPLE_CERT: &str = "-----BEGIN CERTIFICATE-----
MIIC9DCCAdygAwIBAgIBDTANBgkqhkiG9w0BAQsFADATMREwDwYDVQQDDAhhZGct
dGVzdDAeFw0yNjA0MzAwMjA0MzJaFw0yNjA1MDEwMjA0MzJaMBMxETAPBgNVBAMM
CGFkZy10ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAouvBzEGc
sh6si4RXMvEGFKnpiFo6ekW9juNCd9a11iXUHDSNsxgIOVxExqIgFcRytDkWEquG
3YAH+H/dy1010BLhJAH9yMaW3XI3/Un2HMq+jG1Jpm4GzJodDGsTwSzibzp4gEsL
46yqoz+yAp+/L128OL1/RkBOP62OxlMce21lnLOTt6eAt6xiJD0A/E3gPzsc/9iA
g6tLrVuZjm2TfYh+6b0hHqI6zfKcp2VUv783o21GIQW2Qv7TGgP+tFg1fAWgW89X
SVqSiq3WG9+X0ytg65N2DAv/ejVU/7z/zwikDnvu6jH7nB3dTZmF6w5Gt2/KPtiN
BVR40QZRjcdC7wIDAQABo1MwUTAdBgNVHQ4EFgQUnx+cZJZ4rzPoYTturQGp2soW
UIIwHwYDVR0jBBgwFoAUnx+cZJZ4rzPoYTturQGp2soWUIIwDwYDVR0TAQH/BAUw
AwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAIvhRVdf5OFVAHvHjBghwMKHpf1cUL2Or
lGtPZ/A/0nZnSDSUoxPuom3BNu/oBb9jrK+epXVEMWdJXf1yO11CQiQy3DrgI1Dn
HIOUFUnsnPX+AhxZfadX6LW6P6k11slE+FqhqDyZy7NC5du0L2KU4ehdsrd0jNVy
/+I0PRgZMY19kopjcHWgGGSm7lXmHofg+IvgxkYRFfxEG420Tuw/yZ4icj9L8m9B
RRntjQih7hTQLClxC88VzCOIZo1yGc57P+o5LU0OfB82xEWHhGXUDQjtqaoANjPw
gz6ouG0MNrc8wNu++RoOct9R7cQmNOQvk+4qQCEYZXiqKwffFEz0xg==
-----END CERTIFICATE-----
";

    #[test]
    fn persist_writes_three_files_with_mode_0600() {
        let dir = Tmp::new();
        let enrolled = persist(dir.path(), sample_resp()).unwrap();

        assert_eq!(enrolled.cert_path, dir.path().join("cert.pem"));
        assert_eq!(enrolled.key_path, dir.path().join("key.pem"));
        assert_eq!(enrolled.ca_path, dir.path().join("ca.pem"));
        for path in [&enrolled.cert_path, &enrolled.key_path, &enrolled.ca_path] {
            let mode = fs::metadata(path).unwrap().mode() & 0o777;
            assert_eq!(mode, 0o600, "{} mode {mode:o}", path.display());
        }
        let dir_mode = fs::metadata(dir.path()).unwrap().mode() & 0o777;
        assert_eq!(dir_mode, 0o700);
    }

    #[test]
    fn persist_overwrites_atomically_no_tmp_leak() {
        let dir = Tmp::new();
        persist(dir.path(), sample_resp()).unwrap();
        persist(dir.path(), sample_resp()).unwrap();
        assert!(!dir.path().join("cert.pem.tmp").exists());
        assert!(!dir.path().join("key.pem.tmp").exists());
        assert!(!dir.path().join("ca.pem.tmp").exists());
    }

    #[test]
    fn parse_serial_extracts_hex_serial() {
        let serial = parse_serial(SAMPLE_CERT.as_bytes());
        assert_eq!(serial, "0d", "expected 0x0d byte-encoded as \"0d\", got {serial}");
    }

    #[test]
    fn parse_serial_returns_unknown_on_garbage() {
        assert_eq!(parse_serial(b"not a pem"), "unknown");
    }

    #[test]
    fn shred_removes_files() {
        let dir = Tmp::new();
        persist(dir.path(), sample_resp()).unwrap();
        shred(dir.path()).unwrap();
        assert!(!dir.path().join("cert.pem").exists());
        assert!(!dir.path().join("key.pem").exists());
        assert!(!dir.path().join("ca.pem").exists());
    }

    #[test]
    fn shred_is_safe_when_files_missing() {
        let dir = Tmp::new();
        shred(dir.path()).unwrap();
    }

    #[test]
    fn shred_is_safe_when_files_disappear_mid_run() {
        // Simulates the harness race: two shredders, one wins per file.
        // shred_file must absorb ENOENT at metadata, open, and remove.
        let dir = Tmp::new();
        persist(dir.path(), sample_resp()).unwrap();
        // Pre-delete one file out from under shred so it hits NotFound at
        // the metadata call.
        std::fs::remove_file(dir.path().join("cert.pem")).unwrap();
        shred(dir.path()).unwrap();
        assert!(!dir.path().join("cert.pem").exists());
        assert!(!dir.path().join("key.pem").exists());
        assert!(!dir.path().join("ca.pem").exists());
    }

    #[test]
    fn load_identity_reads_persisted_pems() {
        let dir = Tmp::new();
        let enrolled = persist(dir.path(), sample_resp()).unwrap();
        let id = load_identity(&enrolled).unwrap();
        assert!(!id.cert_pem.is_empty());
        assert!(!id.key_pem.is_empty());
        assert!(!id.ca_pem.is_empty());
        let bundle = id.pem_bundle();
        assert!(bundle
            .windows(b"BEGIN PRIVATE KEY".len())
            .any(|w| w == b"BEGIN PRIVATE KEY"));
        assert!(bundle
            .windows(b"BEGIN CERTIFICATE".len())
            .any(|w| w == b"BEGIN CERTIFICATE"));
    }
}
