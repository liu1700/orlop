//! Tiny shared helpers used across login / enroll / upgrade / main / etc.
//!
//! Resist the urge to grow this into a junk drawer. Things land here only
//! when at least three call sites would otherwise duplicate them.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};

pub fn home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("$HOME is not set"))
}

/// Atomically write a secret file: 0600 `<name>.tmp` sibling, then write,
/// fsync, rename. Killing the process mid-write leaves at most a `.tmp`
/// orphan, never a partial secret under its real name. Shared by the
/// credentials (login) and cert/key/CA (enroll) writers.
pub fn write_secret_atomic(path: &Path, body: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_else(|| std::ffi::OsString::from("orlop-secret"));
    name.push(".tmp");
    let tmp = path.with_file_name(name);
    {
        let mut f = std::fs::OpenOptions::new()
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
    std::fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

pub fn http_client(timeout: Duration) -> Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .timeout(timeout)
        .build()
        .context("build http client")
}

/// Print a `warning: <label> failed: <err>` line on Err and discard the value
/// either way. Common shape across CLI cleanup paths (`Drop`, post-unmount,
/// background renewals) where a failure is informational, not fatal.
pub fn warn_err<T>(label: &str, res: Result<T>) {
    if let Err(err) = res {
        eprintln!("warning: {label} failed: {err:#}");
    }
}
