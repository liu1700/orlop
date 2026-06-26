//! Tiny shared helpers used across login / enroll / upgrade / main / etc.
//!
//! Resist the urge to grow this into a junk drawer. Things land here only
//! when at least three call sites would otherwise duplicate them.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};

pub fn home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("$HOME is not set"))
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
