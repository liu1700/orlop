//! `orlop doctor` — an offline preflight that answers "can this host mount a
//! Orlop disk?" before anyone tries to, and prints actionable fixes when the
//! answer is no.
//!
//! It checks host mount support (FUSE on Linux, the built-in NFSv3 client on
//! macOS), a writable chunk-cache dir, and whether a usable config +
//! credentials are present. Network is intentionally NOT touched, so it stays
//! fast and safe to run anywhere, including inside a pod.
//!
//! Two tiers of check:
//!   - **required** (mount support, chunk cache): a failure means mounting
//!     cannot work on this host; these drive [`DoctorReport::ready`].
//!   - **advisory** (config, credentials, control-plane): warnings that guide
//!     a config-based `orlop mount`. `--from-env` pod mounts supply these out
//!     of band, so their absence is not a hard failure.

use std::path::{Path, PathBuf};

use serde::Serialize;

/// One named check in the report.
#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub name: String,
    pub ok: bool,
    /// Required checks gate [`DoctorReport::ready`]; advisory ones only warn.
    pub required: bool,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
}

impl Check {
    fn req_ok(name: &str, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ok: true,
            required: true,
            detail: detail.into(),
            fix: None,
        }
    }
    fn req_fail(name: &str, detail: impl Into<String>, fix: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ok: false,
            required: true,
            detail: detail.into(),
            fix: Some(fix.into()),
        }
    }
    fn warn_ok(name: &str, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ok: true,
            required: false,
            detail: detail.into(),
            fix: None,
        }
    }
    fn warn_fail(name: &str, detail: impl Into<String>, fix: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ok: false,
            required: false,
            detail: detail.into(),
            fix: Some(fix.into()),
        }
    }
}

/// Resolved inputs the binary gathers (config/cache live behind `main.rs`
/// helpers, so they're passed in rather than re-derived here).
pub struct DoctorInputs {
    /// Chunk-cache root, or `None` when it can't be determined.
    pub cache_root: Option<PathBuf>,
    /// Resolved config path, or `None` when no config was found.
    pub config_path: Option<PathBuf>,
    /// `Some(true)`/`Some(false)` = config loaded and has/lacks a `hosted:`
    /// block; `None` with a `config_path` set = the file failed to parse.
    pub config_has_hosted: Option<bool>,
    /// Credentials file, or `None` when absent.
    pub credentials_path: Option<PathBuf>,
    /// Control-plane URL read from credentials, if any.
    pub control_plane_url: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    pub os: String,
    pub arch: String,
    /// True when every *required* check passed.
    pub ready: bool,
    pub checks: Vec<Check>,
}

/// Assemble the report from host probes + the resolved inputs.
pub fn gather(inputs: DoctorInputs) -> DoctorReport {
    let mut checks = Vec::new();

    // Required: host mount support.
    checks.push(mount_support_check());

    // Required: a writable chunk-cache dir.
    checks.push(match &inputs.cache_root {
        Some(root) => match check_writable_dir(root) {
            Ok(()) => Check::req_ok("chunk-cache", format!("writable at {}", root.display())),
            Err(e) => Check::req_fail(
                "chunk-cache",
                format!("{} is not writable: {e}", root.display()),
                "point XDG_CACHE_HOME (or HOME) at a writable directory",
            ),
        },
        None => Check::req_fail(
            "chunk-cache",
            "cache directory could not be determined",
            "set XDG_CACHE_HOME or HOME",
        ),
    });

    // Advisory: config presence + a `hosted:` block.
    checks.push(match (&inputs.config_path, inputs.config_has_hosted) {
        (Some(p), Some(true)) => Check::warn_ok("config", format!("{} (hosted)", p.display())),
        (Some(p), Some(false)) => Check::warn_fail(
            "config",
            format!("{} has no `hosted:` block", p.display()),
            "run `orlop login` to regenerate, or add `hosted: {}` by hand",
        ),
        (Some(p), None) => Check::warn_fail(
            "config",
            format!("{} failed to parse", p.display()),
            "fix the YAML, or run `orlop login` to regenerate it",
        ),
        (None, _) => Check::warn_fail(
            "config",
            "no config found",
            "run `orlop login`, pass --config, or mount with `orlop mount --from-env`",
        ),
    });

    // Advisory: credentials.
    checks.push(match &inputs.credentials_path {
        Some(p) => Check::warn_ok("credentials", p.display().to_string()),
        None => Check::warn_fail(
            "credentials",
            "no credentials.json",
            "run `orlop login` (in-pod `--from-env` mounts supply this out of band)",
        ),
    });

    // Informational: control-plane URL, when known.
    if let Some(url) = &inputs.control_plane_url {
        checks.push(Check::warn_ok("control-plane", url.clone()));
    }

    let ready = checks.iter().all(|c| c.ok || !c.required);
    DoctorReport {
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        ready,
        checks,
    }
}

impl DoctorReport {
    /// Human-readable rendering for the default (non-`--json`) output.
    pub fn render_human(&self) -> String {
        let mut out = format!("orlop doctor — {}/{}\n", self.os, self.arch);
        for c in &self.checks {
            let tag = if c.ok {
                "ok  "
            } else if c.required {
                "FAIL"
            } else {
                "warn"
            };
            out.push_str(&format!("  [{tag}] {}: {}\n", c.name, c.detail));
            if !c.ok {
                if let Some(fix) = &c.fix {
                    out.push_str(&format!("         fix: {fix}\n"));
                }
            }
        }
        out.push_str(if self.ready {
            "\nready: this host can mount a Orlop disk.\n"
        } else {
            "\nNOT ready: resolve the FAIL items above before mounting.\n"
        });
        out
    }
}

/// Probe host mount support: FUSE on Linux, the built-in NFSv3 client on macOS.
fn mount_support_check() -> Check {
    #[cfg(target_os = "linux")]
    {
        let has_dev_fuse = Path::new("/dev/fuse").exists();
        let helper = which_on_path("fusermount3").or_else(|| which_on_path("fusermount"));
        match (has_dev_fuse, helper) {
            (true, Some(h)) => Check::req_ok(
                "mount-support",
                format!("FUSE ready (/dev/fuse + {})", h.display()),
            ),
            (false, _) => Check::req_fail(
                "mount-support",
                "/dev/fuse is missing",
                "load the fuse kernel module and give this container access to /dev/fuse",
            ),
            (true, None) => Check::req_fail(
                "mount-support",
                "neither fusermount3 nor fusermount is on PATH",
                "install fuse3 (it provides fusermount3)",
            ),
        }
    }
    #[cfg(target_os = "macos")]
    {
        // macOS mounts via the in-process NFSv3 server plus the built-in
        // mount_nfs client — no macFUSE or kernel extension required.
        match which_on_path("mount_nfs") {
            Some(p) => Check::req_ok(
                "mount-support",
                format!("NFSv3 ready (built-in {})", p.display()),
            ),
            None => Check::req_fail(
                "mount-support",
                "mount_nfs was not found",
                "mount_nfs ships with macOS; ensure PATH includes /sbin",
            ),
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Check::req_fail(
            "mount-support",
            format!("unsupported OS: {}", std::env::consts::OS),
            "Orlop mounts are supported on Linux (FUSE) and macOS (NFSv3)",
        )
    }
}

/// Confirm a directory exists (creating it if needed) and accepts a write.
fn check_writable_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let probe = dir.join(format!(".orlop-doctor-{}", std::process::id()));
    std::fs::write(&probe, b"ok")?;
    std::fs::remove_file(&probe)?;
    Ok(())
}

/// First executable named `name` found on `PATH`, if any.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn which_on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writable_dir_passes_on_tempdir() {
        let tmp = tempfile::tempdir().unwrap();
        check_writable_dir(tmp.path()).unwrap();
    }

    #[test]
    fn writable_dir_creates_missing_nested_path() {
        let tmp = tempfile::tempdir().unwrap();
        let nested = tmp.path().join("a/b/c");
        check_writable_dir(&nested).unwrap();
        assert!(nested.exists());
    }

    #[test]
    fn ready_is_gated_only_by_required_checks() {
        // No config, no creds, but a writable cache + host mount support:
        // advisory failures must not flip `ready`.
        let tmp = tempfile::tempdir().unwrap();
        let report = gather(DoctorInputs {
            cache_root: Some(tmp.path().to_path_buf()),
            config_path: None,
            config_has_hosted: None,
            credentials_path: None,
            control_plane_url: None,
        });
        // ready iff the host's mount-support check passed; either way it must
        // equal the required-checks-only verdict (advisory fails ignored).
        let required_ok = report.checks.iter().all(|c| c.ok || !c.required);
        assert_eq!(report.ready, required_ok);
        // The advisory config/credentials failures are present but non-required.
        assert!(report
            .checks
            .iter()
            .any(|c| c.name == "config" && !c.ok && !c.required));
    }

    #[test]
    fn report_names_every_section_and_renders() {
        let report = gather(DoctorInputs {
            cache_root: None,
            config_path: None,
            config_has_hosted: None,
            credentials_path: None,
            control_plane_url: Some("https://api.example".into()),
        });
        for name in ["mount-support", "chunk-cache", "config", "credentials"] {
            assert!(
                report.checks.iter().any(|c| c.name == name),
                "missing {name}"
            );
        }
        // cache_root None makes chunk-cache (required) fail → not ready.
        assert!(!report.ready);
        let text = report.render_human();
        assert!(text.contains("orlop doctor"));
        assert!(text.contains("control-plane"));
    }
}
