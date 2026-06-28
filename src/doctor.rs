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
    /// When set (`orlop doctor --dev`), check exactly what `orlop dev up` needs:
    /// these `(label, port)` pairs are free. In this mode the config/credentials
    /// checks are skipped — `dev up` supplies them out of band (issue #54).
    pub dev_ports: Option<Vec<(String, u16)>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    pub os: String,
    pub arch: String,
    /// True when every *required* check passed.
    pub ready: bool,
    /// Whether this report was gathered for the `dev up` path (`--dev`).
    pub dev: bool,
    pub checks: Vec<Check>,
}

/// Assemble the report from host probes + the resolved inputs.
pub fn gather(inputs: DoctorInputs) -> DoctorReport {
    let mut checks = Vec::new();

    // Required everywhere: host mount support + a writable chunk-cache dir.
    checks.push(mount_support_check());
    checks.push(chunk_cache_check(inputs.cache_root.as_deref()));

    let dev = inputs.dev_ports.is_some();
    if let Some(ports) = &inputs.dev_ports {
        // `dev up` preflight: the ports it binds must be free. Config and
        // credentials are minted out of band, so they're intentionally absent
        // from this report.
        for (label, port) in ports {
            checks.push(port_free_check(label, *port));
        }
    } else {
        // Config-based `orlop mount` advisories. These are *not* needed for
        // `orlop dev up` (which supplies config + credentials itself), so the
        // wording says so — their absence on a clean host is normal, not a fault.
        checks.push(config_check(&inputs.config_path, inputs.config_has_hosted));
        checks.push(credentials_check(inputs.credentials_path.as_deref()));
        if let Some(url) = &inputs.control_plane_url {
            checks.push(Check::warn_ok("control-plane", url.clone()));
        }
    }

    let ready = checks.iter().all(|c| c.ok || !c.required);
    DoctorReport {
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        ready,
        dev,
        checks,
    }
}

/// Required: a writable chunk-cache directory.
fn chunk_cache_check(cache_root: Option<&Path>) -> Check {
    match cache_root {
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
    }
}

/// Advisory: config presence + a `hosted:` block (config-based mount only).
fn config_check(config_path: &Option<PathBuf>, has_hosted: Option<bool>) -> Check {
    match (config_path, has_hosted) {
        (Some(p), Some(true)) => Check::warn_ok("config", format!("{} (hosted)", p.display())),
        (Some(p), Some(false)) => Check::warn_fail(
            "config",
            format!("{} has no `hosted:` block", p.display()),
            "add `hosted: {}` by hand (control_plane_url and cert_dir fall back to credentials.json)",
        ),
        (Some(p), None) => Check::warn_fail(
            "config",
            format!("{} failed to parse", p.display()),
            "fix the YAML so the file parses",
        ),
        (None, _) => Check::warn_fail(
            "config",
            "no config found (not needed for `orlop dev up`)",
            "only for a config-based `orlop mount`: pass --config, or mount with `orlop mount --from-env`",
        ),
    }
}

/// Advisory: credentials file (config-based mount only).
fn credentials_check(credentials_path: Option<&Path>) -> Check {
    match credentials_path {
        Some(p) => Check::warn_ok("credentials", p.display().to_string()),
        None => Check::warn_fail(
            "credentials",
            "no credentials.json (not needed for `orlop dev up`)",
            "only for a config-based `orlop mount`: re-enroll the agent, or mount with `orlop mount --from-env`",
        ),
    }
}

/// Required (dev mode): a TCP connect to 127.0.0.1:port fails iff nothing is
/// listening, i.e. `dev up` can bind it.
fn port_free_check(label: &str, port: u16) -> Check {
    use std::net::TcpStream;
    use std::time::Duration;
    let in_use = TcpStream::connect_timeout(
        &([127, 0, 0, 1], port).into(),
        Duration::from_millis(200),
    )
    .is_ok();
    let name = format!("port-{port}");
    if in_use {
        Check::req_fail(
            &name,
            format!("{port} ({label}) is already in use"),
            format!("free port {port}, or pass a different --*-port to `orlop dev up`"),
        )
    } else {
        Check::req_ok(&name, format!("{port} ({label}) is free"))
    }
}

impl DoctorReport {
    /// Human-readable rendering for the default (non-`--json`) output.
    pub fn render_human(&self) -> String {
        let mut out = format!(
            "orlop doctor{} — {}/{}\n",
            if self.dev { " --dev" } else { "" },
            self.os,
            self.arch,
        );
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
        out.push_str(match (self.ready, self.dev) {
            (true, true) => "\nready: this host can run `orlop dev up`.\n",
            (true, false) => "\nready: this host can mount a Orlop disk.\n",
            (false, _) => "\nNOT ready: resolve the FAIL items above first.\n",
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
            dev_ports: None,
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
            dev_ports: None,
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

    #[test]
    fn clean_host_config_credentials_warnings_mention_dev_up() {
        // issue #54: on a clean host the advisory warnings must not read as
        // "your setup is incomplete" — they say they're not needed for dev up.
        let tmp = tempfile::tempdir().unwrap();
        let report = gather(DoctorInputs {
            cache_root: Some(tmp.path().to_path_buf()),
            config_path: None,
            config_has_hosted: None,
            credentials_path: None,
            control_plane_url: None,
            dev_ports: None,
        });
        let config = report.checks.iter().find(|c| c.name == "config").unwrap();
        let creds = report.checks.iter().find(|c| c.name == "credentials").unwrap();
        assert!(config.detail.contains("orlop dev up"), "got: {}", config.detail);
        assert!(creds.detail.contains("orlop dev up"), "got: {}", creds.detail);
    }

    #[test]
    fn dev_mode_checks_ports_and_omits_config_credentials() {
        let tmp = tempfile::tempdir().unwrap();
        // Pick a port nothing is listening on so the check passes deterministically.
        let report = gather(DoctorInputs {
            cache_root: Some(tmp.path().to_path_buf()),
            config_path: None,
            config_has_hosted: None,
            credentials_path: None,
            control_plane_url: Some("https://api.example".into()),
            dev_ports: Some(vec![("control plane".into(), 0)]),
        });
        assert!(report.dev);
        // Config/credentials/control-plane checks are absent in dev mode.
        for absent in ["config", "credentials", "control-plane"] {
            assert!(
                !report.checks.iter().any(|c| c.name == absent),
                "{absent} should be omitted in --dev mode"
            );
        }
        // The port check is present and required.
        let port = report.checks.iter().find(|c| c.name == "port-0").unwrap();
        assert!(port.required);
        assert!(report.render_human().contains("orlop dev up"));
    }
}
