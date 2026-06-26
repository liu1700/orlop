//! Daemon lifecycle helpers for `orlop mount` — preflight classification,
//! PID file + ready-pipe protocol, and platform-agnostic mount-active
//! probe. The actual fork/setsid/stdio plumbing is provided by the
//! `daemonize` crate; this module owns the surrounding policy.

use std::fs;
use std::io;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use anyhow::Context;

/// Result of inspecting the existing PID file + mountpoint before deciding
/// what `orlop mount` should do.
#[derive(Debug, PartialEq, Eq)]
pub enum PreflightOutcome {
    /// Daemon already running and serving the mountpoint. Caller exits 0
    /// (idempotent for agents).
    AlreadyMounted { pid: u32 },
    /// PID file points at a live process but the kernel mount is gone.
    /// Caller bails with "run `orlop unmount` first".
    StaleDaemon { pid: u32 },
    /// PID file exists, but the PID is dead. Caller unlinks the file and
    /// proceeds to daemonize fresh.
    StalePidOnly,
    /// Mountpoint occupied (something mounted there) but no PID file we
    /// own. Caller bails so we don't mask an unrelated mount.
    Busy,
    /// Clean slate. Proceed.
    Fresh,
}

/// Pure decision function — testable without touching disk or processes.
/// Inputs are the gathered facts; output is the action to take.
pub fn classify(
    pid_from_file: Option<u32>,
    pid_alive: bool,
    mountpoint_active: bool,
) -> PreflightOutcome {
    match (pid_from_file, pid_alive, mountpoint_active) {
        (Some(pid), true, true) => PreflightOutcome::AlreadyMounted { pid },
        (Some(pid), true, false) => PreflightOutcome::StaleDaemon { pid },
        (Some(_), false, _) => PreflightOutcome::StalePidOnly,
        (None, _, true) => PreflightOutcome::Busy,
        (None, _, false) => PreflightOutcome::Fresh,
    }
}

/// Read the integer PID written by `daemonize`. Missing file is `Ok(None)`;
/// unparseable content is also `Ok(None)` (treated as if the file were
/// missing — daemonize crashed mid-write, etc.).
pub fn read_pid_file(path: &Path) -> io::Result<Option<u32>> {
    match fs::read_to_string(path) {
        Ok(s) => Ok(s.trim().parse::<u32>().ok()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// `kill(pid, 0)` — returns `true` if the process exists and the caller can
/// signal it, `false` otherwise. Doesn't actually signal the process.
pub fn pid_alive(pid: u32) -> bool {
    // SAFETY: passing 0 as the signal is a no-op probe.
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

/// Send `sig` to `pid`. Returns `true` if the kernel accepted it.
pub fn send_signal(pid: u32, sig: libc::c_int) -> bool {
    // SAFETY: kill(2) on any pid_t + valid signal number is defined.
    unsafe { libc::kill(pid as libc::pid_t, sig) == 0 }
}

/// Send `sig` to the calling process.
pub fn raise_signal(sig: libc::c_int) {
    // SAFETY: raise(3) on a valid signal number is defined.
    unsafe { libc::raise(sig) };
}

/// Result of reading the daemon's ready pipe in the parent.
#[derive(Debug, PartialEq, Eq)]
pub enum ReadyOutcome {
    /// Grandchild signaled "READY" — mount is live, parent exits 0.
    Ready,
    /// Grandchild signaled "ERR <msg>" — parent prints msg, exits 1.
    Err(String),
    /// Pipe closed with no line written — grandchild died silently.
    DaemonExited,
}

/// Decode whatever the grandchild wrote into its end of the pipe.
pub fn decode_ready(buf: &str) -> ReadyOutcome {
    let line = buf.lines().next();
    match line {
        Some("READY") => ReadyOutcome::Ready,
        Some(other) if other.starts_with("ERR ") => {
            ReadyOutcome::Err(other[4..].to_string())
        }
        Some(other) => ReadyOutcome::Err(format!("unrecognized daemon signal: {other}")),
        None => ReadyOutcome::DaemonExited,
    }
}

/// Read from a pipe (or anything else implementing `Read + Send`) with a
/// wall-clock budget. Returns `Err(())` on timeout; the caller is
/// responsible for killing the grandchild and unlinking the PID file.
///
/// The blocking read runs in a helper thread so the main thread can wait
/// on a `recv_timeout`. On timeout the helper thread is leaked — it
/// finishes when the pipe is closed externally (which the caller does
/// by SIGKILLing the grandchild).
pub fn read_ready_with_timeout<R: Read + Send + 'static>(
    mut reader: R,
    timeout: Duration,
) -> Result<ReadyOutcome, ()> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut buf = String::new();
        let _ = reader.read_to_string(&mut buf);
        let _ = tx.send(buf);
    });
    match rx.recv_timeout(timeout) {
        Ok(buf) => Ok(decode_ready(&buf)),
        Err(_) => Err(()),
    }
}

/// `$XDG_CACHE_HOME/orlop` or `$HOME/.cache/orlop`. Matches the resolution
/// used by `ChunkCache::default_root` so the daemon's PID/log files live
/// alongside the chunk cache.
fn cache_dir() -> anyhow::Result<PathBuf> {
    let dir = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .ok_or_else(|| {
            anyhow::anyhow!("cannot resolve cache directory: set XDG_CACHE_HOME or HOME")
        })?
        .join("orlop");
    fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    Ok(dir)
}

/// `<cache_dir>/mount.pid`. Created on demand by `daemonize`.
pub fn pid_file_path() -> anyhow::Result<PathBuf> {
    Ok(cache_dir()?.join("mount.pid"))
}

/// `<cache_dir>/mount.log`. The `daemonize` crate truncates on open because
/// we pass `File::create`.
pub fn log_file_path() -> anyhow::Result<PathBuf> {
    Ok(cache_dir()?.join("mount.log"))
}

/// Is anything mounted at `path`? Cross-platform via `/sbin/mount`, which
/// exists on both Linux and macOS and prints one line per active mount.
///
/// The mount probe is best-effort: a false negative just means we proceed
/// to attempt a fresh mount, which will fail with "busy" from the kernel
/// if there really was something there.
pub fn is_mountpoint_active(path: &Path) -> bool {
    let path_str = match path.to_str() {
        Some(s) => s,
        None => return false,
    };
    let out = match std::process::Command::new("/sbin/mount").output() {
        Ok(o) => o,
        Err(_) => return false,
    };
    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout.lines().any(|line| {
        line.contains(&format!(" on {} ", path_str))
            || line.contains(&format!(" on {}(", path_str))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_already_mounted() {
        assert_eq!(
            classify(Some(42), true, true),
            PreflightOutcome::AlreadyMounted { pid: 42 }
        );
    }

    #[test]
    fn classify_stale_daemon() {
        assert_eq!(
            classify(Some(42), true, false),
            PreflightOutcome::StaleDaemon { pid: 42 }
        );
    }

    #[test]
    fn classify_stale_pid_only_when_dead_and_no_mount() {
        assert_eq!(classify(Some(42), false, false), PreflightOutcome::StalePidOnly);
    }

    #[test]
    fn classify_stale_pid_only_when_dead_with_mount() {
        // PID dead trumps mount existence — the mount may be a remnant.
        assert_eq!(classify(Some(42), false, true), PreflightOutcome::StalePidOnly);
    }

    #[test]
    fn classify_busy_when_no_pid_file_but_mountpoint_active() {
        assert_eq!(classify(None, false, true), PreflightOutcome::Busy);
    }

    #[test]
    fn classify_fresh_when_clean() {
        assert_eq!(classify(None, false, false), PreflightOutcome::Fresh);
    }

    #[test]
    fn read_pid_file_returns_none_when_missing() {
        let tmp = std::env::temp_dir().join("orlop-daemon-test-missing.pid");
        let _ = fs::remove_file(&tmp);
        assert_eq!(read_pid_file(&tmp).unwrap(), None);
    }

    #[test]
    fn read_pid_file_parses_integer() {
        let tmp = std::env::temp_dir().join("orlop-daemon-test-ok.pid");
        fs::write(&tmp, "12345\n").unwrap();
        assert_eq!(read_pid_file(&tmp).unwrap(), Some(12345));
        fs::remove_file(&tmp).unwrap();
    }

    #[test]
    fn read_pid_file_garbage_treated_as_missing() {
        let tmp = std::env::temp_dir().join("orlop-daemon-test-garbage.pid");
        fs::write(&tmp, "not-a-pid\n").unwrap();
        assert_eq!(read_pid_file(&tmp).unwrap(), None);
        fs::remove_file(&tmp).unwrap();
    }

    #[test]
    fn pid_alive_returns_true_for_self() {
        assert!(pid_alive(std::process::id()));
    }

    #[test]
    fn pid_alive_returns_false_for_pid_one_billion() {
        // PID space tops out well below 2^30 on Linux/macOS; pid=1e9 is
        // guaranteed to be unused.
        assert!(!pid_alive(1_000_000_000));
    }

    #[test]
    fn decode_ready_recognizes_ready() {
        assert_eq!(decode_ready("READY\n"), ReadyOutcome::Ready);
    }

    #[test]
    fn decode_ready_recognizes_ready_no_newline() {
        assert_eq!(decode_ready("READY"), ReadyOutcome::Ready);
    }

    #[test]
    fn decode_ready_extracts_err_message() {
        assert_eq!(
            decode_ready("ERR mount_nfs exited with 1\n"),
            ReadyOutcome::Err("mount_nfs exited with 1".to_string())
        );
    }

    #[test]
    fn decode_ready_handles_empty_input() {
        assert_eq!(decode_ready(""), ReadyOutcome::DaemonExited);
    }

    #[test]
    fn decode_ready_handles_unknown_line() {
        match decode_ready("WAT\n") {
            ReadyOutcome::Err(msg) => assert!(msg.contains("WAT")),
            other => panic!("unexpected outcome: {other:?}"),
        }
    }

    #[test]
    fn read_ready_with_timeout_returns_ready_quickly() {
        // Pre-loaded reader with READY — should resolve well under the timeout.
        let cursor = std::io::Cursor::new(b"READY\n".to_vec());
        let outcome = read_ready_with_timeout(cursor, Duration::from_secs(1)).unwrap();
        assert_eq!(outcome, ReadyOutcome::Ready);
    }

    #[test]
    fn read_ready_with_timeout_fires_on_slow_reader() {
        // A reader that blocks forever — timeout must fire.
        struct BlockReader;
        impl Read for BlockReader {
            fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                std::thread::park();
                Ok(0)
            }
        }
        let result = read_ready_with_timeout(BlockReader, Duration::from_millis(50));
        assert!(result.is_err(), "expected timeout, got {result:?}");
    }

    #[test]
    fn pid_file_path_lives_under_cache_orlop() {
        let p = pid_file_path().unwrap();
        assert!(p.ends_with(".cache/orlop/mount.pid"), "got {}", p.display());
    }

    #[test]
    fn log_file_path_lives_under_cache_orlop() {
        let p = log_file_path().unwrap();
        assert!(p.ends_with(".cache/orlop/mount.log"), "got {}", p.display());
    }

    #[test]
    fn is_mountpoint_active_returns_false_for_nonexistent() {
        let p = std::path::PathBuf::from("/this/path/definitely/does/not/exist/anywhere");
        assert!(!is_mountpoint_active(&p));
    }
}
