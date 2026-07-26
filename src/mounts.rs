//! Host mount-table inspection and stale Orlop FUSE cleanup.
//!
//! Linux mountpoints whose userspace FUSE server has died return `ENOTCONN`.
//! They cannot be discovered by walking the filesystem reliably, so this
//! module enumerates `/proc/self/mountinfo` and only acts on records whose
//! filesystem/source identifies them as Orlop mounts.

#[cfg(target_os = "linux")]
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
#[cfg(any(target_os = "linux", test))]
use std::time::Duration;

#[cfg(any(target_os = "linux", test))]
use anyhow::Context;
use anyhow::Result;
use serde::Serialize;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MountState {
    Alive,
    Stale,
    Inaccessible,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OrlopMount {
    pub mount_id: u64,
    pub path: String,
    pub filesystem: String,
    pub source: String,
    pub state: MountState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Debug)]
struct MountRecord {
    mount_id: u64,
    mountpoint: PathBuf,
    filesystem: String,
    source: String,
}

#[cfg(any(target_os = "linux", test))]
impl MountRecord {
    fn is_orlop(&self) -> bool {
        self.filesystem == "fuse.orlop" || (self.filesystem == "fuse" && self.source == "orlop")
    }
}

/// Enumerate Orlop FUSE mounts in the caller's mount namespace.
///
/// Each row describes a mount-table record. For stacked mounts the path may
/// appear more than once; `state` is the observable state of the topmost mount
/// at that path.
pub fn list() -> Result<Vec<OrlopMount>> {
    #[cfg(target_os = "linux")]
    {
        let records = read_mountinfo()?;
        Ok(records
            .iter()
            .filter(|record| record.is_orlop())
            .map(|record| {
                let (state, error) = probe(&record.mountpoint);
                OrlopMount {
                    mount_id: record.mount_id,
                    path: record.mountpoint.to_string_lossy().into_owned(),
                    filesystem: record.filesystem.clone(),
                    source: record.source.clone(),
                    state,
                    error,
                }
            })
            .collect())
    }
    #[cfg(not(target_os = "linux"))]
    {
        anyhow::bail!("mount enumeration is currently supported on Linux only")
    }
}

/// Inspect one path and require every mount-table layer at that exact path to
/// belong to Orlop. This fail-closed check is suitable for readiness probes:
/// a mixed stack, missing mount, stale connection, or timed-out probe cannot be
/// mistaken for a healthy Orlop mount.
pub fn inspect(path: &Path) -> Result<OrlopMount> {
    #[cfg(target_os = "linux")]
    {
        let records = read_mountinfo()?;
        let at_path: Vec<&MountRecord> = records
            .iter()
            .filter(|record| record.mountpoint == path)
            .collect();
        if at_path.is_empty() {
            anyhow::bail!("{} is not a mountpoint in this namespace", path.display());
        }
        if at_path.iter().any(|record| !record.is_orlop()) {
            anyhow::bail!(
                "{} has a non-Orlop filesystem in its mount stack",
                path.display()
            );
        }
        let record = at_path[0];
        let (state, error) = probe(path);
        Ok(OrlopMount {
            mount_id: record.mount_id,
            path: path.to_string_lossy().into_owned(),
            filesystem: record.filesystem.clone(),
            source: record.source.clone(),
            state,
            error,
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        anyhow::bail!("mount inspection is currently supported on Linux only")
    }
}

/// Lazy-detach every stale, topmost Orlop FUSE mount in this namespace.
///
/// Stacked mounts are handled one layer at a time. After each detach the mount
/// table and path state are re-read; cleanup stops as soon as the next visible
/// layer is live or is not an Orlop mount.
pub fn reclaim_stale() -> Result<Vec<PathBuf>> {
    #[cfg(target_os = "linux")]
    {
        let initial = read_mountinfo()?;
        let paths: BTreeSet<PathBuf> = initial
            .iter()
            .filter(|record| record.is_orlop())
            .map(|record| record.mountpoint.clone())
            .collect();
        let mut detached = Vec::new();

        for path in paths {
            // A hard ceiling protects against a concurrently-created mount
            // keeping this command in an endless detach loop.
            let mut attempts = 0usize;
            loop {
                let records = read_mountinfo()?;
                // If another filesystem is stacked at the same path, do
                // nothing: umount2(path) always targets the visible layer and
                // there is no race-free path-based way to select a buried
                // mount. Ordinary Orlop-on-Orlop stacks remain reclaimable.
                if !safe_to_detach(&records, &path) || probe(&path).0 != MountState::Stale {
                    break;
                }
                if attempts == 4096 {
                    anyhow::bail!(
                        "stale mount cleanup exceeded 4096 attempts at {}",
                        path.display()
                    );
                }
                attempts += 1;
                match lazy_unmount(&path) {
                    Ok(()) => detached.push(path.clone()),
                    // A concurrent janitor may detach the same mount after our
                    // mount-table check. Re-read from the top of the loop so a
                    // retried cleanup remains idempotent.
                    Err(err) if is_concurrent_unmount_errno(&err) => continue,
                    Err(err) => {
                        return Err(err).with_context(|| {
                            format!("lazy-unmount stale Orlop mount {}", path.display())
                        });
                    }
                }
            }
        }
        Ok(detached)
    }
    #[cfg(not(target_os = "linux"))]
    {
        anyhow::bail!("stale mount cleanup is currently supported on Linux only")
    }
}

#[cfg(target_os = "linux")]
fn probe(path: &Path) -> (MountState, Option<String>) {
    let path = path.to_owned();
    probe_with_timeout(Duration::from_secs(2), move || {
        std::fs::metadata(path).map(|_| ())
    })
}

#[cfg(any(target_os = "linux", test))]
fn probe_with_timeout<F>(timeout: Duration, operation: F) -> (MountState, Option<String>)
where
    F: FnOnce() -> std::io::Result<()> + Send + 'static,
{
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let _ = sender.send(operation());
    });

    match receiver.recv_timeout(timeout) {
        Ok(Ok(())) => (MountState::Alive, None),
        Ok(Err(err)) if err.raw_os_error() == Some(libc::ENOTCONN) => {
            (MountState::Stale, Some("ENOTCONN".to_string()))
        }
        Ok(Err(err)) => (
            MountState::Inaccessible,
            Some(match err.raw_os_error() {
                Some(errno) => format!("errno {errno}: {err}"),
                None => err.to_string(),
            }),
        ),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => (
            MountState::Inaccessible,
            Some(format!("probe timed out after {} ms", timeout.as_millis())),
        ),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => (
            MountState::Inaccessible,
            Some("probe worker terminated unexpectedly".to_string()),
        ),
    }
}

#[cfg(target_os = "linux")]
fn read_mountinfo() -> Result<Vec<MountRecord>> {
    let bytes = std::fs::read("/proc/self/mountinfo").context("read /proc/self/mountinfo")?;
    parse_mountinfo(&bytes)
}

#[cfg(any(target_os = "linux", test))]
fn parse_mountinfo(bytes: &[u8]) -> Result<Vec<MountRecord>> {
    let mut records = Vec::new();
    for (line_no, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
        if line.is_empty() {
            continue;
        }
        let fields: Vec<&[u8]> = line
            .split(|byte| *byte == b' ')
            .filter(|field| !field.is_empty())
            .collect();
        let Some(separator) = fields.iter().position(|field| *field == b"-") else {
            anyhow::bail!("mountinfo line {} has no field separator", line_no + 1);
        };
        if fields.len() < 6 || separator + 2 >= fields.len() {
            anyhow::bail!("mountinfo line {} is truncated", line_no + 1);
        }
        let mount_id = std::str::from_utf8(fields[0])
            .context("mountinfo mount id is not UTF-8")?
            .parse::<u64>()
            .with_context(|| format!("invalid mount id on mountinfo line {}", line_no + 1))?;
        let mountpoint = path_from_mountinfo_field(fields[4]);
        let filesystem = String::from_utf8_lossy(fields[separator + 1]).into_owned();
        let source = String::from_utf8_lossy(fields[separator + 2]).into_owned();
        records.push(MountRecord {
            mount_id,
            mountpoint,
            filesystem,
            source,
        });
    }
    Ok(records)
}

#[cfg(any(target_os = "linux", test))]
fn path_from_mountinfo_field(field: &[u8]) -> PathBuf {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let mut decoded = Vec::with_capacity(field.len());
    let mut index = 0;
    while index < field.len() {
        if field[index] == b'\\' && index + 3 < field.len() {
            let octal = &field[index + 1..index + 4];
            if octal.iter().all(|byte| (b'0'..=b'7').contains(byte)) {
                decoded.push((octal[0] - b'0') * 64 + (octal[1] - b'0') * 8 + (octal[2] - b'0'));
                index += 4;
                continue;
            }
        }
        decoded.push(field[index]);
        index += 1;
    }
    PathBuf::from(OsString::from_vec(decoded))
}

#[cfg(any(target_os = "linux", test))]
fn safe_to_detach(records: &[MountRecord], path: &Path) -> bool {
    let mut found = false;
    for record in records.iter().filter(|record| record.mountpoint == path) {
        found = true;
        if !record.is_orlop() {
            return false;
        }
    }
    found
}

#[cfg(target_os = "linux")]
fn lazy_unmount(path: &Path) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let path_c = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("mount path contains NUL: {}", path.display()),
        )
    })?;
    // SAFETY: path_c is a valid NUL-terminated pathname and remains alive for
    // the duration of the syscall.
    let rc = unsafe { libc::umount2(path_c.as_ptr(), libc::MNT_DETACH) };
    if rc == 0 {
        return Ok(());
    }
    Err(std::io::Error::last_os_error())
}

#[cfg(any(target_os = "linux", test))]
fn is_concurrent_unmount_errno(err: &std::io::Error) -> bool {
    matches!(err.raw_os_error(), Some(libc::EINVAL) | Some(libc::ENOENT))
}

#[cfg(test)]
mod tests {
    use super::{
        is_concurrent_unmount_errno, parse_mountinfo, path_from_mountinfo_field,
        probe_with_timeout, safe_to_detach, MountState,
    };
    use std::path::Path;
    use std::time::Duration;

    #[test]
    fn parses_only_after_separator_and_decodes_mount_paths() {
        let input = b"36 25 0:32 / /mnt/orlop\\040agent rw,nosuid - fuse orlop rw\n\
                      41 25 0:33 / /other rw - ext4 /dev/vda1 rw\n";
        let records = parse_mountinfo(input).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].mount_id, 36);
        assert_eq!(records[0].mountpoint, Path::new("/mnt/orlop agent"));
        assert_eq!(records[0].filesystem, "fuse");
        assert_eq!(records[0].source, "orlop");
        assert!(records[0].is_orlop());
        assert!(!records[1].is_orlop());
    }

    #[test]
    fn recognizes_fuse_subtype_form() {
        let records = parse_mountinfo(b"9 1 0:9 / /workspace rw - fuse.orlop orlop rw\n").unwrap();
        assert!(records[0].is_orlop());
    }

    #[test]
    fn rejects_other_fuse_filesystems() {
        let records = parse_mountinfo(b"9 1 0:9 / /workspace rw - fuse.sshfs sshfs rw\n").unwrap();
        assert!(!records[0].is_orlop());
    }

    #[test]
    fn stacked_orlop_mounts_are_safe_but_mixed_stacks_are_not() {
        let records = parse_mountinfo(
            b"12 1 0:12 / /workspace rw - fuse orlop rw\n\
              19 1 0:19 / /workspace rw - fuse orlop rw\n",
        )
        .unwrap();
        assert!(safe_to_detach(&records, Path::new("/workspace")));

        let mixed = parse_mountinfo(
            b"12 1 0:12 / /workspace rw - fuse orlop rw\n\
              19 1 0:19 / /workspace rw - ext4 /dev/vda1 rw\n",
        )
        .unwrap();
        assert!(!safe_to_detach(&mixed, Path::new("/workspace")));
        assert!(!safe_to_detach(&mixed, Path::new("/missing")));
    }

    #[test]
    fn decoder_preserves_backslash_when_escape_is_not_octal() {
        assert_eq!(
            path_from_mountinfo_field(br"/mnt/a\q"),
            Path::new(r"/mnt/a\q")
        );
    }

    #[test]
    fn concurrent_unmount_races_are_retryable() {
        assert!(is_concurrent_unmount_errno(
            &std::io::Error::from_raw_os_error(libc::EINVAL)
        ));
        assert!(is_concurrent_unmount_errno(
            &std::io::Error::from_raw_os_error(libc::ENOENT)
        ));
        assert!(!is_concurrent_unmount_errno(
            &std::io::Error::from_raw_os_error(libc::EPERM)
        ));
    }

    #[test]
    fn probe_timeout_fails_safe_without_marking_mount_stale() {
        let (state, error) = probe_with_timeout(Duration::from_millis(1), || {
            std::thread::sleep(Duration::from_millis(50));
            Ok(())
        });
        assert_eq!(state, MountState::Inaccessible);
        assert_eq!(error.as_deref(), Some("probe timed out after 1 ms"));
    }

    #[test]
    fn probe_classifies_disconnected_fuse_mount() {
        let (state, error) = probe_with_timeout(Duration::from_secs(1), || {
            Err(std::io::Error::from_raw_os_error(libc::ENOTCONN))
        });
        assert_eq!(state, MountState::Stale);
        assert_eq!(error.as_deref(), Some("ENOTCONN"));
    }
}
