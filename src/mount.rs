//! Platform-conditional mount lifecycle.
//!
//! Linux uses FUSE via the `fuser` crate. macOS uses an in-process NFSv3
//! server (see [`crate::nfs`]) plus the kernel-builtin `mount_nfs` client —
//! that path requires no kernel extension, no `sudo` at mount time, and no
//! reboot. The `MountedFs` handle abstracts both: a single `wait()` call
//! blocks until the kernel tears the mount down (Linux) or until a SIGINT
//! arrives (macOS), and `Drop` runs `unmount` either way so panics or early
//! returns leave no zombie mount behind.
//!
//! `main.rs` is intentionally platform-agnostic: it builds the same
//! `Vec<Backend>` regardless of OS and hands it to [`mount`]. On macOS the
//! first backend's `store` + `policy` flow into the NFS adapter; the rest of
//! the FUSE-only knobs (TTL, write-buffer, multi-mount) are dropped because
//! the NFS export presents a single namespace.

use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::sync::Arc;
#[cfg(target_os = "macos")]
use std::time::Duration;
#[cfg(target_os = "linux")]
use std::{os::fd::AsFd, os::fd::OwnedFd};

use anyhow::{Context, Result};

use crate::audit::AuditLog;
use crate::backend::MountedStore;
use crate::config::FuseConfig;
#[cfg(target_os = "linux")]
use crate::fs::GatewayFs;
use crate::lease::LeaseHandle;

pub struct MountedFs {
    mountpoint: PathBuf,
    inner: Inner,
    /// Lease handles for each backend's root "/" lease; held alive for the
    /// full mount lifetime so `lease_release` fires only when the mount tears
    /// down, not at end-of-block.
    _lease_handles: Vec<Arc<LeaseHandle>>,
    #[cfg(target_os = "linux")]
    handoff: crate::fs::GatewayHandoff,
    /// Successors must not unmount the predecessor's live connection if
    /// preparation fails before COMMIT.
    unmount_on_drop: bool,
}

#[cfg(target_os = "linux")]
pub struct InheritedFuse {
    pub fd: OwnedFd,
    pub proto_major: u32,
    pub proto_minor: u32,
    pub snapshot: crate::fs::HandoffSnapshot,
}

#[cfg(target_os = "linux")]
enum Inner {
    /// `Some` until [`MountedFs::wait`] consumes it via `Session::run`.
    Fuse(Option<fuser::Session<GatewayFs>>),
}

#[cfg(target_os = "macos")]
enum Inner {
    /// Holding the runtime keeps the spawned NFS server task alive; dropping
    /// the runtime aborts it.
    Nfs { rt: tokio::runtime::Runtime },
}

/// Acquire the root "/" lease on `backend`, tag the store with the resulting
/// `mount:<hex>` session id, and return the handle. The server's forgery
/// check (manifests.go validateSessionIDForLease) requires this exact format.
/// Returns `Ok(None)` when the backend has no LeaseManager (e.g. a local
/// fixture); `Ok(None)` is also returned from a successful skip path so the
/// caller can collect handles uniformly.
fn acquire_mount_lease(backend: &MountedStore) -> Result<Option<Arc<LeaseHandle>>> {
    let Some(lm) = backend.leases.as_ref() else {
        return Ok(None);
    };
    match lm.acquire_exclusive("/") {
        Ok(Some(handle)) => {
            let session_id = format!(
                "mount:{}",
                crate::backend::dataplane::cache::hex_encode(&handle.entry().lease_id)
            );
            backend.store.set_session(Some(session_id.clone()));
            eprintln!("implicit mount session opened: {session_id}");
            Ok(Some(handle))
        }
        Ok(None) => anyhow::bail!(
            "another machine is currently mounted on this allocation; \
             unmount there first, or use the dashboard take-over flow"
        ),
        Err(e) => Err(e).context("could not acquire mount lease"),
    }
}

/// Mount the user's disk at `mountpoint`. Linux returns once the FUSE
/// session is wired (kernel-side mount established but not yet dispatching);
/// macOS returns once `mount_nfs` reports success. In both cases the caller
/// must call [`MountedFs::wait`] to actually serve requests.
///
/// `fuse_cfg` and `write_buffer_bytes` are FUSE-only and ignored on macOS.
pub fn mount(
    backends: Vec<MountedStore>,
    audit: AuditLog,
    fuse_cfg: &FuseConfig,
    write_buffer_bytes: u64,
    mountpoint: &Path,
) -> Result<MountedFs> {
    #[cfg(target_os = "linux")]
    {
        let mut lease_handles: Vec<Arc<LeaseHandle>> = Vec::new();
        for b in &backends {
            if let Some(handle) = acquire_mount_lease(b)? {
                lease_handles.push(handle);
            }
        }

        let fs = GatewayFs::new(backends, audit, fuse_cfg, write_buffer_bytes);
        let notifier_slot = fs.notifier_handle();
        let handoff = fs.handoff_handle();
        // AllowOther: the mounter runs privileged/root, but the executor that
        // reads this mount is distroless `USER nonroot`. Without allow_other a
        // FUSE mount is accessible only to the mounting user, so the executor's
        // stat("/workspace") fails with EACCES and it aborts before the run.
        // Root mounts it, so no /etc/fuse.conf user_allow_other is needed.
        let mut options = vec![
            fuser::MountOption::FSName("orlop".to_string()),
            fuser::MountOption::AllowOther,
        ];
        // Opt-in POSIX permission enforcement (default off — see FuseConfig).
        // The kernel does uid/gid/mode access checks against the attrs we
        // return from getattr; lets conformance suites (pjdfstest) exercise
        // EACCES/EPERM semantics without the client owning a permission model.
        if fuse_cfg.enforce_permissions {
            options.push(fuser::MountOption::DefaultPermissions);
        }
        let session = fuser::Session::new(fs, mountpoint, &options)
            .with_context(|| format!("FUSE Session::new failed for {}", mountpoint.display()))?;
        let _ = notifier_slot.set(session.notifier());
        Ok(MountedFs {
            mountpoint: mountpoint.to_path_buf(),
            inner: Inner::Fuse(Some(session)),
            _lease_handles: lease_handles,
            handoff,
            unmount_on_drop: true,
        })
    }

    #[cfg(target_os = "macos")]
    {
        let _ = (fuse_cfg, write_buffer_bytes); // FUSE-only knobs, n/a here
        let mut backend_iter = backends.into_iter();
        let backend = backend_iter
            .next()
            .ok_or_else(|| anyhow::anyhow!("no backend supplied to mount::mount"))?;

        let lease_handles: Vec<Arc<LeaseHandle>> =
            acquire_mount_lease(&backend)?.into_iter().collect();

        mount_macos(
            Arc::clone(&backend.store),
            backend.policy.clone(),
            audit,
            mountpoint,
            lease_handles,
        )
    }
}

/// Attach a reconstructed userspace filesystem to an already-mounted,
/// initialized FUSE connection received from a predecessor process.
#[cfg(target_os = "linux")]
pub fn mount_from_handoff(
    backends: Vec<MountedStore>,
    audit: AuditLog,
    fuse_cfg: &FuseConfig,
    write_buffer_bytes: u64,
    mountpoint: &Path,
    inherited: InheritedFuse,
) -> Result<MountedFs> {
    let mut lease_handles: Vec<Arc<LeaseHandle>> = Vec::new();
    for backend in &backends {
        if let Some(handle) = acquire_mount_lease(backend)? {
            lease_handles.push(handle);
        }
    }

    let fs = GatewayFs::from_handoff(
        backends,
        audit,
        fuse_cfg,
        write_buffer_bytes,
        inherited.snapshot,
    )?;
    let notifier_slot = fs.notifier_handle();
    let handoff = fs.handoff_handle();
    let session = fuser::Session::from_initialized_fd(
        fs,
        inherited.fd,
        fuser::SessionACL::All,
        inherited.proto_major,
        inherited.proto_minor,
    )
    .context("construct inherited FUSE session")?;
    let _ = notifier_slot.set(session.notifier());
    Ok(MountedFs {
        mountpoint: mountpoint.to_path_buf(),
        inner: Inner::Fuse(Some(session)),
        _lease_handles: lease_handles,
        handoff,
        unmount_on_drop: false,
    })
}

#[cfg(target_os = "macos")]
fn mount_macos(
    store: Arc<dyn crate::store::Store>,
    policy: crate::policy::Policy,
    audit: AuditLog,
    mountpoint: &Path,
    lease_handles: Vec<Arc<LeaseHandle>>,
) -> Result<MountedFs> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build tokio runtime for NFS server")?;
    let mp = mountpoint.to_path_buf();

    rt.block_on(async {
        let nfs = crate::nfs::OrlopNfs::new(store, policy, Arc::new(audit));
        let server = nfsserve::tcp::NFSTcpListener::bind("127.0.0.1:0", nfs)
            .await
            .context("bind nfsserve listener on 127.0.0.1:0")?;
        // get_listen_port is from the NFSTcp trait; pull it before moving
        // `server` into the spawned task.
        use nfsserve::tcp::NFSTcp;
        let port = server.get_listen_port();
        tokio::spawn(async move {
            let _ = server.handle_forever().await;
        });
        // Hand mount_nfs an explicit port so it doesn't go through portmapper
        // (which we don't run). `nolocks` skips the lock manager (we don't
        // implement NLM); `nobrowse` keeps the mount out of Finder.
        let opt =
            format!("vers=3,nolocks,soft,nobrowse,noatime,actimeo=2,port={port},mountport={port}");
        let status = ProcessCommand::new("mount_nfs")
            .args([
                "-o",
                &opt,
                "127.0.0.1:/",
                mp.to_str()
                    .ok_or_else(|| anyhow::anyhow!("non-utf8 mountpoint"))?,
            ])
            .status()
            .context("exec mount_nfs")?;
        if !status.success() {
            anyhow::bail!("mount_nfs exited with {status}");
        }
        Ok::<(), anyhow::Error>(())
    })?;

    Ok(MountedFs {
        mountpoint: mountpoint.to_path_buf(),
        inner: Inner::Nfs { rt },
        _lease_handles: lease_handles,
        unmount_on_drop: true,
    })
}

impl MountedFs {
    /// Arm normal unmount-on-drop behavior after the predecessor commits.
    #[cfg(target_os = "linux")]
    pub fn commit_handoff(&mut self) {
        self.unmount_on_drop = true;
    }

    /// Clone the initialized FUSE connection for a successor process.
    #[cfg(target_os = "linux")]
    pub fn handoff_parts(&self) -> Result<(OwnedFd, crate::fs::GatewayHandoff)> {
        let Inner::Fuse(Some(session)) = &self.inner else {
            anyhow::bail!("FUSE session is unavailable for handoff");
        };
        Ok((
            session
                .as_fd()
                .try_clone_to_owned()
                .context("duplicate /dev/fuse descriptor")?,
            self.handoff.clone(),
        ))
    }

    /// Block the calling thread until the mount is torn down.
    ///
    /// Linux: enters the FUSE dispatch loop via `Session::run`; returns when
    /// the kernel sees the unmount syscall (e.g. `fusermount3 -u`).
    ///
    /// macOS: blocks on SIGINT/SIGTERM *and* polls the mountpoint so an
    /// out-of-band `umount` (e.g. `orlop unmount` in another shell) also wakes
    /// it. The kernel NFS client services RPCs from the spawned tokio task in
    /// the background; on any of those signals — or once the mount disappears —
    /// we fall through to `Drop`, which runs `umount` and releases the lease.
    pub fn wait(mut self) -> Result<()> {
        match &mut self.inner {
            #[cfg(target_os = "linux")]
            Inner::Fuse(session) => {
                let mut s = session
                    .take()
                    .ok_or_else(|| anyhow::anyhow!("FUSE session already consumed"))?;
                s.run()?;
            }
            #[cfg(target_os = "macos")]
            Inner::Nfs { rt } => {
                // self.mountpoint and self.inner are disjoint fields, so this
                // borrow coexists with the `&mut self.inner` match above.
                let mountpoint = self.mountpoint.clone();
                rt.block_on(async move {
                    use tokio::signal::unix::{signal, SignalKind};
                    let mut term =
                        signal(SignalKind::terminate()).expect("install SIGTERM handler");
                    let mut int = signal(SignalKind::interrupt()).expect("install SIGINT handler");
                    // Poll for an out-of-band unmount. A foreground / `--from-env`
                    // mount writes no PID file, so `orlop unmount` can't signal
                    // it; it only runs the kernel `umount`. Without this the NFS
                    // server task and the lease-refresh loop keep running after
                    // the filesystem is gone, leaving a process that holds the
                    // mount lease until it expires (the zombie supervisor bug).
                    let mut poll = tokio::time::interval(UMOUNT_POLL_INTERVAL);
                    poll.tick().await; // first tick is immediate; skip it
                    let mut misses: u8 = 0;
                    loop {
                        tokio::select! {
                            _ = term.recv() => break,
                            _ = int.recv() => break,
                            _ = poll.tick() => {
                                let mp = mountpoint.clone();
                                // `/sbin/mount` shell-out is blocking; keep it off
                                // the runtime worker. A probe failure (Err) is
                                // treated as "still mounted" so we never unmount
                                // spuriously.
                                let active = tokio::task::spawn_blocking(move || {
                                    crate::daemon::is_mountpoint_active(&mp)
                                })
                                .await
                                .unwrap_or(true);
                                let (next, stop) = umount_poll_step(active, misses);
                                misses = next;
                                if stop {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        }
        Ok(())
    }

    /// Serve requests through a gate that can park the dispatcher at a clean
    /// handoff boundary.
    #[cfg(target_os = "linux")]
    pub fn wait_with_gate(mut self, gate: &fuser::SessionGate) -> Result<()> {
        let Inner::Fuse(session) = &mut self.inner;
        let mut session = session
            .take()
            .ok_or_else(|| anyhow::anyhow!("FUSE session already consumed"))?;
        session.run_with_gate(gate)?;
        Ok(())
    }
}

/// How often [`MountedFs::wait`] (macOS) re-checks whether the filesystem is
/// still mounted, to catch an out-of-band `umount`.
#[cfg(target_os = "macos")]
const UMOUNT_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Decide whether the macOS wait loop should stop, given the latest mount
/// liveness sample and the running count of consecutive "not mounted" samples.
/// Requires two consecutive misses before stopping so a transient `/sbin/mount`
/// hiccup can't tear down a healthy mount. Returns `(updated_misses, stop)`.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn umount_poll_step(active: bool, misses: u8) -> (u8, bool) {
    if active {
        (0, false)
    } else {
        let misses = misses.saturating_add(1);
        (misses, misses >= 2)
    }
}

impl Drop for MountedFs {
    fn drop(&mut self) {
        // Best-effort. On Linux the FUSE Session's own Drop normally already
        // unmounted; this is for the panic/early-return path. On macOS this
        // is the only thing that runs umount.
        if self.unmount_on_drop {
            let _ = unmount(&self.mountpoint);
        }
    }
}

/// Round-trip health probe, run just after a mount is established, to turn a
/// silently-broken mount into a loud, immediate failure instead of a deferred
/// agent I/O error. It lists the mount root (exercises lookup/getattr/readdir
/// on every platform) and, on a read-write mount, writes + reads back + removes
/// a unique sentinel at the root (exercises create/write/flush/read/unlink, the
/// full data path through to the gateway). Read-only mounts skip the write — a
/// failed write there would be correct, not a fault.
///
/// MUST run on a different thread than the one driving [`MountedFs::wait`]:
/// on Linux the FUSE dispatch loop only starts inside `wait()`, so a probe on
/// the same thread would block forever waiting for its own request to be
/// served. The probe's syscalls simply queue in the kernel until `wait()`
/// begins dispatching, then complete.
pub fn probe_mount(mountpoint: &Path, readonly: bool) -> Result<()> {
    // Draining a couple of entries forces an opendir/readdir round-trip.
    let entries = std::fs::read_dir(mountpoint)
        .with_context(|| format!("mount probe: list root {}", mountpoint.display()))?;
    for entry in entries.take(2) {
        entry.with_context(|| format!("mount probe: readdir {}", mountpoint.display()))?;
    }
    if readonly {
        return Ok(());
    }

    let sentinel = mountpoint.join(format!(".orlop-probe-{}", std::process::id()));
    let payload: &[u8] = b"orlop-mount-probe";
    std::fs::write(&sentinel, payload)
        .with_context(|| format!("mount probe: write {}", sentinel.display()))?;
    let read_back = std::fs::read(&sentinel)
        .with_context(|| format!("mount probe: read {}", sentinel.display()));
    // Clean up before deciding the verdict so a mismatch still leaves no trace.
    let _ = std::fs::remove_file(&sentinel);
    let read_back = read_back?;
    if read_back != payload {
        anyhow::bail!(
            "mount probe: sentinel at {} read back {} bytes, expected {}",
            sentinel.display(),
            read_back.len(),
            payload.len()
        );
    }
    Ok(())
}

/// Exit status of a mount process that lost its lease involuntarily and
/// aborted the mount (sysexits.h EX_UNAVAILABLE), so supervisors can tell an
/// eviction from a crash.
pub const EVICTION_EXIT_CODE: i32 = 69;

/// Involuntary-eviction teardown: leave the mountpoint UNUSABLE instead of
/// cleanly unmounted, then exit the process.
///
/// A clean unmount restores whatever the mountpoint was covering — under a
/// container typically an empty writable directory — so a still-running
/// workload keeps "successfully" writing files that never reach the disk
/// (issue #92). This path does the opposite of `unmount`:
///
/// - Linux: abort the FUSE connection via
///   `/sys/fs/fuse/connections/<minor>/abort` so every in-flight and
///   subsequent syscall on the mountpoint fails with ENOTCONN — enforced by
///   the kernel, impossible for the workload to mistake for success.
/// - Then exit WITHOUT running destructors: `MountedFs::Drop` (and fuser's
///   own mount guard) would run the clean unmount this path exists to avoid.
///   On Linux, process exit closes `/dev/fuse`, which also aborts the
///   connection, so the sysfs write failing (or macOS, which has no abort
///   control) still ends with a dead mount rather than an exposed directory:
///   the macOS NFS server dies with the process and the kernel's `soft` NFS
///   mount turns subsequent I/O into errors after its retries.
///
/// The stale mountpoint left behind is deliberate; reclaim it out of band
/// with `orlop unmount --stale` (Linux) or `umount -f` (macOS).
pub fn evict_abort(mountpoint: &Path) -> ! {
    #[cfg(target_os = "linux")]
    match abort_fuse_connection(mountpoint) {
        Ok(minor) => eprintln!(
            "aborted FUSE connection {minor} for {}; subsequent I/O fails with ENOTCONN",
            mountpoint.display()
        ),
        Err(e) => eprintln!(
            "warning: FUSE abort via sysfs failed for {}: {e:#}; exiting without unmount \
             (closing /dev/fuse aborts the connection as well)",
            mountpoint.display()
        ),
    }
    #[cfg(not(target_os = "linux"))]
    eprintln!(
        "leaving {} mounted without a server; I/O will fail instead of landing \
         in the directory underneath (clean up with `umount -f`)",
        mountpoint.display()
    );
    std::process::exit(EVICTION_EXIT_CODE);
}

/// Abort the kernel side of the Orlop FUSE connection serving `mountpoint`.
/// Returns the connection's device minor on success. Resolution goes through
/// `/proc/self/mountinfo` (no I/O on the possibly-wedged mount itself) and
/// fails closed unless every mount-table layer at the path is an Orlop mount,
/// so this can never abort an unrelated FUSE filesystem.
#[cfg(target_os = "linux")]
pub fn abort_fuse_connection(mountpoint: &Path) -> Result<u32> {
    let minor = crate::mounts::orlop_fuse_device_minor(mountpoint)?;
    let ctl = format!("/sys/fs/fuse/connections/{minor}/abort");
    std::fs::write(&ctl, "1").with_context(|| format!("write {ctl}"))?;
    Ok(minor)
}

/// Run the platform-appropriate kernel-side unmount. Used by both
/// `Command::Unmount` and `MountedFs::Drop`.
pub fn unmount(mountpoint: &Path) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let fusermount = ProcessCommand::new("fusermount3")
            .arg("-u")
            .arg(mountpoint)
            .output();
        if let Ok(o) = fusermount {
            if o.status.success() {
                return Ok(());
            }
        }
        let o = ProcessCommand::new("umount")
            .arg(mountpoint)
            .output()
            .context("failed to run fusermount3 or umount")?;
        if o.status.success() {
            return Ok(());
        }
        anyhow::bail!(
            "failed to unmount {}: {}",
            mountpoint.display(),
            String::from_utf8_lossy(&o.stderr).trim()
        )
    }
    #[cfg(target_os = "macos")]
    {
        let o = ProcessCommand::new("umount")
            .arg(mountpoint)
            .output()
            .context("failed to run umount")?;
        if o.status.success() {
            return Ok(());
        }
        anyhow::bail!(
            "failed to unmount {}: {}",
            mountpoint.display(),
            String::from_utf8_lossy(&o.stderr).trim()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{probe_mount, umount_poll_step};

    #[test]
    fn umount_poll_active_resets_and_continues() {
        // A live mount never stops the wait loop and clears any prior misses.
        assert_eq!(umount_poll_step(true, 0), (0, false));
        assert_eq!(umount_poll_step(true, 1), (0, false));
    }

    #[test]
    fn umount_poll_stops_only_after_two_consecutive_misses() {
        // One miss is not enough (tolerates a transient `/sbin/mount` hiccup).
        let (misses, stop) = umount_poll_step(false, 0);
        assert_eq!((misses, stop), (1, false));
        // A second consecutive miss tears the mount down.
        let (misses, stop) = umount_poll_step(false, misses);
        assert_eq!((misses, stop), (2, true));
    }

    #[test]
    fn umount_poll_miss_then_recover_does_not_stop() {
        let (misses, stop) = umount_poll_step(false, 0);
        assert_eq!((misses, stop), (1, false));
        // Mount reappears before the second miss → counter resets, keep waiting.
        assert_eq!(umount_poll_step(true, misses), (0, false));
    }

    // Exercised against a plain directory rather than a live FUSE/NFS mount —
    // it validates the probe's own read/write/cleanup logic; the threading vs.
    // `wait()` integration is covered by the live mount path.
    #[test]
    fn probe_rw_roundtrips_and_leaves_no_trace() {
        let tmp = tempfile::tempdir().unwrap();
        probe_mount(tmp.path(), false).unwrap();
        let leftover = std::fs::read_dir(tmp.path()).unwrap().count();
        assert_eq!(leftover, 0, "probe left a file behind");
    }

    #[test]
    fn probe_readonly_skips_the_write() {
        let tmp = tempfile::tempdir().unwrap();
        probe_mount(tmp.path(), true).unwrap();
        assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);
    }

    #[test]
    fn probe_fails_on_missing_mountpoint() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("nope");
        assert!(probe_mount(&missing, false).is_err());
    }
}
