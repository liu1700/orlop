//! Integration test for the issue #92 eviction primitive against a REAL
//! kernel FUSE mount: after `orlop::mount::abort_fuse_connection`, every
//! syscall on the mountpoint — reads AND writes — must fail loudly with
//! ENOTCONN instead of landing in whatever directory a clean unmount would
//! expose. This is the kernel-enforced property the unit tests around
//! `EvictionAction` cannot cover.
//!
//! Needs `/dev/fuse`, mount privileges (CAP_SYS_ADMIN or root), and the
//! fusectl tree at `/sys/fs/fuse/connections`. Each missing prerequisite
//! self-skips with a message so plain `cargo test` stays green on
//! unprivileged hosts; CI runners with FUSE run the real thing.

#![cfg(target_os = "linux")]

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::{Duration, SystemTime};

use fuser::{FileAttr, FileType, Filesystem, MountOption, ReplyAttr, Request, Session};

/// The smallest filesystem that serves a stat-able empty root directory.
/// Attr TTL is zero so every `stat` round-trips to userspace — a cached attr
/// could otherwise answer the post-abort probe and mask the ENOTCONN this
/// test exists to observe.
struct EmptyDirFs;

fn root_attr() -> FileAttr {
    let now = SystemTime::now();
    FileAttr {
        ino: 1,
        size: 0,
        blocks: 0,
        atime: now,
        mtime: now,
        ctime: now,
        crtime: now,
        kind: FileType::Directory,
        perm: 0o755,
        nlink: 2,
        uid: 0,
        gid: 0,
        rdev: 0,
        blksize: 4096,
        flags: 0,
    }
}

impl Filesystem for EmptyDirFs {
    fn getattr(&mut self, _req: &Request<'_>, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        if ino == 1 {
            reply.attr(&Duration::ZERO, &root_attr());
        } else {
            reply.error(libc::ENOENT);
        }
    }
}

/// `umount2(MNT_DETACH)` — how `orlop unmount --stale` reclaims the stale
/// mountpoint an abort deliberately leaves behind; here it lets the tempdir
/// be removed on test exit.
fn lazy_unmount(path: &Path) {
    let c = CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: c is a valid NUL-terminated path that outlives the call.
    unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) };
}

#[test]
fn abort_turns_a_live_fuse_mount_into_enotconn() {
    let tmp = tempfile::tempdir().unwrap();
    let mp = tmp.path().join("mnt");
    std::fs::create_dir_all(&mp).unwrap();

    // FSName("orlop") is what production mounts pass; it is also what lets
    // mounts::orlop_fuse_device_minor recognize the mount as ours.
    let options = [MountOption::FSName("orlop".to_string())];
    let session = match Session::new(EmptyDirFs, &mp, &options) {
        Ok(session) => session,
        Err(err) => {
            eprintln!("skipping: cannot establish a FUSE mount here ({err})");
            return;
        }
    };

    let dispatcher = std::thread::spawn(move || {
        let mut session = session;
        let result = session.run();
        // Mimic the production eviction path: `evict_abort` exits the process
        // WITHOUT running destructors, because fuser's mount guard would
        // cleanly unmount the aborted connection and re-expose the directory
        // underneath — the exact failure mode under test. Forgetting the
        // session is this test's in-process equivalent.
        std::mem::forget(session);
        result
    });

    // First stat round-trips through EmptyDirFs (it queues until the
    // dispatcher thread starts serving), proving the mount is live pre-abort.
    std::fs::metadata(&mp).expect("live mount must serve getattr before the abort");

    let minor = orlop::mounts::orlop_fuse_device_minor(&mp)
        .expect("mountinfo must resolve the orlop FUSE device minor");
    if !Path::new(&format!("/sys/fs/fuse/connections/{minor}")).is_dir() {
        eprintln!("skipping: fusectl (/sys/fs/fuse/connections/{minor}) is not available");
        lazy_unmount(&mp);
        let _ = dispatcher.join();
        return;
    }

    let aborted = orlop::mount::abort_fuse_connection(&mp).expect("abort via sysfs");
    assert_eq!(aborted, minor, "abort must target the mount's own connection");

    // The kernel now fails every request on the mountpoint. ENOTCONN — not a
    // silently-working empty directory — is the whole point of the eviction
    // path: reads cannot be mistaken for an empty disk...
    let read_err = std::fs::metadata(&mp).expect_err("stat after abort must fail");
    assert_eq!(
        read_err.raw_os_error(),
        Some(libc::ENOTCONN),
        "stat after abort: {read_err}"
    );
    // ...and writes cannot report success while going nowhere (the #92
    // incident shape: files "saved" into the exposed scratch dir).
    let write_err =
        std::fs::write(mp.join("x-article-draft.md"), b"data").expect_err("write must fail");
    assert_eq!(
        write_err.raw_os_error(),
        Some(libc::ENOTCONN),
        "write after abort: {write_err}"
    );

    // The dispatch loop observes the abort as ENODEV and exits cleanly, so a
    // real mount client's `wait()` returns instead of hanging.
    dispatcher
        .join()
        .expect("dispatcher thread panicked")
        .expect("Session::run should treat the abort as a clean unmount");

    lazy_unmount(&mp);
}
