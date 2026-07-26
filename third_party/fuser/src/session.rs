//! Filesystem session
//!
//! A session runs a filesystem implementation while it is being mounted to a specific mount
//! point. A session begins by mounting the filesystem and ends by unmounting it. While the
//! filesystem is mounted, the session loop receives, dispatches and replies to kernel requests
//! for filesystem operations under its mount point.

use libc::{EAGAIN, EINTR, ENODEV, ENOENT};
use log::{info, warn};
use nix::unistd::geteuid;
use std::fmt;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, Once};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use std::{io, ops::DerefMut};

use crate::ll::fuse_abi as abi;
use crate::request::Request;
use crate::Filesystem;
use crate::MountOption;
use crate::{channel::Channel, mnt::Mount};
#[cfg(feature = "abi-7-11")]
use crate::{channel::ChannelSender, notify::Notifier};

/// The max size of write requests from the kernel. The absolute minimum is 4k,
/// FUSE recommends at least 128k, max 16M. The FUSE default is 16M on macOS
/// and 128k on other systems.
pub const MAX_WRITE_SIZE: usize = 16 * 1024 * 1024;

/// Size of the buffer for reading a request from the kernel. Since the kernel may send
/// up to MAX_WRITE_SIZE bytes in a write request, we use that value plus some extra space.
const BUFFER_SIZE: usize = MAX_WRITE_SIZE + 4096;

#[derive(Default, Debug, Eq, PartialEq)]
/// How requests should be filtered based on the calling UID.
pub enum SessionACL {
    /// Allow requests from any user. Corresponds to the `allow_other` mount option.
    All,
    /// Allow requests from root. Corresponds to the `allow_root` mount option.
    RootAndOwner,
    /// Allow requests from the owning UID. This is FUSE's default mode of operation.
    #[default]
    Owner,
}

/// Cooperative boundary used to park a session between FUSE requests.
///
/// `pause` never interrupts a request that is being dispatched. If the event
/// loop is blocked in `read(2)`, a no-op SIGUSR2 wakes it so it can observe the
/// pause request. `resume` releases the same loop after a failed handoff.
#[derive(Debug)]
pub struct SessionGate {
    state: Mutex<GateState>,
    changed: Condvar,
}

#[derive(Clone, Copy, Debug)]
struct RegisteredThread(libc::pthread_t);

// SAFETY: pthread_t is an opaque thread identifier specifically designed to
// be passed to pthread_kill from another thread. Some libc implementations
// represent it as a raw pointer, which is not Send by default even though the
// POSIX operation is thread-safe.
unsafe impl Send for RegisteredThread {}

#[derive(Debug, Default)]
struct GateState {
    pause_requested: bool,
    parked: bool,
    reading: bool,
    dispatching: bool,
    thread: Option<RegisteredThread>,
    protocol: Option<(u32, u32)>,
}

static INSTALL_INTERRUPT_HANDLER: Once = Once::new();

extern "C" fn handoff_interrupt_handler(_signal: libc::c_int) {}

impl Default for SessionGate {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionGate {
    /// Construct an unpaused gate.
    pub fn new() -> Self {
        INSTALL_INTERRUPT_HANDLER.call_once(|| unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = handoff_interrupt_handler as *const () as usize;
            libc::sigemptyset(&mut action.sa_mask);
            action.sa_flags = 0;
            libc::sigaction(libc::SIGUSR2, &action, std::ptr::null_mut());
        });
        Self {
            state: Mutex::new(GateState::default()),
            changed: Condvar::new(),
        }
    }

    /// Request a pause and wait until the dispatch loop is parked between
    /// requests. A timeout cancels the request and leaves the loop running.
    pub fn pause(&self, timeout: Duration) -> io::Result<()> {
        let deadline = Instant::now() + timeout;
        let mut state = self.state.lock().unwrap();
        if state.pause_requested {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "session pause already requested",
            ));
        }
        let thread = state.thread.ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "session loop is not running")
        })?;
        state.pause_requested = true;
        if state.reading {
            // SAFETY: `thread` is registered by the live run_with_gate thread,
            // and SIGUSR2 has a process-wide no-op handler installed in new().
            let result = unsafe { libc::pthread_kill(thread.0, libc::SIGUSR2) };
            if result != 0 {
                state.pause_requested = false;
                return Err(io::Error::from_raw_os_error(result));
            }
        }
        while !state.parked {
            let now = Instant::now();
            if now >= deadline {
                state.pause_requested = false;
                self.changed.notify_all();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "timed out parking FUSE request loop",
                ));
            }
            let wait = deadline.saturating_duration_since(now);
            let (next, result) = self.changed.wait_timeout(state, wait).unwrap();
            state = next;
            if result.timed_out() && !state.parked {
                state.pause_requested = false;
                self.changed.notify_all();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "timed out parking FUSE request loop",
                ));
            }
        }
        Ok(())
    }

    /// Resume a loop parked by [`SessionGate::pause`].
    pub fn resume(&self) {
        let mut state = self.state.lock().unwrap();
        state.pause_requested = false;
        self.changed.notify_all();
        while state.parked {
            state = self.changed.wait(state).unwrap();
        }
    }

    /// Negotiated FUSE ABI observed after the INIT request was dispatched.
    pub fn protocol_version(&self) -> Option<(u32, u32)> {
        self.state.lock().unwrap().protocol
    }

    fn register_current_thread(&self) {
        let mut state = self.state.lock().unwrap();
        // SAFETY: pthread_self has no preconditions.
        state.thread = Some(RegisteredThread(unsafe { libc::pthread_self() }));
        self.changed.notify_all();
    }

    fn before_receive(&self) {
        let state = self.state.lock().unwrap();
        let mut state = self.park_wait(state);
        state.reading = true;
    }

    fn before_dispatch(&self) {
        let mut state = self.state.lock().unwrap();
        state.reading = false;
        let mut state = self.park_wait(state);
        state.dispatching = true;
    }

    fn after_receive_error(&self) {
        let mut state = self.state.lock().unwrap();
        state.reading = false;
        let _state = self.park_wait(state);
    }

    fn after_dispatch(&self, protocol: Option<(u32, u32)>) {
        let mut state = self.state.lock().unwrap();
        state.dispatching = false;
        if protocol.is_some() {
            state.protocol = protocol;
        }
        let _state = self.park_wait(state);
    }

    fn park_wait<'a>(
        &self,
        mut state: std::sync::MutexGuard<'a, GateState>,
    ) -> std::sync::MutexGuard<'a, GateState> {
        if state.pause_requested {
            state.parked = true;
            self.changed.notify_all();
            while state.pause_requested {
                state = self.changed.wait(state).unwrap();
            }
            state.parked = false;
            self.changed.notify_all();
        }
        state
    }
}

/// The session data structure
#[derive(Debug)]
pub struct Session<FS: Filesystem> {
    /// Filesystem operation implementations
    pub(crate) filesystem: FS,
    /// Communication channel to the kernel driver
    pub(crate) ch: Channel,
    /// Handle to the mount.  Dropping this unmounts.
    mount: Arc<Mutex<Option<(PathBuf, Mount)>>>,
    /// Whether to restrict access to owner, root + owner, or unrestricted
    /// Used to implement allow_root and auto_unmount
    pub(crate) allowed: SessionACL,
    /// User that launched the fuser process
    pub(crate) session_owner: u32,
    /// FUSE protocol major version
    pub(crate) proto_major: u32,
    /// FUSE protocol minor version
    pub(crate) proto_minor: u32,
    /// True if the filesystem is initialized (init operation done)
    pub(crate) initialized: bool,
    /// True if the filesystem was destroyed (destroy operation done)
    pub(crate) destroyed: bool,
}

impl<FS: Filesystem> AsFd for Session<FS> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.ch.as_fd()
    }
}

impl<FS: Filesystem> Session<FS> {
    /// Create a new session by mounting the given filesystem to the given mountpoint
    pub fn new<P: AsRef<Path>>(
        filesystem: FS,
        mountpoint: P,
        options: &[MountOption],
    ) -> io::Result<Session<FS>> {
        let mountpoint = mountpoint.as_ref();
        info!("Mounting {}", mountpoint.display());
        // If AutoUnmount is requested, but not AllowRoot or AllowOther we enforce the ACL
        // ourself and implicitly set AllowOther because fusermount needs allow_root or allow_other
        // to handle the auto_unmount option
        let (file, mount) = if options.contains(&MountOption::AutoUnmount)
            && !(options.contains(&MountOption::AllowRoot)
                || options.contains(&MountOption::AllowOther))
        {
            warn!("Given auto_unmount without allow_root or allow_other; adding allow_other, with userspace permission handling");
            let mut modified_options = options.to_vec();
            modified_options.push(MountOption::AllowOther);
            Mount::new(mountpoint, &modified_options)?
        } else {
            Mount::new(mountpoint, options)?
        };

        let ch = Channel::new(file);
        let allowed = if options.contains(&MountOption::AllowRoot) {
            SessionACL::RootAndOwner
        } else if options.contains(&MountOption::AllowOther) {
            SessionACL::All
        } else {
            SessionACL::Owner
        };

        Ok(Session {
            filesystem,
            ch,
            mount: Arc::new(Mutex::new(Some((mountpoint.to_owned(), mount)))),
            allowed,
            session_owner: geteuid().as_raw(),
            proto_major: 0,
            proto_minor: 0,
            initialized: false,
            destroyed: false,
        })
    }

    /// Wrap an existing /dev/fuse file descriptor. This doesn't mount the
    /// filesystem anywhere; that must be done separately.
    pub fn from_fd(filesystem: FS, fd: OwnedFd, acl: SessionACL) -> Self {
        let ch = Channel::new(Arc::new(fd.into()));
        Session {
            filesystem,
            ch,
            mount: Arc::new(Mutex::new(None)),
            allowed: acl,
            session_owner: geteuid().as_raw(),
            proto_major: 0,
            proto_minor: 0,
            initialized: false,
            destroyed: false,
        }
    }

    /// Wrap an existing, already-initialized `/dev/fuse` descriptor.
    ///
    /// This is only valid when a predecessor completed the INIT exchange for
    /// the same connection and transferred the negotiated protocol version
    /// together with the descriptor.
    pub fn from_initialized_fd(
        filesystem: FS,
        fd: OwnedFd,
        acl: SessionACL,
        proto_major: u32,
        proto_minor: u32,
    ) -> io::Result<Self> {
        if proto_major != 7 || proto_minor < 6 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported inherited FUSE ABI {proto_major}.{proto_minor}"),
            ));
        }
        let mut session = Self::from_fd(filesystem, fd, acl);
        session.proto_major = proto_major;
        session.proto_minor = proto_minor;
        session.initialized = true;
        Ok(session)
    }

    /// Run the session loop that receives kernel requests and dispatches them to method
    /// calls into the filesystem. This read-dispatch-loop is non-concurrent to prevent
    /// having multiple buffers (which take up much memory), but the filesystem methods
    /// may run concurrent by spawning threads.
    pub fn run(&mut self) -> io::Result<()> {
        self.run_inner(None)
    }

    /// Run the request loop with a cooperative handoff gate.
    pub fn run_with_gate(&mut self, gate: &SessionGate) -> io::Result<()> {
        gate.register_current_thread();
        self.run_inner(Some(gate))
    }

    fn run_inner(&mut self, gate: Option<&SessionGate>) -> io::Result<()> {
        // Buffer for receiving requests from the kernel. Only one is allocated and
        // it is reused immediately after dispatching to conserve memory and allocations.
        let mut buffer = vec![0; BUFFER_SIZE];
        let buf = aligned_sub_buf(
            buffer.deref_mut(),
            std::mem::align_of::<abi::fuse_in_header>(),
        );
        loop {
            if let Some(gate) = gate {
                gate.before_receive();
            }
            // Read the next request from the given channel to kernel driver
            // The kernel driver makes sure that we get exactly one request per read
            match self.ch.receive(buf) {
                Ok(size) => {
                    if let Some(gate) = gate {
                        gate.before_dispatch();
                    }
                    let result = match Request::new(self.ch.sender(), &buf[..size]) {
                        // Dispatch request
                        Some(req) => {
                            req.dispatch(self);
                            None
                        }
                        // Quit loop on illegal request
                        None => Some(Ok(())),
                    };
                    if let Some(gate) = gate {
                        let protocol = self
                            .initialized
                            .then_some((self.proto_major, self.proto_minor));
                        gate.after_dispatch(protocol);
                    }
                    if let Some(result) = result {
                        return result;
                    }
                }
                Err(err) => {
                    if let Some(gate) = gate {
                        gate.after_receive_error();
                    }
                    match err.raw_os_error() {
                        // Operation interrupted. Accordingly to FUSE, this is safe to retry
                        Some(ENOENT) => continue,
                        // Interrupted system call, retry
                        Some(EINTR) => continue,
                        // Explicitly try again
                        Some(EAGAIN) => continue,
                        // Filesystem was unmounted, quit the loop
                        Some(ENODEV) => break,
                        // Unhandled error
                        _ => return Err(err),
                    }
                }
            }
        }
        Ok(())
    }

    /// Unmount the filesystem
    pub fn unmount(&mut self) {
        drop(std::mem::take(&mut *self.mount.lock().unwrap()));
    }

    /// Returns a thread-safe object that can be used to unmount the Filesystem
    pub fn unmount_callable(&mut self) -> SessionUnmounter {
        SessionUnmounter {
            mount: self.mount.clone(),
        }
    }

    /// Returns an object that can be used to send notifications to the kernel
    #[cfg(feature = "abi-7-11")]
    pub fn notifier(&self) -> Notifier {
        Notifier::new(self.ch.sender())
    }
}

#[derive(Debug)]
/// A thread-safe object that can be used to unmount a Filesystem
pub struct SessionUnmounter {
    mount: Arc<Mutex<Option<(PathBuf, Mount)>>>,
}

impl SessionUnmounter {
    /// Unmount the filesystem
    pub fn unmount(&mut self) -> io::Result<()> {
        drop(std::mem::take(&mut *self.mount.lock().unwrap()));
        Ok(())
    }
}

fn aligned_sub_buf(buf: &mut [u8], alignment: usize) -> &mut [u8] {
    let off = alignment - (buf.as_ptr() as usize) % alignment;
    if off == alignment {
        buf
    } else {
        &mut buf[off..]
    }
}

impl<FS: 'static + Filesystem + Send> Session<FS> {
    /// Run the session loop in a background thread
    pub fn spawn(self) -> io::Result<BackgroundSession> {
        BackgroundSession::new(self)
    }
}

impl<FS: Filesystem> Drop for Session<FS> {
    fn drop(&mut self) {
        if !self.destroyed {
            self.filesystem.destroy();
            self.destroyed = true;
        }

        if let Some((mountpoint, _mount)) = std::mem::take(&mut *self.mount.lock().unwrap()) {
            info!("unmounting session at {}", mountpoint.display());
        }
    }
}

/// The background session data structure
pub struct BackgroundSession {
    /// Thread guard of the background session
    pub guard: JoinHandle<io::Result<()>>,
    /// Object for creating Notifiers for client use
    #[cfg(feature = "abi-7-11")]
    sender: ChannelSender,
    /// Ensures the filesystem is unmounted when the session ends
    _mount: Option<Mount>,
}

impl BackgroundSession {
    /// Create a new background session for the given session by running its
    /// session loop in a background thread. If the returned handle is dropped,
    /// the filesystem is unmounted and the given session ends.
    pub fn new<FS: Filesystem + Send + 'static>(se: Session<FS>) -> io::Result<BackgroundSession> {
        #[cfg(feature = "abi-7-11")]
        let sender = se.ch.sender();
        // Take the fuse_session, so that we can unmount it
        let mount = std::mem::take(&mut *se.mount.lock().unwrap()).map(|(_, mount)| mount);
        let guard = thread::spawn(move || {
            let mut se = se;
            se.run()
        });
        Ok(BackgroundSession {
            guard,
            #[cfg(feature = "abi-7-11")]
            sender,
            _mount: mount,
        })
    }
    /// Unmount the filesystem and join the background thread.
    pub fn join(self) {
        let Self {
            guard,
            #[cfg(feature = "abi-7-11")]
                sender: _,
            _mount,
        } = self;
        drop(_mount);
        guard.join().unwrap().unwrap();
    }

    /// Returns an object that can be used to send notifications to the kernel
    #[cfg(feature = "abi-7-11")]
    pub fn notifier(&self) -> Notifier {
        Notifier::new(self.sender.clone())
    }
}

// replace with #[derive(Debug)] if Debug ever gets implemented for
// thread_scoped::JoinGuard
impl fmt::Debug for BackgroundSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "BackgroundSession {{ guard: JoinGuard<()> }}",)
    }
}

#[cfg(test)]
mod handoff_tests {
    use super::*;

    #[test]
    fn gate_parks_an_interrupted_reader_and_resumes() {
        let gate = Arc::new(SessionGate::new());
        let worker_gate = Arc::clone(&gate);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let worker = thread::spawn(move || {
            worker_gate.register_current_thread();
            worker_gate.before_receive();
            ready_tx.send(()).unwrap();
            // SessionGate::pause sends SIGUSR2 to interrupt this syscall.
            unsafe { libc::pause() };
            worker_gate.after_receive_error();
        });
        ready_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        gate.pause(Duration::from_secs(1)).unwrap();
        gate.resume();
        worker.join().unwrap();
    }

    #[test]
    fn gate_rejects_pause_before_loop_registration() {
        let gate = SessionGate::new();
        let error = gate.pause(Duration::from_millis(10)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotConnected);
    }

    #[test]
    fn initialized_fd_rejects_invalid_protocol() {
        struct EmptyFs;
        impl Filesystem for EmptyFs {}
        let file = std::fs::File::open("/dev/null").unwrap();
        let fd: OwnedFd = file.into();
        let result = Session::from_initialized_fd(EmptyFs, fd, SessionACL::All, 6, 0);
        assert!(result.is_err());
    }
}
