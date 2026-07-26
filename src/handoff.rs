//! Authenticated Linux FUSE live-handoff protocol.
//!
//! The old daemon owns the listener and remains the sole request consumer
//! until a successor has reconstructed all userspace state. The initialized
//! `/dev/fuse` descriptor is transferred with `SCM_RIGHTS`; a versioned rmp
//! frame carries the configuration, inode/FH snapshot, and negotiated ABI.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::config::Config;
use crate::enroll::EnrolledCert;

pub const PROTOCOL_VERSION: u32 = 1;
const MAX_FRAME_BYTES: usize = 256 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeSpec {
    pub config: Config,
    pub mountpoint: PathBuf,
    pub credentials: Option<PathBuf>,
    pub enrolled: Option<EnrolledCert>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Transfer {
    pub protocol_version: u32,
    pub runtime: RuntimeSpec,
    pub snapshot: crate::fs::HandoffSnapshot,
    pub fuse_proto_major: u32,
    pub fuse_proto_minor: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    Inspect {
        protocol_version: u32,
        mountpoint: PathBuf,
    },
    Upgrade {
        protocol_version: u32,
        mountpoint: PathBuf,
        binary: PathBuf,
    },
    Successor {
        protocol_version: u32,
        token: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    Info {
        protocol_version: u32,
        pid: u32,
        mountpoint: PathBuf,
    },
    Complete {
        protocol_version: u32,
        successor_pid: u32,
    },
    Prepared,
    Commit,
    Activated,
    Failed(String),
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::io::{self, IoSlice, IoSliceMut, Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::Path;
    use std::process::{Child, Command, Stdio};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use anyhow::{Context, Result};

    use super::{Request, Response, RuntimeSpec, Transfer, MAX_FRAME_BYTES, PROTOCOL_VERSION};
    use crate::fs::GatewayHandoff;

    const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
    const PREPARE_TIMEOUT: Duration = Duration::from_secs(60);
    const PARK_TIMEOUT: Duration = Duration::from_secs(15);

    pub struct Service {
        pub socket_path: std::path::PathBuf,
        cleanup_path: Arc<Mutex<std::path::PathBuf>>,
        _thread: std::thread::JoinHandle<()>,
    }

    impl Service {
        pub fn start(
            runtime: RuntimeSpec,
            fuse_fd: OwnedFd,
            gateway: GatewayHandoff,
            gate: Arc<fuser::SessionGate>,
        ) -> Result<Self> {
            let socket_path = socket_path(&runtime.mountpoint)?;
            prepare_socket_path(&socket_path)?;
            Self::bind(runtime, fuse_fd, gateway, gate, socket_path)
        }

        /// Bind the successor service beside the active predecessor socket.
        /// `activate` later atomically replaces the public pathname.
        pub fn start_staged(
            runtime: RuntimeSpec,
            fuse_fd: OwnedFd,
            gateway: GatewayHandoff,
            gate: Arc<fuser::SessionGate>,
            active_socket: &Path,
        ) -> Result<Self> {
            let file_name = active_socket
                .file_name()
                .ok_or_else(|| anyhow::anyhow!("handoff socket has no file name"))?
                .to_string_lossy();
            let staged =
                active_socket.with_file_name(format!("{file_name}.next-{}", std::process::id()));
            prepare_socket_path(&staged)?;
            Self::bind(runtime, fuse_fd, gateway, gate, staged)
        }

        fn bind(
            runtime: RuntimeSpec,
            fuse_fd: OwnedFd,
            gateway: GatewayHandoff,
            gate: Arc<fuser::SessionGate>,
            socket_path: std::path::PathBuf,
        ) -> Result<Self> {
            let listener = UnixListener::bind(&socket_path)
                .with_context(|| format!("bind handoff socket {}", socket_path.display()))?;
            fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))
                .with_context(|| format!("chmod handoff socket {}", socket_path.display()))?;

            let cleanup_path = Arc::new(Mutex::new(socket_path.clone()));
            let thread_path = Arc::clone(&cleanup_path);
            let thread = std::thread::Builder::new()
                .name("orlop-handoff".into())
                .spawn(move || {
                    if let Err(error) = serve(listener, runtime, fuse_fd, gateway, gate) {
                        eprintln!("warning: live handoff service stopped: {error:#}");
                    }
                    if let Ok(path) = thread_path.lock() {
                        let _ = fs::remove_file(&*path);
                    }
                })
                .context("spawn handoff service")?;
            Ok(Self {
                socket_path,
                cleanup_path,
                _thread: thread,
            })
        }

        /// Publish a fully prepared successor using one atomic pathname swap.
        pub fn activate(&mut self, active_socket: &Path) -> Result<()> {
            match fs::symlink_metadata(active_socket) {
                Ok(metadata)
                    if metadata.file_type().is_socket()
                        && metadata.uid() == unsafe { libc::geteuid() } => {}
                Ok(_) => anyhow::bail!(
                    "refusing to replace unsafe handoff path {}",
                    active_socket.display()
                ),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            let mut cleanup_path = self
                .cleanup_path
                .lock()
                .map_err(|_| anyhow::anyhow!("handoff cleanup path lock poisoned"))?;
            fs::rename(&self.socket_path, active_socket).with_context(|| {
                format!(
                    "activate handoff socket {} over {}",
                    self.socket_path.display(),
                    active_socket.display()
                )
            })?;
            self.socket_path = active_socket.to_path_buf();
            *cleanup_path = self.socket_path.clone();
            Ok(())
        }
    }

    fn serve(
        listener: UnixListener,
        runtime: RuntimeSpec,
        fuse_fd: OwnedFd,
        gateway: GatewayHandoff,
        gate: Arc<fuser::SessionGate>,
    ) -> Result<()> {
        loop {
            let (mut requester, _) = match listener.accept() {
                Ok(connection) => connection,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error).context("accept handoff request"),
            };
            if let Err(error) = handle_request(
                &listener,
                &mut requester,
                &runtime,
                fuse_fd.as_raw_fd(),
                &gateway,
                &gate,
            ) {
                eprintln!("warning: rejected live handoff request: {error:#}");
                let _ = write_frame(&mut requester, &Response::Failed(format!("{error:#}")));
            }
        }
    }

    fn handle_request(
        listener: &UnixListener,
        requester: &mut UnixStream,
        runtime: &RuntimeSpec,
        fuse_fd: RawFd,
        gateway: &GatewayHandoff,
        gate: &fuser::SessionGate,
    ) -> Result<()> {
        authenticate_peer(requester)?;
        requester
            .set_read_timeout(Some(PREPARE_TIMEOUT))
            .context("set request timeout")?;
        requester
            .set_write_timeout(Some(PREPARE_TIMEOUT))
            .context("set response timeout")?;
        match read_frame::<Request>(requester)? {
            Request::Inspect {
                protocol_version,
                mountpoint,
            } => {
                check_request(protocol_version, &mountpoint, &runtime.mountpoint)?;
                write_frame(
                    requester,
                    &Response::Info {
                        protocol_version: PROTOCOL_VERSION,
                        pid: std::process::id(),
                        mountpoint: runtime.mountpoint.clone(),
                    },
                )?;
            }
            Request::Upgrade {
                protocol_version,
                mountpoint,
                binary,
            } => {
                check_request(protocol_version, &mountpoint, &runtime.mountpoint)?;
                upgrade(
                    listener, requester, runtime, fuse_fd, gateway, gate, &binary,
                )?;
            }
            Request::Successor { .. } => {
                write_frame(
                    requester,
                    &Response::Failed("unsolicited successor connection".into()),
                )?;
            }
        }
        Ok(())
    }

    fn upgrade(
        listener: &UnixListener,
        requester: &mut UnixStream,
        runtime: &RuntimeSpec,
        fuse_fd: RawFd,
        gateway: &GatewayHandoff,
        gate: &fuser::SessionGate,
        binary: &Path,
    ) -> Result<()> {
        validate_binary(binary)?;
        let token = random_token()?;
        let mut child = spawn_successor(binary, &socket_path(&runtime.mountpoint)?, &token)?;
        let result = upgrade_inner(
            listener, runtime, fuse_fd, gateway, gate, &token, &mut child,
        );
        if result.is_err() {
            terminate_child(&mut child);
        }
        let successor_pid = result?;
        let _ = write_frame(
            requester,
            &Response::Complete {
                protocol_version: PROTOCOL_VERSION,
                successor_pid,
            },
        );
        // The successor has acknowledged activation and owns a duplicate fd.
        // _exit intentionally skips Session/MountedFs destructors: running
        // either would unmount the connection we just transferred.
        unsafe { libc::_exit(0) }
    }

    fn upgrade_inner(
        listener: &UnixListener,
        runtime: &RuntimeSpec,
        fuse_fd: RawFd,
        gateway: &GatewayHandoff,
        gate: &fuser::SessionGate,
        token: &str,
        child: &mut Child,
    ) -> Result<u32> {
        let mut successor = accept_successor(listener, token, child)?;
        gate.pause(PARK_TIMEOUT).context("park FUSE dispatcher")?;
        let attempt = (|| -> Result<()> {
            let snapshot = gateway.prepare().context("prepare FUSE state snapshot")?;
            let (major, minor) = gate
                .protocol_version()
                .ok_or_else(|| anyhow::anyhow!("FUSE INIT handshake has not completed"))?;
            let transfer = Transfer {
                protocol_version: PROTOCOL_VERSION,
                runtime: runtime.clone(),
                snapshot,
                fuse_proto_major: major,
                fuse_proto_minor: minor,
            };
            send_fd(&successor, fuse_fd)?;
            write_frame(&mut successor, &transfer)?;
            match read_frame::<Response>(&mut successor)? {
                Response::Prepared => {}
                Response::Failed(message) => anyhow::bail!("successor rejected handoff: {message}"),
                other => anyhow::bail!("unexpected successor response: {other:?}"),
            }
            write_frame(&mut successor, &Response::Commit)?;
            match read_frame::<Response>(&mut successor)? {
                Response::Activated => Ok(()),
                Response::Failed(message) => {
                    anyhow::bail!("successor failed to activate handoff: {message}")
                }
                other => anyhow::bail!("unexpected activation response: {other:?}"),
            }
        })();
        if let Err(error) = attempt {
            let recovery = gateway
                .recover_leases()
                .context("recover predecessor leases after failed handoff");
            gate.resume();
            if let Err(recovery_error) = recovery {
                return Err(error.context(format!("{recovery_error:#}")));
            }
            return Err(error);
        }
        Ok(child.id())
    }

    fn accept_successor(
        listener: &UnixListener,
        token: &str,
        child: &mut Child,
    ) -> Result<UnixStream> {
        listener.set_nonblocking(true)?;
        let deadline = Instant::now() + CONNECT_TIMEOUT;
        let result = (|| -> Result<UnixStream> {
            loop {
                if let Some(status) = child.try_wait().context("poll successor")? {
                    break Err(anyhow::anyhow!("successor exited before handoff: {status}"));
                }
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        authenticate_peer(&stream)?;
                        stream.set_read_timeout(Some(PREPARE_TIMEOUT))?;
                        stream.set_write_timeout(Some(PREPARE_TIMEOUT))?;
                        match read_frame::<Request>(&mut stream)? {
                            Request::Successor {
                                protocol_version,
                                token: received,
                            } if protocol_version == PROTOCOL_VERSION && received == token => {
                                break Ok(stream);
                            }
                            _ => {
                                let _ = write_frame(
                                    &mut stream,
                                    &Response::Failed("invalid successor token or protocol".into()),
                                );
                            }
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            break Err(anyhow::anyhow!("timed out waiting for successor"));
                        }
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Err(error) => break Err(error.into()),
                }
            }
        })();
        let restore = listener
            .set_nonblocking(false)
            .context("restore blocking handoff listener");
        restore?;
        result
    }

    fn spawn_successor(binary: &Path, socket: &Path, token: &str) -> Result<Child> {
        Command::new(binary)
            .arg("__handoff-resume")
            .arg("--socket")
            .arg(socket)
            .arg("--token")
            .arg(token)
            .stdin(Stdio::null())
            .spawn()
            .with_context(|| format!("spawn successor {}", binary.display()))
    }

    fn validate_binary(binary: &Path) -> Result<()> {
        if !binary.is_absolute() {
            anyhow::bail!("replacement binary must be an absolute path");
        }
        let meta = fs::metadata(binary)
            .with_context(|| format!("stat replacement binary {}", binary.display()))?;
        if !meta.is_file() || meta.permissions().mode() & 0o111 == 0 {
            anyhow::bail!("replacement binary is not an executable regular file");
        }
        Ok(())
    }

    fn terminate_child(child: &mut Child) {
        let _ = child.kill();
        let _ = child.wait();
    }

    fn check_request(version: u32, requested: &Path, actual: &Path) -> Result<()> {
        if version != PROTOCOL_VERSION {
            anyhow::bail!(
                "handoff protocol mismatch: requester {version}, daemon {PROTOCOL_VERSION}"
            );
        }
        if requested != actual {
            anyhow::bail!(
                "handoff socket belongs to {}, not {}",
                actual.display(),
                requested.display()
            );
        }
        Ok(())
    }

    pub fn inspect(mountpoint: &Path) -> Result<u32> {
        let mut stream = connect(mountpoint)?;
        write_frame(
            &mut stream,
            &Request::Inspect {
                protocol_version: PROTOCOL_VERSION,
                mountpoint: mountpoint.to_path_buf(),
            },
        )?;
        match read_frame::<Response>(&mut stream)? {
            Response::Info {
                protocol_version,
                pid,
                mountpoint: actual,
            } if protocol_version == PROTOCOL_VERSION && actual == mountpoint => Ok(pid),
            Response::Failed(message) => anyhow::bail!("{message}"),
            other => anyhow::bail!("unexpected handoff response: {other:?}"),
        }
    }

    pub fn request_upgrade(mountpoint: &Path, binary: &Path) -> Result<u32> {
        let mut stream = connect(mountpoint)?;
        stream.set_read_timeout(Some(Duration::from_secs(120)))?;
        write_frame(
            &mut stream,
            &Request::Upgrade {
                protocol_version: PROTOCOL_VERSION,
                mountpoint: mountpoint.to_path_buf(),
                binary: binary.to_path_buf(),
            },
        )?;
        match read_frame::<Response>(&mut stream)? {
            Response::Complete {
                protocol_version,
                successor_pid,
            } if protocol_version == PROTOCOL_VERSION => Ok(successor_pid),
            Response::Failed(message) => anyhow::bail!("{message}"),
            other => anyhow::bail!("unexpected handoff response: {other:?}"),
        }
    }

    pub fn receive_transfer(socket: &Path, token: &str) -> Result<(UnixStream, OwnedFd, Transfer)> {
        let mut stream = UnixStream::connect(socket)
            .with_context(|| format!("connect predecessor {}", socket.display()))?;
        authenticate_peer(&stream)?;
        stream.set_read_timeout(Some(PREPARE_TIMEOUT))?;
        stream.set_write_timeout(Some(PREPARE_TIMEOUT))?;
        write_frame(
            &mut stream,
            &Request::Successor {
                protocol_version: PROTOCOL_VERSION,
                token: token.to_string(),
            },
        )?;
        let fd = receive_fd(&stream)?;
        let transfer = read_frame::<Transfer>(&mut stream)?;
        if transfer.protocol_version != PROTOCOL_VERSION {
            anyhow::bail!(
                "handoff protocol mismatch: predecessor {}, successor {}",
                transfer.protocol_version,
                PROTOCOL_VERSION
            );
        }
        Ok((stream, fd, transfer))
    }

    pub fn successor_prepared(stream: &mut UnixStream) -> Result<()> {
        write_frame(stream, &Response::Prepared)?;
        match read_frame::<Response>(stream)? {
            Response::Commit => Ok(()),
            Response::Failed(message) => anyhow::bail!("predecessor aborted handoff: {message}"),
            other => anyhow::bail!("unexpected commit response: {other:?}"),
        }
    }

    pub fn successor_failed(stream: &mut UnixStream, error: &anyhow::Error) {
        let _ = write_frame(stream, &Response::Failed(format!("{error:#}")));
    }

    pub fn successor_activated(stream: &mut UnixStream) -> Result<()> {
        write_frame(stream, &Response::Activated)
    }

    fn connect(mountpoint: &Path) -> Result<UnixStream> {
        let path = socket_path(mountpoint)?;
        let stream = UnixStream::connect(&path)
            .with_context(|| format!("connect handoff socket {}", path.display()))?;
        authenticate_peer(&stream)?;
        stream.set_read_timeout(Some(PREPARE_TIMEOUT))?;
        stream.set_write_timeout(Some(PREPARE_TIMEOUT))?;
        Ok(stream)
    }

    pub fn socket_path(mountpoint: &Path) -> Result<std::path::PathBuf> {
        let runtime = match std::env::var_os("ORLOP_RUNTIME_DIR") {
            Some(path) => std::path::PathBuf::from(path),
            None if unsafe { libc::geteuid() } == 0 => std::path::PathBuf::from("/run/orlop"),
            None => {
                let base = std::env::var_os("XDG_RUNTIME_DIR")
                    .map(std::path::PathBuf::from)
                    .unwrap_or_else(std::env::temp_dir);
                base.join(format!("orlop-{}", unsafe { libc::geteuid() }))
            }
        };
        fs::create_dir_all(&runtime)
            .with_context(|| format!("create runtime directory {}", runtime.display()))?;
        let metadata = fs::symlink_metadata(&runtime)
            .with_context(|| format!("inspect runtime directory {}", runtime.display()))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            anyhow::bail!(
                "handoff runtime path {} is not a real directory",
                runtime.display()
            );
        }
        let own_uid = unsafe { libc::geteuid() };
        if metadata.uid() != own_uid {
            anyhow::bail!(
                "handoff runtime directory {} is owned by uid {}, expected {}",
                runtime.display(),
                metadata.uid(),
                own_uid
            );
        }
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod runtime directory {}", runtime.display()))?;
        let digest = blake3::hash(mountpoint.as_os_str().as_encoded_bytes());
        Ok(runtime.join(format!("mount-{}.sock", &digest.to_hex()[..24])))
    }

    fn prepare_socket_path(path: &Path) -> Result<()> {
        match fs::symlink_metadata(path) {
            Ok(meta) => {
                if !meta.file_type().is_socket() || meta.uid() != unsafe { libc::geteuid() } {
                    anyhow::bail!("refusing to replace unsafe handoff path {}", path.display());
                }
                match UnixStream::connect(path) {
                    Ok(_) => {
                        anyhow::bail!("another handoff service is active at {}", path.display())
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
                        ) =>
                    {
                        fs::remove_file(path)
                            .with_context(|| format!("remove stale socket {}", path.display()))?;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    fn authenticate_peer(stream: &UnixStream) -> Result<()> {
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error()).context("read Unix peer credentials");
        }
        let own_uid = unsafe { libc::geteuid() };
        if cred.uid != own_uid && cred.uid != 0 {
            anyhow::bail!("handoff peer uid {} is not authorized", cred.uid);
        }
        Ok(())
    }

    fn random_token() -> Result<String> {
        let mut bytes = [0u8; 32];
        let mut filled = 0;
        while filled < bytes.len() {
            let count = unsafe {
                libc::getrandom(
                    bytes[filled..].as_mut_ptr() as *mut libc::c_void,
                    bytes.len() - filled,
                    0,
                )
            };
            if count > 0 {
                filled += count as usize;
                continue;
            }
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error).context("generate handoff token");
        }
        Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
    }

    fn write_frame<T: serde::Serialize>(stream: &mut UnixStream, value: &T) -> Result<()> {
        let bytes = rmp_serde::to_vec_named(value).context("encode handoff frame")?;
        if bytes.len() > MAX_FRAME_BYTES {
            anyhow::bail!("handoff frame exceeds {MAX_FRAME_BYTES} bytes");
        }
        stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
        stream.write_all(&bytes)?;
        stream.flush()?;
        Ok(())
    }

    fn read_frame<T: serde::de::DeserializeOwned>(stream: &mut UnixStream) -> Result<T> {
        let mut length = [0u8; 4];
        stream.read_exact(&mut length)?;
        let length = u32::from_be_bytes(length) as usize;
        if length > MAX_FRAME_BYTES {
            anyhow::bail!("handoff frame length {length} exceeds limit");
        }
        let mut bytes = vec![0u8; length];
        stream.read_exact(&mut bytes)?;
        rmp_serde::from_slice(&bytes).context("decode handoff frame")
    }

    // glibc exposes these ancillary-data lengths as usize, while musl uses
    // socklen_t. The conversions are intentionally redundant on glibc.
    #[allow(clippy::useless_conversion)]
    fn send_fd(stream: &UnixStream, fd: RawFd) -> Result<()> {
        let byte = [0x46u8];
        let mut iov = [IoSlice::new(&byte)];
        let space =
            unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as libc::c_uint) as usize };
        let mut control = vec![0u8; space];
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = iov.as_mut_ptr() as *mut libc::iovec;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr() as *mut libc::c_void;
        message.msg_controllen = control
            .len()
            .try_into()
            .context("SCM_RIGHTS control buffer length does not fit msghdr")?;
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as libc::c_uint)
                .try_into()
                .context("SCM_RIGHTS payload length does not fit cmsghdr")?;
            std::ptr::write(libc::CMSG_DATA(header) as *mut RawFd, fd);
            loop {
                let count = libc::sendmsg(stream.as_raw_fd(), &message, libc::MSG_NOSIGNAL);
                if count == 1 {
                    break;
                }
                let error = io::Error::last_os_error();
                if count < 0 && error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                if count >= 0 {
                    anyhow::bail!("short write while sending FUSE descriptor");
                }
                return Err(error).context("send FUSE descriptor");
            }
        }
        Ok(())
    }

    // See send_fd: the libc field types differ between glibc and musl.
    #[allow(clippy::useless_conversion)]
    fn receive_fd(stream: &UnixStream) -> Result<OwnedFd> {
        let mut byte = [0u8; 1];
        let mut iov = [IoSliceMut::new(&mut byte)];
        let space =
            unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as libc::c_uint) as usize };
        let mut control = vec![0u8; space];
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = iov.as_mut_ptr() as *mut libc::iovec;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr() as *mut libc::c_void;
        message.msg_controllen = control
            .len()
            .try_into()
            .context("SCM_RIGHTS control buffer length does not fit msghdr")?;
        let count =
            unsafe { libc::recvmsg(stream.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
        if count != 1 || byte[0] != 0x46 {
            anyhow::bail!("invalid FUSE descriptor message");
        }
        if message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0 {
            anyhow::bail!("truncated FUSE descriptor message");
        }
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            let expected_len: usize = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as libc::c_uint)
                .try_into()
                .context("SCM_RIGHTS payload length does not fit usize")?;
            let actual_len: usize = if header.is_null() {
                0
            } else {
                (*header)
                    .cmsg_len
                    .try_into()
                    .context("received SCM_RIGHTS payload length does not fit usize")?
            };
            if header.is_null()
                || (*header).cmsg_level != libc::SOL_SOCKET
                || (*header).cmsg_type != libc::SCM_RIGHTS
                || actual_len != expected_len
                || !libc::CMSG_NXTHDR(&message, header).is_null()
            {
                anyhow::bail!("handoff message did not contain SCM_RIGHTS");
            }
            let fd = std::ptr::read(libc::CMSG_DATA(header) as *const RawFd);
            if fd < 0 {
                anyhow::bail!("handoff supplied an invalid descriptor");
            }
            Ok(OwnedFd::from_raw_fd(fd))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::fd::AsFd;

        #[test]
        fn framed_protocol_round_trip() {
            let (mut left, mut right) = UnixStream::pair().unwrap();
            let request = Request::Inspect {
                protocol_version: PROTOCOL_VERSION,
                mountpoint: "/mnt/orlop".into(),
            };
            write_frame(&mut left, &request).unwrap();
            match read_frame::<Request>(&mut right).unwrap() {
                Request::Inspect {
                    protocol_version,
                    mountpoint,
                } => {
                    assert_eq!(protocol_version, PROTOCOL_VERSION);
                    assert_eq!(mountpoint, Path::new("/mnt/orlop"));
                }
                other => panic!("unexpected request: {other:?}"),
            }
        }

        #[test]
        fn framed_protocol_rejects_oversized_length_before_allocating() {
            let (mut left, mut right) = UnixStream::pair().unwrap();
            left.write_all(&((MAX_FRAME_BYTES as u32) + 1).to_be_bytes())
                .unwrap();
            let error = read_frame::<Request>(&mut right).unwrap_err();
            assert!(error.to_string().contains("exceeds limit"));
        }

        #[test]
        fn handoff_tokens_are_full_width_and_non_repeating() {
            let first = random_token().unwrap();
            let second = random_token().unwrap();
            assert_eq!(first.len(), 64);
            assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
            assert_ne!(first, second);
        }

        #[test]
        fn scm_rights_transfers_a_live_descriptor() {
            let (left, right) = UnixStream::pair().unwrap();
            let file = tempfile::tempfile().unwrap();
            send_fd(&left, file.as_raw_fd()).unwrap();
            let received = receive_fd(&right).unwrap();
            let original = file.as_fd().try_clone_to_owned().unwrap();
            let original_meta = std::fs::File::from(original).metadata().unwrap();
            let received_meta = std::fs::File::from(received).metadata().unwrap();
            assert_eq!(original_meta.dev(), received_meta.dev());
            assert_eq!(original_meta.ino(), received_meta.ino());
        }

        #[test]
        fn peer_credentials_accept_same_process() {
            let (left, _right) = UnixStream::pair().unwrap();
            authenticate_peer(&left).unwrap();
        }

        #[test]
        fn malformed_successor_restores_listener_blocking_mode() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("handoff.sock");
            let listener = UnixListener::bind(&path).unwrap();
            let connector = std::thread::spawn(move || {
                let _stream = UnixStream::connect(path).unwrap();
                // Drop without a frame so accept_successor exits through its
                // read error path.
            });
            let mut child = Command::new("/bin/sleep").arg("2").spawn().unwrap();

            let result = accept_successor(&listener, "unused", &mut child);
            terminate_child(&mut child);
            connector.join().unwrap();

            assert!(result.is_err());
            let flags = unsafe { libc::fcntl(listener.as_raw_fd(), libc::F_GETFL) };
            assert!(flags >= 0);
            assert_eq!(flags & libc::O_NONBLOCK, 0);
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::{
    inspect, receive_transfer, request_upgrade, socket_path, successor_activated, successor_failed,
    successor_prepared, Service,
};
