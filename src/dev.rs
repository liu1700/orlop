//! `orlop dev up` and `orlop status` — single-host developer convenience.
//!
//! `dev up` automates the standalone quickstart: it starts the SQLite control
//! plane, registers and starts the data-plane server, mints an enroll token,
//! mounts a disk, then supervises the three processes until Ctrl-C and tears
//! them down in order. `status` reports what a running `dev up` stack (and any
//! mount daemon) is doing, reading the state file `dev up` leaves behind.
//!
//! All orchestration here is synchronous (no tokio runtime) so the blocking
//! `reqwest` health checks are legal. Children are placed in their own process
//! groups so a terminal Ctrl-C reaches only this supervisor, which then tears
//! them down deterministically rather than letting the kernel race them.

use std::fs;
use std::io::Read;
use std::net::TcpStream;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

/// Options for `orlop dev up`.
pub struct DevUpOpts {
    pub dir: PathBuf,
    pub mountpoint: Option<PathBuf>,
    pub agent: String,
    pub control_port: u16,
    pub ops_port: u16,
    pub data_port: u16,
    pub total_bytes: u64,
    /// Run the supervisor in the background and return 0 once the disk is
    /// mounted, instead of blocking until Ctrl-C. See [`run_dev_up`].
    pub detach: bool,
}

/// Persisted description of a running `dev up` stack. Written to
/// [`crate::daemon::dev_state_path`] so `orlop status` and `orlop dev down`
/// find it with no args.
#[derive(Debug, Serialize, Deserialize)]
pub struct DevState {
    pub work_dir: PathBuf,
    pub control_plane_url: String,
    /// PID of the `orlop dev up` supervisor itself — the process `orlop dev
    /// down` signals for a graceful teardown. Present whether the stack was
    /// started in the foreground or with `--detach`.
    #[serde(default)]
    pub supervisor_pid: u32,
    pub control_pid: u32,
    pub server_pid: u32,
    pub mount_pid: u32,
    pub mountpoint: PathBuf,
    pub ops_addr: String,
    pub data_addr: String,
    pub agent_id: String,
}

const READY_TIMEOUT: Duration = Duration::from_secs(30);
const STOP_TIMEOUT: Duration = Duration::from_secs(10);
/// `dev up --detach` blocks at most this long for the backgrounded supervisor
/// to mount the disk. Bring-up is normally a few seconds; this covers the
/// worst case where each of the five steps approaches its own timeout.
const DETACH_TIMEOUT: Duration = Duration::from_secs(120);
/// `dev down` waits at most this long for the supervisor to tear the stack
/// down and exit. The supervisor's teardown is three sequential stops, each
/// bounded by [`STOP_TIMEOUT`], so this must exceed `3 × STOP_TIMEOUT`.
const DOWN_TIMEOUT: Duration = Duration::from_secs(40);
const TRUST_DOMAIN: &str = "demo.example";

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_shutdown_signal(_sig: libc::c_int) {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

/// Kills its child on drop unless [`ChildGuard::stop`] already claimed it, so an
/// early `?` return never leaks a half-started stack.
struct ChildGuard {
    name: &'static str,
    child: Option<Child>,
}

impl ChildGuard {
    fn new(name: &'static str, child: Child) -> Self {
        Self { name, child: Some(child) }
    }

    fn id(&self) -> u32 {
        self.child.as_ref().map(Child::id).unwrap_or(0)
    }

    fn child_mut(&mut self) -> &mut Child {
        self.child.as_mut().expect("child already taken")
    }

    /// True if the child is still running. A child that exited on its own (e.g.
    /// it crashed) returns false.
    fn is_running(&mut self) -> bool {
        match self.child.as_mut() {
            Some(c) => matches!(c.try_wait(), Ok(None)),
            None => false,
        }
    }

    /// Graceful stop: SIGTERM, wait up to `timeout`, then SIGKILL. Claims the
    /// child so Drop won't touch it.
    fn stop(&mut self, timeout: Duration) {
        if let Some(mut c) = self.child.take() {
            eprintln!("  stopping {} (pid {})", self.name, c.id());
            crate::daemon::send_signal(c.id(), libc::SIGTERM);
            let deadline = Instant::now() + timeout;
            loop {
                match c.try_wait() {
                    Ok(Some(_)) => return,
                    Ok(None) if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    _ => break,
                }
            }
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            // Error/early-return path only — best-effort, don't block long.
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

/// Bring up the full single-node stack.
///
/// In the default (foreground) mode this blocks until Ctrl-C / SIGTERM and
/// then tears the stack down. With `opts.detach` it instead re-execs itself as
/// a backgrounded supervisor, blocks only until the disk is mounted, and
/// returns 0 — so CI, an IDE, or an agent can bring the stack up without
/// holding a terminal. Either way `orlop dev down` stops it.
pub fn run_dev_up(opts: DevUpOpts) -> Result<()> {
    if opts.detach {
        return run_dev_up_detached(&opts);
    }

    let control_bin = find_binary("orlop-control")?;
    let server_bin = find_binary("orlop-server")?;
    let self_bin = std::env::current_exe().context("locate the running orlop binary")?;

    preflight(&opts)?;

    // Work dir + layout.
    fs::create_dir_all(&opts.dir).with_context(|| format!("create work dir {}", opts.dir.display()))?;
    let work_dir = fs::canonicalize(&opts.dir).with_context(|| format!("resolve {}", opts.dir.display()))?;
    for sub in ["dg-data/objects", "dg-data/tenants", "dg-secrets", "cert"] {
        fs::create_dir_all(work_dir.join(sub))?;
    }
    let mountpoint = match &opts.mountpoint {
        Some(p) => p.clone(),
        None => work_dir.join("mnt"),
    };
    fs::create_dir_all(&mountpoint)?;
    let mountpoint = fs::canonicalize(&mountpoint)?;

    let token = random_hex_16().context("generate control-plane token")?;
    let control_url = format!("http://localhost:{}", opts.control_port);
    let data_addr = format!("localhost:{}", opts.data_port);
    let ops_addr = format!("localhost:{}", opts.ops_port);

    write_server_yaml(&work_dir, &ops_addr, &data_addr, &control_url)?;

    eprintln!("orlop dev up — work dir {}", work_dir.display());

    // 1. Control plane. Creates/migrates the SQLite DB on boot.
    eprintln!("[1/5] starting control plane on :{}", opts.control_port);
    let mut control = ChildGuard::new(
        "control plane",
        spawn(
            &control_bin,
            &[],
            &work_dir,
            &[
                ("PORT", &opts.control_port.to_string()),
                ("DATABASE_URL", "sqlite:./orlop.db"),
                ("ORLOP_SECRETS_DIR", "./dg-secrets"),
                ("ORLOP_CONTROL_PLANE_TOKEN", &token),
                ("ORLOP_TRUST_DOMAIN", TRUST_DOMAIN),
                ("ORLOP_DATAGW_SERVER_FQDN", "localhost"),
            ],
            &work_dir.join("control.log"),
        )?,
    );
    let http = crate::util::http_client(Duration::from_secs(2))?;
    let health_url = format!("{control_url}/healthz");
    wait_for(control.child_mut(), READY_TIMEOUT, "control plane health", || {
        http.get(&health_url).send().map(|r| r.status().is_success()).unwrap_or(false)
    })
    .context("control plane did not become healthy (see control.log)")?;

    // 2. Register the data-plane server in the placement pool (DB-direct).
    eprintln!("[2/5] registering data-plane server");
    capture(
        &control_bin,
        &[
            "server", "register",
            "--data-addr", &data_addr,
            "--ops-addr", &ops_addr,
            "--total-bytes", &opts.total_bytes.to_string(),
        ],
        &work_dir,
        &[("DATABASE_URL", "sqlite:./orlop.db")],
    )
    .context("server register failed")?;

    // 3. Data-plane server. Self-provisions its cert from the control plane.
    eprintln!("[3/5] starting data-plane server on :{} (data) / :{} (ops)", opts.data_port, opts.ops_port);
    let mut server = ChildGuard::new(
        "data plane",
        spawn(
            &server_bin,
            &["-config", "server.yaml"],
            &work_dir,
            &[("ORLOP_DATAGW_SERVICE_TOKEN", &token)],
            &work_dir.join("server.log"),
        )?,
    );
    wait_for(server.child_mut(), READY_TIMEOUT, "data-plane server", || port_in_use(opts.data_port))
        .context("data-plane server did not start listening (see server.log)")?;

    // 4. Mint an enroll token (DB-direct) and capture it.
    eprintln!("[4/5] minting enroll token for agent {}", opts.agent);
    let token_json = capture(
        &control_bin,
        &["token", "issue", "--agent", &opts.agent, "--control-plane", &control_url, "--json"],
        &work_dir,
        &[("DATABASE_URL", "sqlite:./orlop.db")],
    )
    .context("token issue failed")?;
    let enroll_token = parse_token(&token_json)?;

    // 5. Mount the disk (re-exec ourselves in --from-env mode).
    eprintln!("[5/5] mounting agent disk at {}", mountpoint.display());
    let mut mount = ChildGuard::new(
        "mount",
        spawn(
            &self_bin,
            &["mount", "--from-env", "--no-inject"],
            &work_dir,
            &[
                ("ORLOP_AGENT_ID", &opts.agent),
                ("ORLOP_MOUNT_POINT", &mountpoint.to_string_lossy()),
                ("ORLOP_CONTROL_PLANE", &control_url),
                ("ORLOP_ENROLL_TOKEN", &enroll_token),
                ("ORLOP_CERT_DIR", &work_dir.join("cert").to_string_lossy()),
            ],
            &work_dir.join("mount.log"),
        )?,
    );
    wait_for(mount.child_mut(), READY_TIMEOUT, "agent disk mount", || {
        crate::daemon::is_mountpoint_active(&mountpoint)
    })
    .context("mount did not come up (see mount.log)")?;

    // Persist state for `orlop status` and `orlop dev down`. This process is
    // the supervisor `dev down` will signal, so record our own PID.
    let state = DevState {
        work_dir: work_dir.clone(),
        control_plane_url: control_url.clone(),
        supervisor_pid: std::process::id(),
        control_pid: control.id(),
        server_pid: server.id(),
        mount_pid: mount.id(),
        mountpoint: mountpoint.clone(),
        ops_addr: ops_addr.clone(),
        data_addr: data_addr.clone(),
        agent_id: opts.agent.clone(),
    };
    let state_path = crate::daemon::dev_state_path()?;
    fs::write(&state_path, serde_json::to_vec_pretty(&state)?)
        .with_context(|| format!("write {}", state_path.display()))?;

    print_ready_banner(&state);

    // Supervise until Ctrl-C / SIGTERM, or until a child dies on its own.
    install_signal_handlers();
    supervise(&mut control, &mut server, &mut mount);

    // Teardown in dependency order: mount (releases lease) → server → control.
    eprintln!("\nshutting down orlop dev stack…");
    mount.stop(STOP_TIMEOUT);
    server.stop(STOP_TIMEOUT);
    control.stop(STOP_TIMEOUT);
    let _ = fs::remove_file(&state_path);
    eprintln!("stack down. data kept in {} (rm -rf to discard)", work_dir.display());
    Ok(())
}

/// Fail-fast checks shared by the foreground and detached bring-up paths:
/// refuse to stack a second instance on top of a live one, then surface a busy
/// port with an actionable hint before we spawn anything.
fn preflight(opts: &DevUpOpts) -> Result<()> {
    if let Some(state) = load_dev_state() {
        if state.supervisor_pid != 0 && crate::daemon::pid_alive(state.supervisor_pid) {
            bail!(
                "a dev stack is already up (supervisor pid {}, work dir {}); \
                 inspect it with `orlop status` or stop it with `orlop dev down`",
                state.supervisor_pid,
                state.work_dir.display(),
            );
        }
    }
    for (label, port, flag) in [
        ("control plane", opts.control_port, "--control-port"),
        ("server ops", opts.ops_port, "--ops-port"),
        ("server data", opts.data_port, "--data-port"),
    ] {
        if port_in_use(port) {
            bail!("port {port} ({label}) is already in use; free it or pass {flag} <port>");
        }
    }
    Ok(())
}

/// `orlop dev up --detach`: re-exec ourselves as a backgrounded supervisor,
/// block only until the disk is mounted, then return 0. The child runs the
/// ordinary foreground bring-up (so it writes `dev.json` and tears down on
/// SIGTERM just like an interactive run) — `orlop dev down` stops it.
fn run_dev_up_detached(opts: &DevUpOpts) -> Result<()> {
    // Resolve binaries up front so a misinstall fails synchronously here,
    // rather than inside a backgrounded child the caller can't watch.
    find_binary("orlop-control")?;
    find_binary("orlop-server")?;
    let self_bin = std::env::current_exe().context("locate the running orlop binary")?;

    preflight(opts)?;

    fs::create_dir_all(&opts.dir).with_context(|| format!("create work dir {}", opts.dir.display()))?;
    let work_dir = fs::canonicalize(&opts.dir).with_context(|| format!("resolve {}", opts.dir.display()))?;
    let log = work_dir.join("dev.log");

    eprintln!("orlop dev up --detach — starting supervisor in the background");
    let mut child = spawn_detached_supervisor(opts, &self_bin, &log)?;
    let supervisor_pid = child.id();

    // Block until the backgrounded supervisor records itself in dev.json with
    // the disk mounted, or it dies first.
    let deadline = Instant::now() + DETACH_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait().context("waiting on detached supervisor")? {
            bail!(
                "dev stack failed to come up (supervisor exited with {status}); see {}",
                log.display()
            );
        }
        if let Some(state) = load_dev_state() {
            if state.supervisor_pid == supervisor_pid
                && crate::daemon::is_mountpoint_active(&state.mountpoint)
            {
                print_detached_banner(&state, &log);
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            // Don't leave a half-started stack running behind us.
            crate::daemon::send_signal(supervisor_pid, libc::SIGTERM);
            bail!(
                "dev stack did not come up within {DETACH_TIMEOUT:?}; \
                 signaled the supervisor to stop — see {}",
                log.display()
            );
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Reconstruct the `orlop dev up` argv for the backgrounded supervisor —
/// every option the caller passed, minus `--detach` (the child runs in the
/// foreground; it just happens to be detached from our terminal). Pure so it
/// can be unit-tested without spawning anything.
fn detached_args(opts: &DevUpOpts) -> Vec<String> {
    let mut args: Vec<String> = vec![
        "dev".into(),
        "up".into(),
        "--dir".into(),
        opts.dir.to_string_lossy().into_owned(),
        "--agent".into(),
        opts.agent.clone(),
        "--control-port".into(),
        opts.control_port.to_string(),
        "--ops-port".into(),
        opts.ops_port.to_string(),
        "--data-port".into(),
        opts.data_port.to_string(),
        "--total-bytes".into(),
        opts.total_bytes.to_string(),
    ];
    if let Some(mp) = &opts.mountpoint {
        args.push("--mountpoint".into());
        args.push(mp.to_string_lossy().into_owned());
    }
    args
}

/// Spawn `orlop dev up` (foreground, same options minus `--detach`) detached
/// from the controlling terminal so a shell hangup or the launcher exiting
/// doesn't take the supervisor with it.
fn spawn_detached_supervisor(opts: &DevUpOpts, self_bin: &Path, log: &Path) -> Result<Child> {
    let args = detached_args(opts);

    let out = fs::File::create(log).with_context(|| format!("open {}", log.display()))?;
    let err = out.try_clone()?;
    let mut cmd = Command::new(self_bin);
    cmd.args(&args)
        .stdin(Stdio::null())
        .stdout(out)
        .stderr(err)
        .process_group(0);
    // SAFETY: setsid() is async-signal-safe and the only call between fork and
    // exec; it puts the child in its own session so SIGHUP/SIGINT on the
    // launching terminal can't reach it.
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    cmd.spawn()
        .with_context(|| format!("spawn detached supervisor {}", self_bin.display()))
}

fn print_detached_banner(state: &DevState, log: &Path) {
    eprintln!();
    eprintln!("orlop dev stack is up (detached):");
    eprintln!("  work dir       {}", state.work_dir.display());
    eprintln!("  control plane  {}", state.control_plane_url);
    eprintln!(
        "  disk mounted   {}  (agent {})",
        state.mountpoint.display(),
        state.agent_id
    );
    eprintln!("  supervisor     pid {}  (log {})", state.supervisor_pid, log.display());
    eprintln!();
    eprintln!("  status:   orlop status");
    eprintln!("  stop:     orlop dev down");
}

/// `orlop dev down` — stop a running stack (foreground or detached) without
/// PID-hunting. Reads `dev.json`, sends the graceful-shutdown signal to the
/// supervisor, and waits for it to tear the stack down and exit. Idempotent:
/// a missing or already-dead stack is reconciled and reported, not an error.
pub fn run_dev_down(dir: Option<PathBuf>) -> Result<()> {
    let state_path = crate::daemon::dev_state_path()?;
    let state = match load_dev_state() {
        Some(s) => s,
        None => {
            println!("no dev stack is running");
            return Ok(());
        }
    };

    // If the caller named a --dir, only act on a stack that matches it, so a
    // scripted `dev down --dir X` can never tear down an unrelated stack.
    if let Some(dir) = dir {
        let want = fs::canonicalize(&dir).unwrap_or(dir);
        if state.work_dir != want {
            bail!(
                "the running dev stack is at {}, not {}; \
                 re-run `orlop dev down` without --dir to stop it",
                state.work_dir.display(),
                want.display(),
            );
        }
    }

    let pid = state.supervisor_pid;
    if pid == 0 || !crate::daemon::pid_alive(pid) {
        // Supervisor already gone (crash, kill -9, OOM). Its children are
        // orphaned and still holding the ports — reap them so the next
        // `dev up` isn't blocked, then clear the stale state file.
        eprintln!("supervisor not running; cleaning up orphaned dev stack");
        reap_orphans(&state);
        let _ = fs::remove_file(&state_path);
        println!(
            "dev stack already down. data kept in {} (rm -rf to discard)",
            state.work_dir.display()
        );
        return Ok(());
    }

    eprintln!("stopping dev stack (supervisor pid {pid})…");
    crate::daemon::send_signal(pid, libc::SIGTERM);

    // The supervisor tears down mount→server→control and removes dev.json on
    // its way out; wait for it to exit.
    let deadline = Instant::now() + DOWN_TIMEOUT;
    while crate::daemon::pid_alive(pid) {
        if Instant::now() >= deadline {
            eprintln!("supervisor pid {pid} did not exit within {DOWN_TIMEOUT:?}; sending SIGKILL");
            crate::daemon::send_signal(pid, libc::SIGKILL);
            // The supervisor never ran its teardown — reap its orphaned
            // children and clear state ourselves.
            reap_orphans(&state);
            let _ = fs::remove_file(&state_path);
            bail!("dev stack force-stopped (supervisor was unresponsive)");
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // The supervisor removes dev.json itself; clear any remnant just in case.
    let _ = fs::remove_file(&state_path);
    println!(
        "dev stack stopped. data kept in {} (rm -rf to discard)",
        state.work_dir.display()
    );
    Ok(())
}

/// Stop the recorded children of a supervisor that is no longer driving them,
/// in dependency order: mount first (so it releases its lease while the control
/// plane is still up and unmounts the disk), then data plane, then control.
fn reap_orphans(state: &DevState) {
    reap_pid(state.mount_pid, "mount", STOP_TIMEOUT);
    if crate::daemon::is_mountpoint_active(&state.mountpoint) {
        crate::util::warn_err("unmount leftover disk", crate::mount::unmount(&state.mountpoint));
    }
    reap_pid(state.server_pid, "data plane", STOP_TIMEOUT);
    reap_pid(state.control_pid, "control plane", STOP_TIMEOUT);
}

/// SIGTERM a still-living pid, wait up to `timeout` for it to exit, then
/// SIGKILL. No-op if the pid is unset or already gone.
fn reap_pid(pid: u32, name: &str, timeout: Duration) {
    if pid == 0 || !crate::daemon::pid_alive(pid) {
        return;
    }
    eprintln!("  stopping orphaned {name} (pid {pid})");
    crate::daemon::send_signal(pid, libc::SIGTERM);
    let deadline = Instant::now() + timeout;
    while crate::daemon::pid_alive(pid) {
        if Instant::now() >= deadline {
            crate::daemon::send_signal(pid, libc::SIGKILL);
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn supervise(control: &mut ChildGuard, server: &mut ChildGuard, mount: &mut ChildGuard) {
    while !SHUTDOWN.load(Ordering::SeqCst) {
        if !mount.is_running() {
            eprintln!("\nmount process exited; tearing down the rest of the stack");
            break;
        }
        if !server.is_running() {
            eprintln!("\ndata-plane server exited; tearing down the rest of the stack");
            break;
        }
        if !control.is_running() {
            eprintln!("\ncontrol plane exited; tearing down the rest of the stack");
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn install_signal_handlers() {
    // SAFETY: handler only stores into an AtomicBool, which is async-signal-safe.
    let handler = handle_shutdown_signal as *const () as libc::sighandler_t;
    unsafe {
        libc::signal(libc::SIGINT, handler);
        libc::signal(libc::SIGTERM, handler);
    }
}

fn print_ready_banner(state: &DevState) {
    let mp = state.mountpoint.display();
    eprintln!();
    eprintln!("orlop dev stack is up:");
    eprintln!("  control plane  {}", state.control_plane_url);
    eprintln!("  data plane     ops {}  data {}", state.ops_addr, state.data_addr);
    eprintln!("  disk mounted   {}  (agent {})", mp, state.agent_id);
    eprintln!();
    eprintln!("  try it:   echo hi > {}/hello.txt", mp);
    eprintln!("  status:   orlop status");
    eprintln!("  stop:     Ctrl-C, or `orlop dev down` from another shell");
}

// ---- process helpers -------------------------------------------------------

/// Spawn a long-lived child in its own process group, redirecting stdout+stderr
/// to `log`. The new process group keeps a terminal Ctrl-C from reaching it, so
/// the supervisor controls teardown order.
fn spawn(bin: &Path, args: &[&str], cwd: &Path, env: &[(&str, &str)], log: &Path) -> Result<Child> {
    let out = fs::File::create(log).with_context(|| format!("open {}", log.display()))?;
    let err = out.try_clone()?;
    let mut cmd = Command::new(bin);
    cmd.args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(out)
        .stderr(err)
        .process_group(0)
        .envs(env.iter().copied());
    cmd.spawn().with_context(|| format!("spawn {}", bin.display()))
}

/// Run a short-lived command and return its stdout, bailing on non-zero exit.
fn capture(bin: &Path, args: &[&str], cwd: &Path, env: &[(&str, &str)]) -> Result<String> {
    let mut cmd = Command::new(bin);
    cmd.args(args).current_dir(cwd).envs(env.iter().copied());
    let out = cmd.output().with_context(|| format!("run {} {:?}", bin.display(), args))?;
    if !out.status.success() {
        bail!(
            "{} {:?} exited with {}: {}",
            bin.display(),
            args,
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Poll until `ready()` returns true, the supervised `child` exits early, or the
/// timeout elapses. Shared by the control-plane / data-plane / mount bring-up
/// steps; `what` names the step in error messages.
fn wait_for(child: &mut Child, timeout: Duration, what: &str, ready: impl Fn() -> bool) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            bail!("{what}: process exited early with {status}");
        }
        if ready() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("{what}: not ready within {timeout:?}");
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

// ---- small utilities -------------------------------------------------------

/// Locate `name` next to the running orlop binary, then on `PATH`.
fn find_binary(name: &str) -> Result<PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let cand = dir.join(name);
            if is_executable(&cand) {
                return Ok(cand);
            }
        }
    }
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            let cand = dir.join(name);
            if is_executable(&cand) {
                return Ok(cand);
            }
        }
    }
    Err(anyhow!(
        "could not find `{name}` next to orlop or on PATH — \
         install the orlop binaries (curl -fsSL https://orlop.dev/install.sh | sh)"
    ))
}

fn is_executable(p: &Path) -> bool {
    fs::metadata(p)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// A TCP connect to 127.0.0.1:port succeeds iff something is listening.
fn port_in_use(port: u16) -> bool {
    TcpStream::connect_timeout(
        &([127, 0, 0, 1], port).into(),
        Duration::from_millis(200),
    )
    .is_ok()
}

fn random_hex_16() -> Result<String> {
    let mut buf = [0u8; 16];
    let mut f = fs::File::open("/dev/urandom").context("open /dev/urandom")?;
    f.read_exact(&mut buf).context("read /dev/urandom")?;
    Ok(crate::backend::dataplane::cache::hex_encode(&buf))
}

fn write_server_yaml(work_dir: &Path, ops_addr: &str, data_addr: &str, control_url: &str) -> Result<()> {
    // bind addresses are derived from the ports the agents/control plane use.
    let ops_bind = format!(":{}", port_of(ops_addr));
    let data_bind = format!(":{}", port_of(data_addr));
    let yaml = format!(
        "# server.yaml — generated by `orlop dev up`\n\
tenant:\n  id: a_demo\n  name: demo agent disk\n\
store:   {{ type: local,  root: ./dg-data/objects }}\n\
routes:  {{ type: sqlite, path: ./dg-data/routes.db }}\n\
server:\n  ops_bind:  \"{ops_bind}\"\n  data_bind: \"{data_bind}\"\n\
tls:\n  self_provision: true\n  control_url: {control_url}\n  fqdn: localhost\n  trust_domain: {TRUST_DOMAIN}\n\
tenants_root: ./dg-data/tenants\nquota: {{ enforce: false }}\n"
    );
    fs::write(work_dir.join("server.yaml"), yaml).context("write server.yaml")?;
    Ok(())
}

fn port_of(host_port: &str) -> &str {
    host_port.rsplit(':').next().unwrap_or(host_port)
}

#[derive(Deserialize)]
struct TokenIssueOut {
    token: String,
}

fn parse_token(json: &str) -> Result<String> {
    let parsed: TokenIssueOut = serde_json::from_str(json.trim())
        .with_context(|| format!("parse token issue JSON: {json}"))?;
    if parsed.token.is_empty() {
        bail!("token issue returned an empty token");
    }
    Ok(parsed.token)
}

// ---- status ----------------------------------------------------------------

#[derive(Serialize)]
struct StatusReport {
    dev_stack: Option<DevStackStatus>,
    mount_daemon: Option<ProcStatus>,
}

#[derive(Serialize)]
struct DevStackStatus {
    work_dir: PathBuf,
    control_plane_url: String,
    control: ProcStatus,
    server: ServerStatus,
    mount: MountStatus,
}

#[derive(Serialize)]
struct ProcStatus {
    pid: u32,
    running: bool,
}

#[derive(Serialize)]
struct ServerStatus {
    pid: u32,
    running: bool,
    ops_addr: String,
    data_addr: String,
}

#[derive(Serialize)]
struct MountStatus {
    pid: u32,
    running: bool,
    mountpoint: PathBuf,
    mounted: bool,
    agent_id: String,
}

/// `orlop status` — report a running dev stack and/or mount daemon.
pub fn run_status(json: bool) -> Result<()> {
    let dev = load_dev_state();
    let dev_status = dev.map(|d| DevStackStatus {
        control: ProcStatus { pid: d.control_pid, running: crate::daemon::pid_alive(d.control_pid) },
        server: ServerStatus {
            pid: d.server_pid,
            running: crate::daemon::pid_alive(d.server_pid),
            ops_addr: d.ops_addr,
            data_addr: d.data_addr,
        },
        mount: MountStatus {
            pid: d.mount_pid,
            running: crate::daemon::pid_alive(d.mount_pid),
            mounted: crate::daemon::is_mountpoint_active(&d.mountpoint),
            mountpoint: d.mountpoint,
            agent_id: d.agent_id,
        },
        work_dir: d.work_dir,
        control_plane_url: d.control_plane_url,
    });

    let mount_daemon = crate::daemon::pid_file_path()
        .ok()
        .and_then(|p| crate::daemon::read_pid_file(&p).ok().flatten())
        .map(|pid| ProcStatus { pid, running: crate::daemon::pid_alive(pid) });

    let report = StatusReport { dev_stack: dev_status, mount_daemon };
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print!("{}", render_status(&report));
    }
    Ok(())
}

/// Read + parse the dev state file, treating any error (missing/corrupt) as
/// "no dev stack" — status must never fail just because nothing is running.
fn load_dev_state() -> Option<DevState> {
    let path = crate::daemon::dev_state_path().ok()?;
    let bytes = fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn yesno(b: bool, yes: &'static str, no: &'static str) -> &'static str {
    if b { yes } else { no }
}

fn render_status(r: &StatusReport) -> String {
    let mut s = String::from("orlop status\n\n");
    match &r.dev_stack {
        Some(d) => {
            s.push_str(&format!("dev stack: UP   (work dir {})\n", d.work_dir.display()));
            s.push_str(&format!(
                "  control plane  {}  pid {}  {}\n",
                d.control_plane_url,
                d.control.pid,
                yesno(d.control.running, "running", "DOWN"),
            ));
            s.push_str(&format!(
                "  data plane     ops {}  data {}  pid {}  {}\n",
                d.server.ops_addr,
                d.server.data_addr,
                d.server.pid,
                yesno(d.server.running, "running", "DOWN"),
            ));
            s.push_str(&format!(
                "  mount          {}  agent {}  pid {}  {}\n",
                d.mount.mountpoint.display(),
                d.mount.agent_id,
                d.mount.pid,
                yesno(d.mount.mounted, "mounted", "NOT MOUNTED"),
            ));
        }
        None => s.push_str("dev stack: not running\n"),
    }
    s.push('\n');
    match &r.mount_daemon {
        Some(p) => s.push_str(&format!(
            "mount daemon: pid {}  {}\n",
            p.pid,
            yesno(p.running, "running", "stale pid file"),
        )),
        None => s.push_str("mount daemon: none\n"),
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_token_extracts_field() {
        let json = r#"{"token":"abc123","expires_at":"2026-01-01T00:00:00Z","agent_id":"demo"}"#;
        assert_eq!(parse_token(json).unwrap(), "abc123");
    }

    #[test]
    fn parse_token_rejects_empty() {
        assert!(parse_token(r#"{"token":""}"#).is_err());
    }

    #[test]
    fn parse_token_rejects_garbage() {
        assert!(parse_token("not json").is_err());
    }

    #[test]
    fn random_hex_16_is_32_hex_chars() {
        let h = random_hex_16().unwrap();
        assert_eq!(h.len(), 32);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
        // Two draws should not collide.
        assert_ne!(h, random_hex_16().unwrap());
    }

    #[test]
    fn port_of_extracts_port() {
        assert_eq!(port_of("localhost:8443"), "8443");
        assert_eq!(port_of("8443"), "8443");
        assert_eq!(port_of("[::1]:7878"), "7878");
    }

    fn sample_opts() -> DevUpOpts {
        DevUpOpts {
            dir: PathBuf::from("./orlop-dev"),
            mountpoint: None,
            agent: "demo".into(),
            control_port: 8080,
            ops_port: 7878,
            data_port: 8443,
            total_bytes: 10 * 1024 * 1024 * 1024,
            detach: true,
        }
    }

    #[test]
    fn detached_args_round_trip_options() {
        let args = detached_args(&sample_opts());
        assert_eq!(&args[0..2], &["dev", "up"]);
        // --detach must NOT be forwarded — the child runs foreground.
        assert!(!args.iter().any(|a| a == "--detach" || a == "-d"));
        // Every option the caller can set is carried through.
        for (flag, val) in [
            ("--dir", "./orlop-dev"),
            ("--agent", "demo"),
            ("--control-port", "8080"),
            ("--ops-port", "7878"),
            ("--data-port", "8443"),
            ("--total-bytes", "10737418240"),
        ] {
            let i = args.iter().position(|a| a == flag).expect(flag);
            assert_eq!(args[i + 1], val, "value for {flag}");
        }
        // No mountpoint set → flag omitted (child defaults to <dir>/mnt).
        assert!(!args.iter().any(|a| a == "--mountpoint"));
    }

    #[test]
    fn detached_args_includes_mountpoint_when_set() {
        let mut opts = sample_opts();
        opts.mountpoint = Some(PathBuf::from("/tmp/mp"));
        let args = detached_args(&opts);
        let i = args.iter().position(|a| a == "--mountpoint").expect("--mountpoint");
        assert_eq!(args[i + 1], "/tmp/mp");
    }

    #[test]
    fn dev_state_tolerates_missing_supervisor_pid() {
        // dev.json written by an older orlop has no supervisor_pid; it must
        // still deserialize (defaulting to 0) so status/down don't choke.
        let json = r#"{
            "work_dir":"/tmp/orlop-dev",
            "control_plane_url":"http://localhost:8080",
            "control_pid":1,"server_pid":2,"mount_pid":3,
            "mountpoint":"/tmp/orlop-dev/mnt",
            "ops_addr":"localhost:7878","data_addr":"localhost:8443",
            "agent_id":"demo"
        }"#;
        let state: DevState = serde_json::from_str(json).unwrap();
        assert_eq!(state.supervisor_pid, 0);
    }

    #[test]
    fn render_status_handles_empty() {
        let r = StatusReport { dev_stack: None, mount_daemon: None };
        let out = render_status(&r);
        assert!(out.contains("dev stack: not running"));
        assert!(out.contains("mount daemon: none"));
    }

    #[test]
    fn render_status_shows_running_stack() {
        let r = StatusReport {
            dev_stack: Some(DevStackStatus {
                work_dir: PathBuf::from("/tmp/orlop-dev"),
                control_plane_url: "http://localhost:8080".into(),
                control: ProcStatus { pid: 10, running: true },
                server: ServerStatus { pid: 11, running: true, ops_addr: "localhost:7878".into(), data_addr: "localhost:8443".into() },
                mount: MountStatus { pid: 12, running: true, mountpoint: PathBuf::from("/tmp/orlop-dev/mnt"), mounted: true, agent_id: "demo".into() },
            }),
            mount_daemon: None,
        };
        let out = render_status(&r);
        assert!(out.contains("dev stack: UP"));
        assert!(out.contains("http://localhost:8080"));
        assert!(out.contains("agent demo"));
        assert!(out.contains("mounted"));
    }
}
