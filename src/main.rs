use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context};
use clap::{Parser, Subcommand};
use reqwest::StatusCode;
use serde::Deserialize;

use orlop::agents_md;
use orlop::audit;
use orlop::backend::{self, build_stores, TlsIdentity};
use orlop::config::{Config, HostedConfig, MountConfig, MountKind};
use orlop::enroll::{self, EnrolledCert};
use orlop::login;
use orlop::util;

#[derive(Parser)]
#[command(name = "orlop")]
#[command(about = "Orlop — cross-agent portable disk")]
#[command(version)]
struct Cli {
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,
    #[arg(long, global = true)]
    mountpoint: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Mount the remote Orlop disk at the configured mountpoint. Linux uses
    /// FUSE; macOS uses a localhost NFSv3 server. Blocks until the kernel
    /// unmount syscall returns (e.g. `orlop unmount` from another shell).
    Mount {
        #[arg(short, long)]
        mountpoint: Option<PathBuf>,
        #[arg(long)]
        foreground: bool,
        /// Don't write a Orlop stanza into the cwd's AGENTS.md.
        #[arg(long)]
        no_inject: bool,
        /// Override credentials file location (default ~/.config/orlop/credentials.json).
        /// The certificate directory defaults to the parent of this path, so a
        /// fresh tempdir gives a fully isolated mount on the same host.
        #[arg(long)]
        credentials: Option<PathBuf>,
        /// In-pod env-driven mount. Reads ORLOP_AGENT_ID, ORLOP_MOUNT_POINT,
        /// ORLOP_CONTROL_PLANE and ORLOP_ENROLL_TOKEN from the environment,
        /// trades the enroll token for a short-lived (1h) client cert via
        /// `/agent/enroll`, and mounts over the existing mTLS data path. Runs
        /// in the foreground (the pod is the process supervisor); --mountpoint,
        /// --config and --credentials are ignored in this mode.
        #[arg(long)]
        from_env: bool,
    },
    /// Unmount the Orlop filesystem at the given path (or the default
    /// mountpoint from the active config).
    Unmount {
        target: Option<PathBuf>,
        /// Override credentials file location (default ~/.config/orlop/credentials.json).
        /// Use the same path as `orlop mount --credentials` so the lease/cert
        /// teardown targets the isolated session.
        #[arg(long)]
        credentials: Option<PathBuf>,
    },
    /// Inspect and tail the JSONL audit log for filesystem access events.
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
    /// Offline preflight: check this host can mount a Orlop disk (FUSE/NFS
    /// support, a writable chunk-cache dir, config + credentials). No network
    /// is touched. Exits non-zero when a required check fails; `--json` prints
    /// a machine-readable report.
    Doctor {
        #[arg(long)]
        json: bool,
    },
    /// Single-host developer stack: bring up the control plane, data-plane
    /// server, and a mounted disk in one command.
    Dev {
        #[command(subcommand)]
        command: DevCommand,
    },
    /// Report a running `orlop dev` stack and any mount daemon. `--json` prints
    /// a machine-readable report.
    Status {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum DevCommand {
    /// Bring up a single-node stack (control plane + data plane + mounted disk)
    /// and supervise it until Ctrl-C, which tears it all down. Automates the
    /// standalone quickstart for local development.
    Up {
        /// Work directory for all stack state (db, secrets, data, logs).
        #[arg(long, default_value = "./orlop-dev")]
        dir: PathBuf,
        /// Where to mount the agent disk (default: <dir>/mnt).
        #[arg(long)]
        mountpoint: Option<PathBuf>,
        /// Agent id to provision and mount.
        #[arg(long, default_value = "demo")]
        agent: String,
        #[arg(long, default_value_t = 8080)]
        control_port: u16,
        #[arg(long, default_value_t = 7878)]
        ops_port: u16,
        #[arg(long, default_value_t = 8443)]
        data_port: u16,
        /// Pool capacity to register for the data-plane server, in bytes.
        #[arg(long, default_value_t = 10 * 1024 * 1024 * 1024)]
        total_bytes: u64,
    },
}

#[derive(Subcommand)]
enum AuditCommand {
    Tail {
        /// Filter by event type. Repeatable: --event manifest_put --event lease_revoke.
        #[arg(long = "event")]
        events: Vec<String>,
        /// Filter by lease_id (hex). Matches lease_* events for that lease.
        #[arg(long)]
        lease_id: Option<String>,
        #[arg(long)]
        limit: Option<usize>,
        #[arg(long)]
        follow: bool,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Command::Mount {
            mountpoint,
            foreground,
            no_inject,
            credentials,
            from_env,
        } => {
            use std::io::Write as _;

            if *from_env {
                // In-pod mounter: env vars carry everything (agent id, mount
                // point, control-plane URL, enroll token). Always foreground —
                // the pod supervises this PID — so we skip the daemonize dance
                // and reuse run_mount_payload via a synthesized hosted config.
                return run_env_mount(*no_inject);
            }

            let creds_override = credentials.as_deref();
            let cfg = require_config(
                &cli,
                "mount requires --config (or place a config at ~/.config/orlop/config.yaml)",
            )?;
            if cfg.hosted.is_none() {
                let path = resolve_config_path(&cli)
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "<config>".into());
                anyhow::bail!(
                    "config at {path} is missing the `hosted:` block. \
                     Add `hosted: {{}}` to the file (control_plane_url and \
                     cert_dir fall back to credentials.json) and re-run."
                );
            }
            let mountpoint = mountpoint
                .clone()
                .or_else(|| cfg.fuse_mountpoint())
                .ok_or_else(|| anyhow!("mountpoint is required in config or --mountpoint"))?;

            if *foreground {
                // Existing path — block in this process until SIGINT/SIGTERM.
                // cwd is still the parent's cwd here, so no original_cwd needed.
                return run_mount_payload(&cfg, mountpoint, creds_override, *no_inject, None, None);
            }

            // --- Daemon path ---
            use orlop::daemon;

            let pid_file = daemon::pid_file_path()?;
            let log_file = daemon::log_file_path()?;

            let existing_pid = daemon::read_pid_file(&pid_file)?;
            let alive = existing_pid.map_or(false, daemon::pid_alive);
            let mp_active = daemon::is_mountpoint_active(&mountpoint);

            match daemon::classify(existing_pid, alive, mp_active) {
                daemon::PreflightOutcome::AlreadyMounted { pid } => {
                    eprintln!(
                        "already mounted at {} (daemon PID {})",
                        mountpoint.display(),
                        pid
                    );
                    return Ok(());
                }
                daemon::PreflightOutcome::StaleDaemon { pid } => {
                    anyhow::bail!(
                        "daemon at PID {pid} is alive but mount at {} is missing — \
                         run `orlop unmount` first",
                        mountpoint.display()
                    );
                }
                daemon::PreflightOutcome::Busy => {
                    anyhow::bail!(
                        "mountpoint {} is busy — something else is already mounted there. \
                         Inspect with `mount | grep {}` and unmount it manually before retrying.",
                        mountpoint.display(),
                        mountpoint.display(),
                    );
                }
                daemon::PreflightOutcome::StalePidOnly => {
                    let _ = std::fs::remove_file(&pid_file);
                }
                daemon::PreflightOutcome::Fresh => {}
            }

            // Capture the parent's cwd and resolve relative paths in cfg
            // BEFORE daemonize chdir's the grandchild to "/".
            let original_cwd = std::env::current_dir().ok();
            let cfg_owned: Config;
            let cfg: &Config = if !cfg.audit_log.is_absolute() {
                let abs = std::env::current_dir()?.join(&cfg.audit_log);
                cfg_owned = Config {
                    audit_log: abs,
                    ..cfg.clone()
                };
                &cfg_owned
            } else {
                &cfg
            };

            let (pipe_reader, pipe_writer) = os_pipe::pipe()?;

            // Open log file as both stdout and stderr; truncate on each daemon start.
            let stdout = std::fs::File::create(&log_file)
                .with_context(|| format!("open log {}", log_file.display()))?;
            let stderr = stdout.try_clone()?;

            let d = daemonize::Daemonize::new()
                .pid_file(&pid_file)
                .chown_pid_file(true)
                .working_directory("/")
                .stdout(stdout)
                .stderr(stderr);

            match d.execute() {
                daemonize::Outcome::Parent(Ok(_)) => {
                    // Parent: drop our copy of the writer end so the read can EOF.
                    drop(pipe_writer);
                    let outcome = daemon::read_ready_with_timeout(
                        pipe_reader,
                        std::time::Duration::from_secs(60),
                    );
                    return match outcome {
                        Ok(daemon::ReadyOutcome::Ready) => Ok(()),
                        Ok(daemon::ReadyOutcome::Err(msg)) => {
                            let _ = std::fs::remove_file(&pid_file);
                            anyhow::bail!("daemon failed to start: {msg}")
                        }
                        Ok(daemon::ReadyOutcome::DaemonExited) => {
                            let _ = std::fs::remove_file(&pid_file);
                            anyhow::bail!(
                                "daemon exited before signaling ready — \
                                 check {} for details",
                                log_file.display()
                            )
                        }
                        Err(()) => {
                            if let Ok(Some(pid)) = daemon::read_pid_file(&pid_file) {
                                daemon::send_signal(pid, libc::SIGKILL);
                            }
                            let _ = std::fs::remove_file(&pid_file);
                            anyhow::bail!(
                                "daemon did not signal ready within 60s — killed; \
                                 check {} for details",
                                log_file.display()
                            )
                        }
                    };
                }
                daemonize::Outcome::Child(Ok(_)) => {
                    // Grandchild: drop our copy of the reader end. The pipe is
                    // closed on either successful READY or on grandchild exit.
                    drop(pipe_reader);
                    let writer = std::sync::Arc::new(std::sync::Mutex::new(Some(pipe_writer)));
                    let writer_for_cb = std::sync::Arc::clone(&writer);
                    let ready_cb: Box<dyn FnOnce(Result<(), String>) + Send> =
                        Box::new(move |result| {
                            if let Some(mut w) = writer_for_cb.lock().unwrap().take() {
                                let _ = match result {
                                    Ok(()) => writeln!(w, "READY"),
                                    Err(msg) => writeln!(w, "ERR {msg}"),
                                };
                                let _ = w.flush();
                                // w dropped here closes the write end → parent's read EOFs
                            }
                        });

                    let result = run_mount_payload(
                        cfg,
                        mountpoint.clone(),
                        creds_override,
                        *no_inject,
                        Some(ready_cb),
                        original_cwd.clone(),
                    );
                    // If payload errored before firing the callback, the writer is
                    // still in the Mutex; report the error ourselves so the parent
                    // gets an ERR line rather than a silent EOF.
                    if let Err(ref e) = result {
                        if let Some(mut w) = writer.lock().unwrap().take() {
                            let _ = writeln!(w, "ERR {e}");
                            let _ = w.flush();
                        }
                    }
                    return result;
                }
                daemonize::Outcome::Parent(Err(e)) => {
                    anyhow::bail!("daemonize parent error: {e}")
                }
                daemonize::Outcome::Child(Err(e)) => {
                    // Child daemonize error — write to the log and exit.
                    eprintln!("daemonize child error: {e}");
                    std::process::exit(1);
                }
            }
        }
        Command::Unmount {
            target,
            credentials,
        } => {
            let creds_override = credentials.as_deref();
            let loaded_cfg = try_load_config(&cli).ok().flatten();
            let target = target
                .clone()
                .or_else(|| cli.mountpoint.clone())
                .or_else(|| loaded_cfg.as_ref().and_then(|cfg| cfg.fuse_mountpoint()))
                .ok_or_else(|| anyhow!("unmount target is required"))?;

            // Daemon path: if we wrote a PID file, prefer SIGTERM-then-wait so the
            // daemon's signal handler runs Drop (which releases the lease and runs
            // unmount). Falls back to the direct umount path if no daemon or if it
            // doesn't exit within 10s.
            let pid_file = orlop::daemon::pid_file_path()?;
            if let Ok(Some(pid)) = orlop::daemon::read_pid_file(&pid_file) {
                if orlop::daemon::pid_alive(pid) {
                    eprintln!("signaling daemon PID {pid}");
                    orlop::daemon::send_signal(pid, libc::SIGTERM);
                    // Wait up to 10s for the daemon to exit.
                    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
                    while std::time::Instant::now() < deadline {
                        if !orlop::daemon::pid_alive(pid) {
                            break;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                    if orlop::daemon::pid_alive(pid) {
                        eprintln!("daemon PID {pid} did not exit within 10s; SIGKILL");
                        orlop::daemon::send_signal(pid, libc::SIGKILL);
                    }
                    let _ = std::fs::remove_file(&pid_file);
                    // Daemon's Drop already ran unmount + lease_release. Done.
                    return Ok(());
                }
                // PID file exists but PID dead — unlink and fall through to the
                // existing direct-teardown path below.
                let _ = std::fs::remove_file(&pid_file);
            }

            // Fallback: no daemon (--foreground mode, or stale state). Direct
            // unmount + lease release + cert shred (existing behavior).
            util::warn_err("local unmount", orlop::mount::unmount(&target));
            if let Some(hosted) = loaded_cfg.as_ref().and_then(|cfg| cfg.hosted.clone()) {
                util::warn_err(
                    "mount lease release",
                    release_hosted_mount_lease(&hosted, creds_override),
                );
                util::warn_err("cert shred", shred_hosted_certs(&hosted, creds_override));
            }
        }
        Command::Audit { command } => match command {
            AuditCommand::Tail {
                events,
                lease_id,
                limit,
                follow,
            } => {
                let path = audit_log_path(&cli)?;
                let follow = *follow || limit.is_none();
                let filter = audit::TailFilter {
                    events,
                    lease_id: lease_id.as_deref(),
                };
                audit::tail(&path, filter, *limit, follow)
                    .with_context(|| format!("failed to tail audit log {}", path.display()))?;
            }
        },
        Command::Doctor { json } => {
            // Resolve config state without failing on a missing/broken file:
            // doctor's job is to *report* it, not bail.
            let (config_path, config_has_hosted) = match resolve_config_path(&cli) {
                Some(p) => {
                    let has_hosted = Config::load(&p).ok().map(|c| c.hosted.is_some());
                    (Some(p), has_hosted)
                }
                None => (None, None),
            };
            let credentials_path = login::credentials_path().ok().filter(|p| p.exists());
            let control_plane_url = credentials_path
                .as_deref()
                .and_then(|p| login::load(p).ok().flatten())
                .map(|c| c.control_plane_url);
            let report = orlop::doctor::gather(orlop::doctor::DoctorInputs {
                cache_root: chunk_cache_root().ok(),
                config_path,
                config_has_hosted,
                credentials_path,
                control_plane_url,
            });
            if *json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print!("{}", report.render_human());
            }
            if !report.ready {
                std::process::exit(1);
            }
        }
        Command::Dev { command } => match command {
            DevCommand::Up {
                dir,
                mountpoint,
                agent,
                control_port,
                ops_port,
                data_port,
                total_bytes,
            } => {
                let mountpoint = mountpoint.clone().or_else(|| cli.mountpoint.clone());
                orlop::dev::run_dev_up(orlop::dev::DevUpOpts {
                    dir: dir.clone(),
                    mountpoint,
                    agent: agent.clone(),
                    control_port: *control_port,
                    ops_port: *ops_port,
                    data_port: *data_port,
                    total_bytes: *total_bytes,
                })?;
            }
        },
        Command::Status { json } => {
            orlop::dev::run_status(*json)?;
        }
    }

    Ok(())
}

/// Resolves the config path: explicit `--config` first, then the XDG user
/// config (`$XDG_CONFIG_HOME/orlop/config.yaml` or `$HOME/.config/orlop/config.yaml`)
/// when present. Returns None if nothing is set and no user config exists.
fn resolve_config_path(cli: &Cli) -> Option<PathBuf> {
    if let Some(p) = cli.config.clone() {
        return Some(p);
    }
    let candidate = std::env::var_os("XDG_CONFIG_HOME")
        .map(|x| PathBuf::from(x).join("orlop/config.yaml"))
        .or_else(|| {
            std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config/orlop/config.yaml"))
        });
    candidate.filter(|p| p.exists())
}

/// Resolve + load the config. Returns Err only when the path exists but the
/// file fails to parse — a missing config returns Ok(None). Use for optional
/// paths (cache, status, unmount).
fn try_load_config(cli: &Cli) -> anyhow::Result<Option<Config>> {
    match resolve_config_path(cli) {
        Some(path) => {
            let cfg = Config::load(&path)
                .with_context(|| format!("failed to load {}", path.display()))?;
            Ok(Some(cfg))
        }
        None => Ok(None),
    }
}

/// Resolve + load the config, bailing with `missing_msg` if no path is set.
/// Use for subcommands that can't proceed without one (mount, session, ...).
fn require_config(cli: &Cli, missing_msg: &'static str) -> anyhow::Result<Config> {
    let path = resolve_config_path(cli).ok_or_else(|| anyhow!(missing_msg))?;
    Config::load(&path).with_context(|| format!("failed to load {}", path.display()))
}

fn chunk_cache_root() -> anyhow::Result<PathBuf> {
    backend::dataplane::ChunkCache::default_root()
        .ok_or_else(|| anyhow!("could not determine cache directory (set XDG_CACHE_HOME or HOME)"))
}

fn audit_log_path(cli: &Cli) -> anyhow::Result<PathBuf> {
    if let Some(cfg) = try_load_config(cli)? {
        return Ok(cfg.audit_log);
    }
    Ok(PathBuf::from("./audit.log"))
}

fn enroll_for_mount(
    hosted: &HostedConfig,
    creds_override: Option<&Path>,
    audit: &audit::AuditLog,
) -> anyhow::Result<EnrolledCert> {
    let cert_dir = cert_dir_for_hosted(hosted, creds_override)?;
    // Pre-enrolled hosted mode (Phase 2 anonymous sandbox): the spawner
    // wrote cert.pem + key.pem + ca.pem + enrollment.json into cert_dir
    // before exec'ing us. There are no credentials.json and no refresh
    // tokens — the cert IS the identity for the 5-minute session window.
    if let Some(pre) = enroll::load_enrollment_sidecar(&cert_dir)? {
        audit.record(audit::AuditEvent::simple(
            audit::event::ENROLLMENT,
            &pre.cert_serial,
            true,
            audit::AuditIdentity {
                agent_pid: Some(std::process::id()),
                ..Default::default()
            },
        ));
        return Ok(pre);
    }
    let mut tokens = token_manager_for_hosted(hosted, creds_override)?;
    enroll_with_tokens(&mut tokens, &cert_dir, audit)
}

fn token_manager_for_hosted(
    hosted: &HostedConfig,
    creds_override: Option<&Path>,
) -> anyhow::Result<login::TokenManager> {
    let (creds_path, mut creds) = require_credentials_with(creds_override)?;
    if let Some(url) = &hosted.control_plane_url {
        creds.control_plane_url = url.clone();
    }
    Ok(login::TokenManager::new(creds_path, creds))
}

fn cert_dir_for_hosted(
    hosted: &HostedConfig,
    creds_override: Option<&Path>,
) -> anyhow::Result<PathBuf> {
    // Precedence: explicit `hosted.cert_dir` in config > parent dir of the
    // --credentials override > built-in default (~/.config/orlop). The
    // override-implies-cert-dir rule means a single `orlop mount --credentials
    // /tmp/m2/creds.json` fully isolates state on one host.
    if let Some(dir) = &hosted.cert_dir {
        return Ok(dir.clone());
    }
    if let Some(path) = creds_override {
        if let Some(parent) = path.parent() {
            return Ok(parent.to_path_buf());
        }
    }
    enroll::default_cert_dir()
}

fn control_plane_url_for_hosted(
    hosted: &HostedConfig,
    creds_override: Option<&Path>,
) -> anyhow::Result<String> {
    // Pre-enrolled mode (Phase 2): no credentials.json on disk, so the
    // hosted.control_plane_url is required and there's nowhere to fall
    // back to. Spawner writes a real URL; entrypoint plumbs it into
    // config.yaml at /run/orlop/config.yaml.
    if let Ok(cert_dir) = cert_dir_for_hosted(hosted, creds_override) {
        if cert_dir.join(enroll::FILE_ENROLLMENT).exists() {
            return hosted.control_plane_url.clone().ok_or_else(|| {
                anyhow!("pre-enrolled hosted mode requires hosted.control_plane_url in config")
            });
        }
    }
    let (_, creds) = require_credentials_with(creds_override)?;
    Ok(hosted
        .control_plane_url
        .clone()
        .unwrap_or(creds.control_plane_url))
}

/// Load the credentials at `creds_override` if set, else the default location.
/// Bails with a re-enroll hint when the file is missing.
fn require_credentials_with(
    creds_override: Option<&Path>,
) -> anyhow::Result<(PathBuf, login::Credentials)> {
    match creds_override {
        Some(path) => {
            let creds = login::load(path)?.ok_or_else(|| {
                anyhow!(
                    "no credentials at {} — the host must re-enroll the agent \
                     (mint a fresh enroll token and re-run `orlop mount --from-env`)",
                    path.display()
                )
            })?;
            Ok((path.to_path_buf(), creds))
        }
        None => login::require_credentials(),
    }
}

fn enroll_with_tokens(
    tokens: &mut login::TokenManager,
    cert_dir: &Path,
    audit: &audit::AuditLog,
) -> anyhow::Result<EnrolledCert> {
    let _ = tokens.access_token()?;
    let creds = tokens.credentials().clone();

    let identity = audit::AuditIdentity {
        agent_pid: Some(std::process::id()),
        ..Default::default()
    };
    match enroll::enroll(&creds, cert_dir) {
        Ok(enrolled) => {
            tokens.update_allocation(enrolled.allocation_id.clone(), enrolled.size_bytes)?;
            tokens.update_server_addr(&enrolled.server_addr)?;
            audit.record(audit::AuditEvent::simple(
                audit::event::ENROLLMENT,
                &enrolled.cert_serial,
                true,
                identity,
            ));
            Ok(enrolled)
        }
        Err(err) => {
            audit.record(audit::AuditEvent::simple(
                audit::event::ENROLLMENT,
                "",
                false,
                identity,
            ));
            Err(err)
        }
    }
}

fn format_quota(size_bytes: Option<u64>) -> String {
    match size_bytes {
        Some(size) => format!("quota {}", human_bytes(size)),
        None => "quota unknown".to_string(),
    }
}

fn human_bytes(size: u64) -> String {
    const GIB: u64 = 1024 * 1024 * 1024;
    const MIB: u64 = 1024 * 1024;
    const KIB: u64 = 1024;
    // Exact-multiple fast path keeps quota strings clean ("5 GiB" not "5.00 GiB").
    if size.is_multiple_of(GIB) {
        return format!("{} GiB", size / GIB);
    }
    if size.is_multiple_of(MIB) {
        return format!("{} MiB", size / MIB);
    }
    // For arbitrary sizes (e.g. live disk usage), pick the largest unit that
    // gives a >= 1 quotient and render two decimals.
    if size >= GIB {
        return format!("{:.2} GiB", size as f64 / GIB as f64);
    }
    if size >= MIB {
        return format!("{:.2} MiB", size as f64 / MIB as f64);
    }
    if size >= KIB {
        return format!("{:.2} KiB", size as f64 / KIB as f64);
    }
    format!("{size} B")
}

struct CertManager {
    stop: mpsc::Sender<()>,
    handle: Option<thread::JoinHandle<()>>,
    cert_dir: PathBuf,
}

#[derive(Clone)]
struct MountLeaseClient {
    client: reqwest::blocking::Client,
    base_url: String,
    allocation_id: String,
    agent_fingerprint: String,
}

#[derive(Deserialize)]
struct MountLeaseResp {
    expires_at: chrono::DateTime<chrono::Utc>,
}

struct MountLeaseManager {
    client: MountLeaseClient,
    stop: mpsc::Sender<()>,
    handle: Option<thread::JoinHandle<()>>,
    revoked: Arc<AtomicBool>,
}

impl MountLeaseManager {
    fn acquire(
        control_plane_url: String,
        allocation_id: String,
        agent_fingerprint: String,
        tls: TlsIdentity,
        mountpoint: PathBuf,
    ) -> anyhow::Result<Self> {
        let client =
            MountLeaseClient::new(control_plane_url, allocation_id, agent_fingerprint, tls)?;
        let lease = client.acquire()?;
        eprintln!(
            "acquired mount lease until {}",
            lease.expires_at.to_rfc3339()
        );

        let (stop, rx) = mpsc::channel();
        let thread_client = client.clone();
        let revoked = Arc::new(AtomicBool::new(false));
        let thread_revoked = revoked.clone();
        let handle = thread::spawn(move || {
            mount_lease_refresh_loop(&rx, thread_client, mountpoint, thread_revoked);
        });
        Ok(Self {
            client,
            stop,
            handle: Some(handle),
            revoked,
        })
    }
}

impl Drop for MountLeaseManager {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        if !self.revoked.load(Ordering::Relaxed) {
            util::warn_err("mount lease release", self.client.release());
        }
    }
}

impl MountLeaseClient {
    fn new(
        control_plane_url: String,
        allocation_id: String,
        agent_fingerprint: String,
        tls: TlsIdentity,
    ) -> anyhow::Result<Self> {
        let identity =
            reqwest::Identity::from_pem(&tls.pem_bundle()).context("parse client TLS identity")?;
        let client = reqwest::blocking::Client::builder()
            .identity(identity)
            .timeout(Duration::from_secs(10))
            .build()
            .context("build mount lease HTTP client")?;
        Ok(Self {
            client,
            base_url: control_plane_url.trim_end_matches('/').to_string(),
            allocation_id,
            agent_fingerprint,
        })
    }

    fn acquire(&self) -> anyhow::Result<MountLeaseResp> {
        let resp = self
            .client
            .post(self.url(""))
            .json(&self.body())
            .send()
            .with_context(|| format!("POST {}", self.url("")))?;
        self.decode_lease_response(resp, "acquire")
    }

    fn refresh(&self) -> anyhow::Result<MountLeaseResp> {
        let resp = self
            .client
            .post(self.url("/refresh"))
            .json(&self.body())
            .send()
            .with_context(|| format!("POST {}", self.url("/refresh")))?;
        self.decode_lease_response(resp, "refresh")
    }

    fn release(&self) -> anyhow::Result<()> {
        let resp = self
            .client
            .delete(self.url(""))
            .json(&self.body())
            .send()
            .with_context(|| format!("DELETE {}", self.url("")))?;
        if resp.status().is_success() || resp.status() == StatusCode::NOT_FOUND {
            return Ok(());
        }
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        anyhow::bail!("release mount lease failed: {status} {body}");
    }

    fn decode_lease_response(
        &self,
        resp: reqwest::blocking::Response,
        op: &str,
    ) -> anyhow::Result<MountLeaseResp> {
        let status = resp.status();
        if status.is_success() {
            return resp.json().context("decode mount lease response");
        }
        let body = resp.text().unwrap_or_default();
        Err(classify_lease_error(status, &body, op))
    }

    fn url(&self, suffix: &str) -> String {
        format!(
            "{}/api/allocations/{}/mount{}",
            self.base_url, self.allocation_id, suffix
        )
    }

    fn body(&self) -> serde_json::Value {
        serde_json::json!({ "agent_fingerprint": self.agent_fingerprint })
    }
}

/// Maps a non-2xx lease response onto an `anyhow::Error` whose message the
/// refresh loop classifies as either retryable (warn and continue) or
/// terminal ("revoked" / "lease lost" / "already mounted by another agent"
/// → unmount). See `mount_lease_refresh_loop` for the matching strings.
fn classify_lease_error(status: StatusCode, body: &str, op: &str) -> anyhow::Error {
    if status == StatusCode::CONFLICT && body.contains("already_mounted") {
        return anyhow::anyhow!("allocation is already mounted by another agent");
    }
    if status == StatusCode::GONE && body.contains("revoked") {
        return anyhow::anyhow!("mount lease revoked");
    }
    if status == StatusCode::GONE && body.contains("lease_lost") {
        return anyhow::anyhow!("mount lease lost");
    }
    // 401 invalid_client on /mount/refresh means the allocation row or
    // agent enrollment is gone — not transient. Mapping it onto the
    // existing "lease lost" terminal path makes the refresh loop exit and
    // unmount instead of polling every 30s forever (staging hit this with
    // 119 401s/hour against a deleted allocation).
    if status == StatusCode::UNAUTHORIZED && body.contains("invalid_client") {
        return anyhow::anyhow!("mount lease lost");
    }
    anyhow::anyhow!("{op} mount lease failed: {status} {body}")
}

fn mount_lease_refresh_loop(
    stop: &mpsc::Receiver<()>,
    client: MountLeaseClient,
    mountpoint: PathBuf,
    revoked: Arc<AtomicBool>,
) {
    loop {
        if stop.recv_timeout(Duration::from_secs(30)).is_ok() {
            return;
        }
        match client.refresh() {
            Ok(lease) => {
                eprintln!(
                    "refreshed mount lease until {}",
                    lease.expires_at.to_rfc3339()
                );
            }
            Err(err) => {
                let msg = err.to_string();
                // "already mounted by another agent" comes from a Take over —
                // the dashboard handed our lease to a different device. Same
                // fatal treatment as a revoke: drop the now-useless mount
                // cleanly instead of spinning warnings forever (#155).
                if msg.contains("revoked")
                    || msg.contains("lease lost")
                    || msg.contains("already mounted by another agent")
                {
                    revoked.store(true, Ordering::Relaxed);
                    eprintln!(
                        "{msg}; signaling daemon to unmount {}",
                        mountpoint.display()
                    );
                    // Signal ourselves — MountedFs's signal handler runs Drop which
                    // releases the lease and unmounts cleanly. Works in both daemon
                    // and --foreground modes because both install the SIGTERM handler
                    // (see src/mount.rs MountedFs::wait).
                    orlop::daemon::raise_signal(libc::SIGTERM);
                    return;
                }
                eprintln!("warning: mount lease refresh failed: {err:#}");
            }
        }
    }
}

impl CertManager {
    fn start(
        hosted: HostedConfig,
        creds_override: Option<&Path>,
        initial: EnrolledCert,
        audit: audit::AuditLog,
    ) -> anyhow::Result<Self> {
        let cert_dir = cert_dir_for_hosted(&hosted, creds_override)?;
        // Pre-enrolled hosted mode (Phase 2 anonymous sandbox): the cert
        // TTL (5 min) equals the session TTL (5 min). The session expires
        // before the renewal would fire, and there are no refresh tokens
        // to renew with anyway. Skip the renewal task; Drop still shreds
        // the cert dir on unmount.
        if cert_dir.join(enroll::FILE_ENROLLMENT).exists() {
            let _ = initial; // not used in pre-enrolled mode
            let _ = audit;
            let (stop, _rx) = mpsc::channel();
            return Ok(Self {
                stop,
                handle: None,
                cert_dir,
            });
        }
        let mut tokens = token_manager_for_hosted(&hosted, creds_override)?;
        let (stop, rx) = mpsc::channel();
        let thread_cert_dir = cert_dir.clone();
        let handle = thread::spawn(move || {
            cert_renewal_loop(&rx, &mut tokens, &thread_cert_dir, initial, &audit);
        });
        Ok(Self {
            stop,
            handle: Some(handle),
            cert_dir,
        })
    }
}

impl Drop for CertManager {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        util::warn_err("cert shred", enroll::shred(&self.cert_dir));
    }
}

fn cert_renewal_loop(
    stop: &mpsc::Receiver<()>,
    tokens: &mut login::TokenManager,
    cert_dir: &Path,
    mut current: EnrolledCert,
    audit: &audit::AuditLog,
) {
    let mut failure_count = 0u32;
    loop {
        let wait = renewal_wait(current.expires_at, failure_count);
        if stop.recv_timeout(wait).is_ok() {
            return;
        }

        // Long-lived-pod safety net: before re-enrolling, refresh the enroll
        // token via the pod's projected ServiceAccount token when the env wires
        // it up. The injected enroll token is short-lived (~10m) while the cert
        // it buys lives ~1h, so a pod that outlives the enroll token needs a
        // fresh one to re-enroll. Failure is non-fatal — fall back to the
        // existing token (see maybe_refresh_enroll_token).
        //
        // NOTE: this only fires for long-lived pods; one-shot pods exit before
        // the 1h cert (and thus this renewal loop) ever fires. It is wired and
        // unit-tested here for the response-parsing helper, but the full SA-token
        // -> control-plane -> fresh-enroll-token round-trip is only verifiable
        // end-to-end inside a real cluster.
        maybe_refresh_enroll_token(tokens, cert_dir);

        match renew_cert(tokens, cert_dir, audit) {
            Ok(enrolled) => {
                eprintln!(
                    "renewed hosted client certificate serial={} expires_at={}",
                    enrolled.cert_serial,
                    enrolled.expires_at.to_rfc3339()
                );
                current = enrolled;
                failure_count = 0;
            }
            Err(err) => {
                failure_count = failure_count.saturating_add(1);
                eprintln!("warning: hosted client certificate renewal failed: {err:#}");
                if auth_state_invalid(&err) {
                    eprintln!(
                        "hosted session is invalid; the host must re-enroll the agent \
                         (mint a fresh enroll token and re-run `orlop mount --from-env`)"
                    );
                    return;
                }
            }
        }
    }
}

fn renew_cert(
    tokens: &mut login::TokenManager,
    cert_dir: &Path,
    audit: &audit::AuditLog,
) -> anyhow::Result<EnrolledCert> {
    enroll_with_tokens(tokens, cert_dir, audit)
}

/// Env var holding the path to the pod's projected ServiceAccount token file.
const ENV_SA_TOKEN_PATH: &str = "ORLOP_SA_TOKEN_PATH";
/// Env var holding the control-plane enroll-token refresh URL.
const ENV_REFRESH_URL: &str = "ORLOP_REFRESH_URL";

/// Best-effort enroll-token refresh for the long-lived in-pod mounter.
///
/// When both `ORLOP_SA_TOKEN_PATH` and `ORLOP_REFRESH_URL` are set (the
/// control-plane wired the projected SA token + refresh endpoint into the
/// sidecar), read the SA token, POST it to the refresh URL, and on success
/// rewrite `credentials.json` with the fresh enroll token so the subsequent
/// `renew_cert` re-enrolls with it; the in-memory `TokenManager` is reloaded
/// from the rewritten file.
///
/// Graceful fallback: any failure (env unset, file unreadable, network error,
/// non-2xx, malformed body) logs a warning and returns without touching
/// `tokens`, so renewal proceeds with the existing token. The control-plane
/// derives the agent from the TokenReview'd pod label, never from this request.
fn maybe_refresh_enroll_token(tokens: &mut login::TokenManager, cert_dir: &Path) {
    let (sa_path, refresh_url) = match (
        std::env::var(ENV_SA_TOKEN_PATH)
            .ok()
            .filter(|v| !v.is_empty()),
        std::env::var(ENV_REFRESH_URL)
            .ok()
            .filter(|v| !v.is_empty()),
    ) {
        (Some(p), Some(u)) => (p, u),
        _ => return, // not an SA-refresh-enabled pod; nothing to do
    };
    if let Err(err) = refresh_enroll_token(tokens, cert_dir, &sa_path, &refresh_url) {
        eprintln!("warning: enroll-token refresh failed, proceeding with existing token: {err:#}");
    }
}

/// Body of [`maybe_refresh_enroll_token`]: read the SA token, exchange it for a
/// fresh enroll token, rewrite credentials, and reload the token manager.
fn refresh_enroll_token(
    tokens: &mut login::TokenManager,
    cert_dir: &Path,
    sa_path: &str,
    refresh_url: &str,
) -> anyhow::Result<()> {
    let sa_token =
        std::fs::read_to_string(sa_path).with_context(|| format!("read SA token {sa_path}"))?;
    let sa_token = sa_token.trim();
    if sa_token.is_empty() {
        anyhow::bail!("SA token file {sa_path} is empty");
    }

    let client = util::http_client(Duration::from_secs(30))?;
    let resp = client
        .post(refresh_url)
        .bearer_auth(sa_token)
        .send()
        .with_context(|| format!("POST {refresh_url}"))?;
    let status = resp.status();
    let body = resp.text().unwrap_or_default();
    if !status.is_success() {
        anyhow::bail!("enroll-token refresh returned {status}: {body}");
    }
    let fresh_token = parse_refresh_response(&body)?;

    // Rewrite credentials.json so renew_cert re-enrolls with the fresh token,
    // preserving the control-plane URL from the current credentials.
    let control_plane = tokens.credentials().control_plane_url.clone();
    let creds = login::Credentials::for_enroll(control_plane, fresh_token);
    let creds_path = cert_dir.join("credentials.json");
    login::save(&creds_path, &creds)
        .with_context(|| format!("write refreshed credentials to {}", creds_path.display()))?;
    // Reload the in-memory TokenManager from the rewritten file.
    *tokens = login::TokenManager::load(creds_path)?;
    eprintln!("refreshed enroll token via projected ServiceAccount token");
    Ok(())
}

/// Parse the control-plane enroll-token refresh response body, returning the
/// fresh enroll token. Pure (no I/O) so it is unit-tested directly.
fn parse_refresh_response(body: &str) -> anyhow::Result<String> {
    #[derive(Deserialize)]
    struct RefreshResp {
        token: String,
    }
    let parsed: RefreshResp =
        serde_json::from_str(body).context("decode enroll-token refresh response")?;
    if parsed.token.trim().is_empty() {
        anyhow::bail!("enroll-token refresh response contained an empty token");
    }
    Ok(parsed.token)
}

fn renewal_wait(expires_at: chrono::DateTime<chrono::Utc>, failures: u32) -> Duration {
    let now = chrono::Utc::now();
    let renew_at = expires_at - chrono::Duration::minutes(10);
    if failures == 0 && renew_at > now {
        return (renew_at - now)
            .to_std()
            .unwrap_or_else(|_| Duration::from_secs(0));
    }

    let remaining = expires_at - now;
    let base = if remaining <= chrono::Duration::minutes(2) {
        Duration::from_secs(5)
    } else {
        let capped = failures.min(6);
        Duration::from_secs(30u64.saturating_mul(1 << capped))
    };
    let jitter = Duration::from_millis(jitter_millis(750));
    base.saturating_add(jitter)
}

fn jitter_millis(max: u64) -> u64 {
    if max == 0 {
        return 0;
    }
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| (d.subsec_nanos() as u64) % max)
        .unwrap_or(0)
}

fn auth_state_invalid(err: &anyhow::Error) -> bool {
    // Cases where the cert-renewer loop should give up rather than back off:
    // every recovery path here is "the host must do something" (re-enroll the
    // agent, contact support for suspension, etc) — retrying behind the scenes
    // will never succeed. "re-enroll" is the stable marker carried by every
    // terminal auth failure from the refresh (login.rs) and enroll (enroll.rs)
    // paths; the remaining substrings catch 403 hints that don't restate it.
    let msg = err.to_string();
    msg.contains("re-enroll")
        || msg.contains("session expired")
        || msg.contains("access denied")
        || msg.contains("allocation was revoked")
        || msg.contains("tenant is suspended")
}

/// Parsed `orlop mount --from-env` inputs. The in-pod mounter is driven
/// entirely by env (the control plane injects these via the sidecar spec),
/// so there is no config file and no separate auth step: the enroll token
/// IS the identity, traded for a 1h client cert by `/agent/enroll`.
#[derive(Debug, Clone, PartialEq)]
struct EnvMountSpec {
    /// Informational; surfaced in logs so pod logs tie a mount to an agent.
    agent_id: String,
    mount_point: PathBuf,
    control_plane: String,
    enroll_token: String,
    /// Honor `ORLOP_CERT_DIR` when set so an operator can pin the cert
    /// location (e.g. a tmpfs); otherwise a fresh per-process tempdir.
    cert_dir: Option<PathBuf>,
}

impl EnvMountSpec {
    /// Read the spec from `getter` (an env lookup). Missing/empty required
    /// vars yield a precise "set ORLOP_X" error; `ORLOP_CERT_DIR` is optional.
    fn from_env_with(getter: impl Fn(&str) -> Option<String>) -> anyhow::Result<Self> {
        fn required(getter: &impl Fn(&str) -> Option<String>, key: &str) -> anyhow::Result<String> {
            match getter(key) {
                Some(v) if !v.trim().is_empty() => Ok(v),
                _ => Err(anyhow!(
                    "{key} is required for `orlop mount --from-env` but was not set"
                )),
            }
        }
        Ok(Self {
            agent_id: required(&getter, "ORLOP_AGENT_ID")?,
            mount_point: PathBuf::from(required(&getter, "ORLOP_MOUNT_POINT")?),
            control_plane: required(&getter, "ORLOP_CONTROL_PLANE")?,
            enroll_token: required(&getter, "ORLOP_ENROLL_TOKEN")?,
            cert_dir: getter("ORLOP_CERT_DIR")
                .filter(|v| !v.trim().is_empty())
                .map(PathBuf::from),
        })
    }

    fn from_env() -> anyhow::Result<Self> {
        Self::from_env_with(|k| std::env::var(k).ok())
    }
}

/// `orlop mount --from-env` entry point. Trades the env-supplied enroll token
/// for a short-lived (1h) client cert via `/agent/enroll`, then mounts over
/// the existing mTLS data path. Reuses the standard hosted mount engine by
/// synthesizing a `Config` + on-disk `Credentials` and routing through
/// `run_mount_payload`; that also reuses `CertManager`, whose renewal task is
/// the refresh safety net (re-enrolls ~10 min before the 1h cert expires and
/// atomically replaces the on-disk cert files via `enroll::persist`).
///
// NOTE: refresh keeps the cert files on disk fresh, but the live mTLS data
// connection does NOT hot-swap the cert — quinn/rustls captured the identity
// at dial time, so a rotated cert only takes effect on the next dial (i.e. a
// remount). This is intentional and harmless for the common case: the in-pod
// mounter runs in a one-shot pod that exits well before the 1h cert expires,
// so the renewal never fires. Live rotation is deliberately not built.
fn run_env_mount(no_inject: bool) -> anyhow::Result<()> {
    let spec = EnvMountSpec::from_env()?;

    // Isolated cert dir: honor ORLOP_CERT_DIR, else a fresh tempdir. The
    // TempDir guard (when used) must outlive the blocking mount below, so
    // bind it for the whole function. cert.pem/key.pem/ca.pem + the synthesized
    // credentials.json all live here; CertManager shreds the certs on unmount.
    let (cert_dir, _tmp_guard): (PathBuf, Option<tempfile::TempDir>) = match &spec.cert_dir {
        Some(dir) => {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("create ORLOP_CERT_DIR {}", dir.display()))?;
            (dir.clone(), None)
        }
        None => {
            let tmp = tempfile::Builder::new()
                .prefix("orlop-mount-")
                .tempdir()
                .context("create cert tempdir for --from-env mount")?;
            (tmp.path().to_path_buf(), Some(tmp))
        }
    };

    // Persist the enroll token as credentials.json so the standard hosted
    // path (enroll_for_mount -> token_manager_for_hosted -> require_credentials_with)
    // and the CertManager renewal loop both load it without any separate auth step.
    let creds = login::Credentials::for_enroll(spec.control_plane.clone(), spec.enroll_token);
    let creds_path = cert_dir.join("credentials.json");
    login::save(&creds_path, &creds)
        .with_context(|| format!("write credentials to {}", creds_path.display()))?;

    eprintln!(
        "mounting agent {} at {} via {}",
        spec.agent_id,
        spec.mount_point.display(),
        spec.control_plane,
    );

    // Synthesize a hosted Config. control_plane_url + cert_dir come from env;
    // policy is read-write (the in-pod disk is the workspace, matching the
    // default hosted config), and the rest take struct defaults.
    let cfg = Config {
        mountpoint: Some(spec.mount_point.clone()),
        audit_log: default_env_audit_log(&cert_dir),
        cache: None,
        fuse: Default::default(),
        policy: orlop::config::PolicyConfig {
            readonly: false,
            deny: Vec::new(),
            allow: Vec::new(),
        },
        mounts: Vec::new(),
        hosted: Some(HostedConfig {
            control_plane_url: Some(spec.control_plane),
            cert_dir: Some(cert_dir.clone()),
            // Mount the agent's own disk dir as the FUSE root. The agent-scoped
            // cert is confined to /<agent_id> by orlop-server's per-agent
            // authz (Phase 3); a single top-level segment lets the mounter create
            // it on mount — its parent is the tenant root, which already exists.
            mount_root: Some(format!("/{}", spec.agent_id)),
        }),
        chunk_cache: Default::default(),
    };

    run_mount_payload(
        &cfg,
        spec.mount_point,
        Some(creds_path.as_path()),
        no_inject,
        None,
        None,
    )
}

/// Audit log path for `--from-env` mounts. Lives in the (ephemeral) cert dir
/// so a one-shot pod doesn't need a writable cwd or a mounted log volume.
fn default_env_audit_log(cert_dir: &Path) -> PathBuf {
    cert_dir.join("audit.log")
}

/// Body of `orlop mount` — acquires lease, sets up backends, calls
/// `orlop::mount::mount`, optionally injects AGENTS.md, then blocks on
/// `wait()` until SIGTERM/SIGINT. Called from both the foreground path
/// and the daemon grandchild path.
///
/// `ready_signal` is `None` in the foreground path; in the daemon path
/// it's `Some(closure)` that writes `READY\n` to the parent's pipe once
/// the mount is up. Errors before signaling are surfaced via the same
/// closure (parent translates to "ERR <msg>\n").
fn run_mount_payload(
    cfg: &Config,
    mountpoint: PathBuf,
    creds_override: Option<&Path>,
    no_inject: bool,
    ready_signal: Option<Box<dyn FnOnce(Result<(), String>) + Send>>,
    original_cwd: Option<PathBuf>, // parent's cwd before daemonize chdir'd to /
) -> anyhow::Result<()> {
    if std::env::var("ORLOP_DAEMON_TEST_SKIP_MOUNT").is_ok() {
        // Test-only fast path: skip lease/mount/wait. Signal ready, sleep
        // until SIGTERM, then exit. Lets integration tests exercise the
        // daemon lifecycle without real FUSE/NFS/control-plane.
        let _ = original_cwd; // unused in fast path
        if let Some(signal) = ready_signal {
            signal(Ok(()));
        }
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        rt.block_on(async {
            use tokio::signal::unix::{signal, SignalKind};
            let mut term = signal(SignalKind::terminate()).unwrap();
            let mut int = signal(SignalKind::interrupt()).unwrap();
            tokio::select! {
                _ = term.recv() => {},
                _ = int.recv() => {},
            }
        });
        return Ok(());
    }

    let audit = audit::AuditLog::new(cfg.audit_log.clone())?;
    let cache_cfg = cfg.cache.clone().unwrap_or_default();
    let chunk_cache = backend::dataplane::ChunkCache::open(
        chunk_cache_root()?,
        cfg.chunk_cache.max_bytes,
        Some(audit.clone()),
    )?;

    // Light scan: evict over-quota state from prior sessions before serving FUSE.
    match chunk_cache.prune_to_low_water() {
        Ok(0) => {}
        Ok(n) => eprintln!("chunk cache trimmed to low-water on mount: evicted {n}"),
        Err(e) => {
            eprintln!("warning: mount-time cache prune failed; continuing: {e:#}")
        }
    }

    let (backends, _cert_manager, _lease_manager) = if let Some(hosted) = cfg.hosted.clone() {
        let enrolled = enroll_for_mount(&hosted, creds_override, &audit)?;
        let tls = enroll::load_identity(&enrolled)
            .with_context(|| format!("load identity from {}", enrolled.cert_dir.display()))?;
        let allocation_id = enrolled.allocation_id.clone().ok_or_else(|| {
            anyhow!(
                "no allocation_id in enrollment response; the host must re-enroll \
                 the agent (mint a fresh enroll token and re-run `orlop mount --from-env`)"
            )
        })?;
        // Pre-enrolled hosted mode (Phase 2 anonymous sandbox): the cert
        // was minted directly by control without a row in agent_enrollments,
        // so the /api/allocations/{id}/mount endpoint would 401 invalid_client.
        // Skip the control-plane lease too — the session has no dashboard
        // takeover surface and expires in 5 min anyway; the data-plane
        // LeaseGrant RPC below still enforces the per-allocation single-writer
        // invariant via the mountLeases registry.
        let pre_enrolled = enroll::load_enrollment_sidecar(&enrolled.cert_dir)?.is_some();
        let lease_manager = if pre_enrolled {
            None
        } else {
            Some(MountLeaseManager::acquire(
                control_plane_url_for_hosted(&hosted, creds_override)?,
                allocation_id.clone(),
                enrolled.cert_serial.clone(),
                tls.clone(),
                mountpoint.clone(),
            )?)
        };
        let addr = enrolled.server_addr.clone();
        eprintln!(
            "Allocation {} on {} ({})",
            allocation_id,
            addr,
            format_quota(enrolled.size_bytes),
        );
        let mount_cfg = MountConfig {
            name: "orlop".to_string(),
            kind: MountKind::Remote,
            mount: hosted.mount_root.clone().unwrap_or_else(|| "/".to_string()),
            readonly: cfg.policy.readonly,
            deny: cfg.policy.deny.clone(),
            allow: cfg.policy.allow.clone(),
            addr: Some(addr),
            server_name: None,
        };
        let backends = build_stores(&[mount_cfg], Some(&tls), Arc::clone(&chunk_cache))?;
        for b in &backends {
            b.store.set_allocation_id(Some(allocation_id.clone()));
            // Ensure the agent's disk dir exists so its mount root is writable.
            // Only for a subtree mount (the tenant root "/" already exists). The
            // agent-scoped cert can create its own /<id> (its authz root) but not
            // the tenant root. Idempotent — a re-mount just finds it present.
            if !b.mount_name.is_empty() {
                if let Err(e) = b.store.dir_create("", 0o755) {
                    eprintln!("ensure agent disk dir {}: {e:#}", b.mount_name);
                }
            }
        }
        let cert_manager = CertManager::start(hosted, creds_override, enrolled, audit.clone())
            .with_context(|| "start hosted client certificate renewal task")?;
        (backends, Some(cert_manager), lease_manager)
    } else {
        (
            build_stores(&cfg.fuse_mounts()?, None, Arc::clone(&chunk_cache))?,
            None,
            None,
        )
    };

    std::fs::create_dir_all(&mountpoint)
        .with_context(|| format!("failed to create mountpoint {}", mountpoint.display()))?;

    // mount::mount handles the platform branch — FUSE on Linux,
    // localhost NFSv3 on macOS — and wires the notifier (Linux) /
    // spawns the NFS server (macOS) before returning.
    let mounted = orlop::mount::mount(
        backends,
        audit,
        &cfg.fuse,
        cache_cfg.write_buffer_bytes,
        &mountpoint,
    )?;

    if !no_inject {
        // Use the original cwd (captured before daemonize chdir'd to /).
        // In the foreground path original_cwd is None, so fall back to
        // std::env::current_dir() which is still correct there.
        let inject_result = match original_cwd.as_deref() {
            Some(cwd) => agents_md::maybe_inject_into_cwd_at(&mountpoint, cwd),
            None => agents_md::maybe_inject_into_cwd(&mountpoint),
        };
        match inject_result {
            Ok((Some(path), action)) => match action {
                agents_md::InjectAction::Created => {
                    eprintln!("wrote Orlop stanza to {} (new file)", path.display())
                }
                agents_md::InjectAction::Appended => {
                    eprintln!("appended Orlop stanza to {}", path.display())
                }
                agents_md::InjectAction::Updated => {
                    eprintln!("updated Orlop stanza in {}", path.display())
                }
                agents_md::InjectAction::Unchanged => {}
                agents_md::InjectAction::SkippedNoFile => {}
            },
            Ok((None, _)) => {}
            Err(err) => eprintln!("warning: AGENTS.md injection skipped: {err:#}"),
        }
    }

    // Health-probe the freshly-established mount on a background thread, then
    // signal readiness from there. On Linux the FUSE dispatch loop only starts
    // inside `wait()` below, so the probe MUST run on another thread — its
    // syscalls queue in the kernel until dispatch begins, then complete. A
    // probe failure means the mount cannot serve I/O, so we tear it down (which
    // unblocks `wait()`) and surface the error so the daemon parent / in-pod
    // supervisor sees a failed mount instead of a silently broken one.
    // `ORLOP_SKIP_MOUNT_PROBE` is an escape hatch that restores the old
    // signal-then-wait behavior.
    let skip_probe = std::env::var_os("ORLOP_SKIP_MOUNT_PROBE").is_some();
    let readonly = cfg.policy.readonly;
    let probe_mp = mountpoint.clone();
    let probe_outcome: Arc<std::sync::Mutex<Option<Result<(), String>>>> =
        Arc::new(std::sync::Mutex::new(None));
    let probe_outcome_thread = Arc::clone(&probe_outcome);
    let probe_thread = thread::Builder::new()
        .name("orlop-mount-probe".into())
        .spawn(move || {
            let result = if skip_probe {
                Ok(())
            } else {
                orlop::mount::probe_mount(&probe_mp, readonly).map_err(|e| format!("{e:#}"))
            };
            match &result {
                Ok(()) if !skip_probe => eprintln!("mount verified at {}", probe_mp.display()),
                Ok(()) => {}
                Err(msg) => {
                    eprintln!(
                        "error: mount health probe failed at {}: {msg}",
                        probe_mp.display()
                    );
                    // Tear the mount down so `wait()` returns and supervisors
                    // (daemon parent, CSI node, pod) observe the failure.
                    let _ = orlop::mount::unmount(&probe_mp);
                }
            }
            if let Some(signal) = ready_signal {
                signal(result.clone());
            }
            *probe_outcome_thread.lock().unwrap() = Some(result);
        })?;

    // Block until the kernel tears the mount down (Linux) or SIGINT arrives
    // (macOS). MountedFs::Drop runs unmount on all exits.
    let wait_result = mounted.wait();
    let _ = probe_thread.join();
    wait_result?;

    // A probe failure tore the mount down above; report it so foreground /
    // in-pod callers exit non-zero rather than looking like a clean mount.
    if let Some(Err(msg)) = probe_outcome.lock().unwrap().take() {
        anyhow::bail!("mount health probe failed: {msg}");
    }
    Ok(())
}

fn shred_hosted_certs(hosted: &HostedConfig, creds_override: Option<&Path>) -> anyhow::Result<()> {
    let cert_dir = cert_dir_for_hosted(hosted, creds_override)?;
    enroll::shred(&cert_dir)
}

fn release_hosted_mount_lease(
    hosted: &HostedConfig,
    creds_override: Option<&Path>,
) -> anyhow::Result<()> {
    let cert_dir = cert_dir_for_hosted(hosted, creds_override)?;
    // Pre-enrolled mode never acquired a control-plane lease (see the
    // mount() symmetric guard), so there's nothing to release here.
    if enroll::load_enrollment_sidecar(&cert_dir)?.is_some() {
        return Ok(());
    }
    let tls = enroll::load_identity_from_dir(&cert_dir)?;
    let agent_fingerprint = enroll::cert_serial_from_dir(&cert_dir)?;
    let tokens = token_manager_for_hosted(hosted, creds_override)?;
    let allocation_id = tokens
        .credentials()
        .allocation_id
        .clone()
        .ok_or_else(|| anyhow!("no allocation_id in cached credentials"))?;
    let client = MountLeaseClient::new(
        control_plane_url_for_hosted(hosted, creds_override)?,
        allocation_id,
        agent_fingerprint,
        tls,
    )?;
    client.release()
}

#[cfg(test)]
mod env_mount {
    use super::*;
    use std::collections::HashMap;

    fn getter<'a>(map: &'a HashMap<&str, &str>) -> impl Fn(&str) -> Option<String> + 'a {
        move |k: &str| map.get(k).map(|v| v.to_string())
    }

    fn full() -> HashMap<&'static str, &'static str> {
        HashMap::from([
            ("ORLOP_AGENT_ID", "agent-123"),
            ("ORLOP_MOUNT_POINT", "/mnt/orlop"),
            ("ORLOP_CONTROL_PLANE", "https://control.example"),
            ("ORLOP_ENROLL_TOKEN", "enr_tok_abc"),
        ])
    }

    #[test]
    fn from_env_happy_path_builds_spec() {
        let map = full();
        let spec = EnvMountSpec::from_env_with(getter(&map)).unwrap();
        assert_eq!(spec.agent_id, "agent-123");
        assert_eq!(spec.mount_point, PathBuf::from("/mnt/orlop"));
        assert_eq!(spec.control_plane, "https://control.example");
        assert_eq!(spec.enroll_token, "enr_tok_abc");
        // ORLOP_CERT_DIR unset -> tempdir path chosen at run time.
        assert_eq!(spec.cert_dir, None);
    }

    #[test]
    fn from_env_honors_cert_dir_override() {
        let mut map = full();
        map.insert("ORLOP_CERT_DIR", "/run/orlop/certs");
        let spec = EnvMountSpec::from_env_with(getter(&map)).unwrap();
        assert_eq!(spec.cert_dir, Some(PathBuf::from("/run/orlop/certs")));
    }

    #[test]
    fn from_env_missing_required_var_is_a_clear_error() {
        for missing in [
            "ORLOP_AGENT_ID",
            "ORLOP_MOUNT_POINT",
            "ORLOP_CONTROL_PLANE",
            "ORLOP_ENROLL_TOKEN",
        ] {
            let mut map = full();
            map.remove(missing);
            let err = EnvMountSpec::from_env_with(getter(&map)).unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains(missing),
                "expected {missing} in error, got: {msg}"
            );
            assert!(msg.contains("--from-env"), "got: {msg}");
        }
    }

    #[test]
    fn from_env_treats_blank_required_var_as_missing() {
        let mut map = full();
        map.insert("ORLOP_ENROLL_TOKEN", "   ");
        let err = EnvMountSpec::from_env_with(getter(&map)).unwrap_err();
        assert!(err.to_string().contains("ORLOP_ENROLL_TOKEN"));
    }

    #[test]
    fn parse_refresh_response_extracts_token() {
        let tok =
            parse_refresh_response(r#"{"token":"enr_fresh","expires_at":"2026-06-04T12:00:00Z"}"#)
                .unwrap();
        assert_eq!(tok, "enr_fresh");
        // expires_at is ignored; token-only body is also fine.
        let tok2 = parse_refresh_response(r#"{"token":"enr2"}"#).unwrap();
        assert_eq!(tok2, "enr2");
    }

    #[test]
    fn parse_refresh_response_rejects_empty_or_malformed() {
        assert!(parse_refresh_response(r#"{"token":""}"#).is_err());
        assert!(parse_refresh_response(r#"{"token":"  "}"#).is_err());
        assert!(parse_refresh_response(r#"{}"#).is_err()); // missing token field
        assert!(parse_refresh_response("not json").is_err());
    }

    #[test]
    fn for_enroll_uses_token_as_access_token_without_refresh() {
        let creds =
            login::Credentials::for_enroll("https://control.example/".into(), "enr_tok_abc".into());
        // The enroll token is the bearer sent to /agent/enroll verbatim.
        assert_eq!(creds.access_token, "enr_tok_abc");
        assert_eq!(creds.control_plane_base(), "https://control.example");
        // access_expires_at parked far ahead -> TokenManager never refreshes.
        assert!(creds.access_expires_at > chrono::Utc::now() + chrono::Duration::days(3000));
        // No refresh token; refresh would fail fast (expired) rather than dial.
        assert!(creds.refresh_token.is_empty());
        assert!(creds.refresh_expires_at <= chrono::Utc::now());
    }
}

#[cfg(test)]
mod cert_dir_resolution {
    use super::*;
    use std::path::PathBuf;

    fn hosted_with(cert_dir: Option<PathBuf>) -> HostedConfig {
        HostedConfig {
            control_plane_url: None,
            cert_dir,
            mount_root: None,
        }
    }

    #[test]
    fn override_creds_path_implies_parent_as_cert_dir() {
        let hosted = hosted_with(None);
        let creds = PathBuf::from("/tmp/isolated/creds.json");
        let resolved = cert_dir_for_hosted(&hosted, Some(creds.as_path())).unwrap();
        assert_eq!(resolved, PathBuf::from("/tmp/isolated"));
    }

    #[test]
    fn hosted_cert_dir_wins_over_creds_parent() {
        let hosted = hosted_with(Some(PathBuf::from("/explicit/cert/dir")));
        let creds = PathBuf::from("/tmp/isolated/creds.json");
        let resolved = cert_dir_for_hosted(&hosted, Some(creds.as_path())).unwrap();
        assert_eq!(resolved, PathBuf::from("/explicit/cert/dir"));
    }

    #[test]
    fn no_override_falls_back_to_default_when_hosted_is_empty() {
        let hosted = hosted_with(None);
        let resolved = cert_dir_for_hosted(&hosted, None).unwrap();
        assert_eq!(resolved, enroll::default_cert_dir().unwrap());
    }
}

#[cfg(test)]
mod lease_error_classification {
    use super::*;

    #[test]
    fn conflict_already_mounted_is_terminal() {
        let e = classify_lease_error(
            StatusCode::CONFLICT,
            r#"{"error":"already_mounted"}"#,
            "refresh",
        );
        assert!(e.to_string().contains("already mounted by another agent"));
    }

    #[test]
    fn gone_revoked_is_terminal() {
        let e = classify_lease_error(StatusCode::GONE, r#"{"error":"revoked"}"#, "refresh");
        assert!(e.to_string().contains("revoked"));
    }

    #[test]
    fn gone_lease_lost_is_terminal() {
        let e = classify_lease_error(StatusCode::GONE, r#"{"error":"lease_lost"}"#, "refresh");
        assert!(e.to_string().contains("lease lost"));
    }

    #[test]
    fn unauthorized_invalid_client_is_terminal() {
        // Regression: without the 401 arm the refresh loop polls a deleted
        // allocation forever (see classify_lease_error doc-comment).
        let e = classify_lease_error(
            StatusCode::UNAUTHORIZED,
            r#"{"error":"invalid_client"}"#,
            "refresh",
        );
        let msg = e.to_string();
        // Must match the substring the loop uses to decide to unmount.
        assert!(msg.contains("lease lost"), "msg = {msg}");
    }

    #[test]
    fn other_5xx_stays_retryable() {
        let e = classify_lease_error(StatusCode::BAD_GATEWAY, "upstream timeout", "refresh");
        let msg = e.to_string();
        // Must not contain any of the terminal substrings.
        for terminal in ["revoked", "lease lost", "already mounted by another agent"] {
            assert!(
                !msg.contains(terminal),
                "transient {msg:?} accidentally classified as terminal ({terminal})"
            );
        }
    }
}
