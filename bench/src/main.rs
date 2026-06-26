mod fixtures;
mod metrics;
mod netstats;
mod workload;
mod workloads;

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use clap::Parser;

use fixtures::Fixtures;
use metrics::{Status, SuiteOutput};
use netstats::IfaceStats;
use workload::RunCtx;

#[derive(Parser, Debug)]
#[command(
    name = "orlop-bench",
    about = "Benchmark harness for the orlop data plane (issue #74)."
)]
struct Cli {
    /// Mount point to drive workloads against (any filesystem).
    #[arg(long)]
    mount: PathBuf,

    /// Output JSON file path. Stdout if "-".
    #[arg(long, default_value = "-")]
    out: String,

    /// Comma-separated workload names to run. Default: all.
    #[arg(long)]
    workloads: Option<String>,

    /// Iterations for workloads that loop on the entire op (ls-large-dir,
    /// small-edit). Per-byte/per-op workloads (stat-storm, sequential-read)
    /// already amortize over many ops and ignore this.
    #[arg(long, default_value_t = 20)]
    repeat: usize,

    /// Worker threads issuing parallel ops. Affects stat-storm; other
    /// workloads stay serial. Higher parallelism shows the v2 mux win
    /// against v1's per-connection serialization.
    #[arg(long, default_value_t = 16)]
    parallelism: usize,

    /// Loopback iface to read byte counters from. /sys/class/net/<iface>/statistics.
    #[arg(long, default_value = "lo")]
    iface: String,

    /// Free-form label persisted in the result JSON (e.g. netem profile name).
    #[arg(long)]
    label: Option<String>,

    /// Free-form data-plane version persisted in the result JSON (e.g. v1, v2).
    #[arg(long)]
    data_plane: Option<String>,

    /// Shell command to remount the FS — used by cold-warm-cycle.
    #[arg(long)]
    mount_cmd: Option<String>,

    /// Shell command to unmount the FS — used by cold-warm-cycle.
    #[arg(long)]
    unmount_cmd: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if !cli.mount.exists() {
        return Err(anyhow!(
            "--mount path does not exist: {}",
            cli.mount.display()
        ));
    }
    let mount_meta =
        fs::metadata(&cli.mount).with_context(|| format!("stat {}", cli.mount.display()))?;
    if !mount_meta.is_dir() {
        return Err(anyhow!("--mount must be a directory"));
    }

    let fixtures = Fixtures::new(&cli.mount);
    let iface = IfaceStats::new(&cli.iface);

    let to_run: Vec<Box<dyn workload::Workload>> = match &cli.workloads {
        None => workloads::all(),
        Some(list) => list
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|name| workloads::lookup(name).ok_or_else(|| anyhow!("unknown workload: {name}")))
            .collect::<Result<Vec<_>>>()?,
    };

    let ctx = RunCtx {
        mount: &cli.mount,
        fixtures: &fixtures,
        iface: &iface,
        mount_cmd: cli.mount_cmd.as_deref(),
        unmount_cmd: cli.unmount_cmd.as_deref(),
        repeat: cli.repeat,
        parallelism: cli.parallelism.max(1),
    };

    let mut results = Vec::new();
    for w in &to_run {
        eprintln!("→ {}", w.name());
        match w.run(&ctx) {
            Ok(rs) => {
                for r in &rs {
                    eprintln!(
                        "  {} status={:?} ops={} p50={:.3}ms p99={:.3}ms wall={:.3}s rx={} tx={}",
                        r.name,
                        r.status,
                        r.ops,
                        r.p50_ms,
                        r.p99_ms,
                        r.duration_s,
                        r.bytes_in,
                        r.bytes_out
                    );
                }
                results.extend(rs);
            }
            Err(e) => {
                eprintln!("  error: {e:#}");
                results.push(metrics::WorkloadResult::error(w.name(), e.to_string()));
            }
        }
    }

    let suite = SuiteOutput {
        git_sha: git_sha(),
        git_dirty: git_dirty(),
        timestamp: Utc::now().to_rfc3339(),
        kernel: uname_release().unwrap_or_default(),
        label: cli.label,
        data_plane: cli.data_plane,
        mount: cli.mount.display().to_string(),
        iface: cli.iface,
        workloads: results,
    };

    let json = serde_json::to_string_pretty(&suite)?;
    if cli.out == "-" {
        println!("{json}");
    } else {
        let path = PathBuf::from(&cli.out);
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("create {}", parent.display()))?;
            }
        }
        let mut f =
            fs::File::create(&path).with_context(|| format!("create {}", path.display()))?;
        f.write_all(json.as_bytes())?;
        f.write_all(b"\n")?;
        eprintln!("wrote {}", path.display());
    }

    let any_error = suite.workloads.iter().any(|w| w.status == Status::Error);
    if any_error {
        std::process::exit(1);
    }
    Ok(())
}

fn git_sha() -> String {
    Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_default()
}

fn git_dirty() -> bool {
    Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false)
}

fn uname_release() -> Option<String> {
    Command::new("uname")
        .arg("-sr")
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                None
            }
        })
}
