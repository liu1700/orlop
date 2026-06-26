use std::fs::File;
use std::io::Read;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};

use crate::metrics::WorkloadResult;
use crate::netstats::delta;
use crate::workload::{RunCtx, Workload};
use crate::workloads::sequential_read::READ_BLOCK;

pub struct ColdWarmCycle;

impl Workload for ColdWarmCycle {
    fn name(&self) -> &'static str {
        "cold-warm-cycle"
    }

    fn run(&self, ctx: &RunCtx<'_>) -> Result<Vec<WorkloadResult>> {
        let (Some(unmount), Some(mount)) = (ctx.unmount_cmd, ctx.mount_cmd) else {
            return Ok(vec![WorkloadResult::skipped(
                self.name(),
                "requires --mount-cmd and --unmount-cmd; cycle measures effect of dropping cache via remount",
            )]);
        };

        ctx.fixtures.ensure_root()?;
        ctx.fixtures.ensure_seq_file()?;

        let cold = run_pass(ctx, "cold-warm-cycle.cold")?;
        run_shell(unmount).map_err(|e| anyhow!("unmount-cmd failed: {e}"))?;
        run_shell(mount).map_err(|e| anyhow!("mount-cmd failed: {e}"))?;
        wait_for_mount(ctx.mount, Duration::from_secs(10))?;
        // Re-stage fixtures only if the remount cleared them. The seq file is
        // expected to survive a real remount on a persistent backend; on
        // tmpfs this re-creates it.
        ctx.fixtures.ensure_root()?;
        ctx.fixtures.ensure_seq_file()?;
        let warm = run_pass(ctx, "cold-warm-cycle.warm")?;

        Ok(vec![cold, warm])
    }
}

fn run_pass(ctx: &RunCtx<'_>, name: &str) -> Result<WorkloadResult> {
    let path = ctx.fixtures.seq_file();
    let mut buf = vec![0u8; READ_BLOCK];
    let mut f = File::open(&path)?;
    let n_reads = (crate::fixtures::SEQ_FILE_BYTES / READ_BLOCK as u64) as usize;

    let before = ctx.iface.read()?;
    let wall_start = Instant::now();
    let mut samples: Vec<Duration> = Vec::with_capacity(n_reads);
    for _ in 0..n_reads {
        let t = Instant::now();
        f.read_exact(&mut buf)?;
        samples.push(t.elapsed());
    }
    let wall = wall_start.elapsed();
    let after = ctx.iface.read()?;
    let d = delta(before, after);
    Ok(WorkloadResult::ok(
        name, &samples, wall, d.rx_bytes, d.tx_bytes,
    ))
}

fn run_shell(cmd: &str) -> Result<()> {
    let status = Command::new("sh").arg("-c").arg(cmd).status()?;
    if !status.success() {
        anyhow::bail!("`{}` exited with {status}", cmd);
    }
    Ok(())
}

fn wait_for_mount(mount: &std::path::Path, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if mount.exists() && std::fs::metadata(mount).is_ok() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
    anyhow::bail!(
        "mount {} did not become ready within {:?}",
        mount.display(),
        timeout
    )
}
