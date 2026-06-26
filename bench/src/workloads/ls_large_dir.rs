use std::fs;
use std::time::{Duration, Instant};

use anyhow::Result;

use crate::metrics::WorkloadResult;
use crate::netstats::delta;
use crate::workload::{RunCtx, Workload};

pub struct LsLargeDir;

impl Workload for LsLargeDir {
    fn name(&self) -> &'static str {
        "ls-large-dir"
    }

    fn run(&self, ctx: &RunCtx<'_>) -> Result<Vec<WorkloadResult>> {
        ctx.fixtures.ensure_root()?;
        ctx.fixtures.ensure_ls_large()?;
        let dir = ctx.fixtures.ls_large_dir();

        // Warmup readdir once so subsequent runs measure steady-state.
        let _ = fs::read_dir(&dir)?.count();

        let iters = ctx.repeat.max(10);
        let before = ctx.iface.read()?;
        let wall_start = Instant::now();
        let mut samples: Vec<Duration> = Vec::with_capacity(iters);
        for _ in 0..iters {
            let t = Instant::now();
            let n = fs::read_dir(&dir)?.count();
            samples.push(t.elapsed());
            // Sanity: directory should have the expected entry count.
            if n < crate::fixtures::LS_LARGE_DIR_FILES {
                anyhow::bail!(
                    "ls-large dir had {n} entries; expected ≥ {}",
                    crate::fixtures::LS_LARGE_DIR_FILES
                );
            }
        }
        let wall = wall_start.elapsed();
        let after = ctx.iface.read()?;
        let d = delta(before, after);

        Ok(vec![WorkloadResult::ok(
            self.name(),
            &samples,
            wall,
            d.rx_bytes,
            d.tx_bytes,
        )])
    }
}
