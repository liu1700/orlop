use std::fs::{self, OpenOptions};
use std::io::Write;
use std::time::{Duration, Instant};

use anyhow::Result;

use crate::metrics::WorkloadResult;
use crate::netstats::delta;
use crate::workload::{RunCtx, Workload};

const TOTAL: u64 = 100 * 1024 * 1024;
const BLOCK: usize = 64 * 1024;

pub struct LargeEdit;

impl Workload for LargeEdit {
    fn name(&self) -> &'static str {
        "large-edit"
    }

    fn run(&self, ctx: &RunCtx<'_>) -> Result<Vec<WorkloadResult>> {
        ctx.fixtures.ensure_root()?;
        let path = ctx.fixtures.root().join("large-edit.bin");
        // Always start from a clean target — large-edit measures fresh writes.
        let _ = fs::remove_file(&path);

        let open_result = OpenOptions::new().write(true).create_new(true).open(&path);
        let mut f = match open_result {
            Ok(f) => f,
            Err(e) if e.raw_os_error() == Some(libc_erofs()) => {
                return Ok(vec![WorkloadResult::skipped(
                    self.name(),
                    "EROFS — write side not yet implemented (issue #78)",
                )]);
            }
            Err(e) => return Ok(vec![WorkloadResult::error(self.name(), e.to_string())]),
        };

        let block = vec![0xC3u8; BLOCK];
        let n_writes = (TOTAL / BLOCK as u64) as usize;

        let before = ctx.iface.read()?;
        let wall_start = Instant::now();
        let mut samples: Vec<Duration> = Vec::with_capacity(n_writes);
        for _ in 0..n_writes {
            let t = Instant::now();
            if let Err(e) = f.write_all(&block) {
                if e.raw_os_error() == Some(libc_erofs()) {
                    return Ok(vec![WorkloadResult::skipped(
                        self.name(),
                        "EROFS — write side not yet implemented (issue #78)",
                    )]);
                }
                return Ok(vec![WorkloadResult::error(self.name(), e.to_string())]);
            }
            samples.push(t.elapsed());
        }
        if let Err(e) = f.sync_all() {
            return Ok(vec![WorkloadResult::error(self.name(), e.to_string())]);
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

fn libc_erofs() -> i32 {
    30
}
