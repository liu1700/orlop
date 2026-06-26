use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::time::{Duration, Instant};

use anyhow::Result;

use crate::metrics::WorkloadResult;
use crate::netstats::delta;
use crate::workload::{RunCtx, Workload};

const EDIT_BYTES: usize = 1024;
// Stride iterations across distinct 4 MiB-aligned offsets so individual
// writes don't coalesce in cache and we measure independent edit costs.
const STRIDE_BYTES: u64 = 4 * 1024 * 1024;
const FIRST_OFFSET: u64 = 4 * 1024 * 1024;

pub struct SmallEdit;

impl Workload for SmallEdit {
    fn name(&self) -> &'static str {
        "small-edit"
    }

    fn run(&self, ctx: &RunCtx<'_>) -> Result<Vec<WorkloadResult>> {
        ctx.fixtures.ensure_root()?;
        ctx.fixtures.ensure_seq_file()?;
        let path = ctx.fixtures.seq_file();

        let open_result = OpenOptions::new().read(true).write(true).open(&path);
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

        let payload: Vec<u8> = (0..EDIT_BYTES).map(|i| (i & 0xff) as u8).collect();
        let iters = ctx.repeat.max(10);
        let max_offset = crate::fixtures::SEQ_FILE_BYTES - EDIT_BYTES as u64;

        let before = ctx.iface.read()?;
        let wall_start = Instant::now();
        let mut samples: Vec<Duration> = Vec::with_capacity(iters);

        for i in 0..iters {
            let off = (FIRST_OFFSET + (i as u64) * STRIDE_BYTES).min(max_offset);
            let t = Instant::now();
            if let Err(e) = f.seek(SeekFrom::Start(off)) {
                return Ok(vec![WorkloadResult::error(self.name(), e.to_string())]);
            }
            if let Err(e) = f.write_all(&payload) {
                if e.raw_os_error() == Some(libc_erofs()) {
                    return Ok(vec![WorkloadResult::skipped(
                        self.name(),
                        "EROFS — write side not yet implemented (issue #78)",
                    )]);
                }
                return Ok(vec![WorkloadResult::error(self.name(), e.to_string())]);
            }
            if let Err(e) = f.sync_all() {
                return Ok(vec![WorkloadResult::error(self.name(), e.to_string())]);
            }
            samples.push(t.elapsed());
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
    // EROFS is 30 on Linux; the constant is portable through libc but we avoid
    // adding the libc dep to bench. If we ever run this on non-Linux we'll
    // route through libc::EROFS.
    30
}
