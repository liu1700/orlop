use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::time::{Duration, Instant};

use anyhow::Result;

use crate::metrics::WorkloadResult;
use crate::netstats::delta;
use crate::workload::{RunCtx, Workload};

pub const READ_BLOCK: usize = 64 * 1024;

pub struct SequentialRead;

impl Workload for SequentialRead {
    fn name(&self) -> &'static str {
        "sequential-read"
    }

    fn run(&self, ctx: &RunCtx<'_>) -> Result<Vec<WorkloadResult>> {
        ctx.fixtures.ensure_root()?;
        ctx.fixtures.ensure_seq_file()?;
        let path = ctx.fixtures.seq_file();

        let mut buf = vec![0u8; READ_BLOCK];
        let mut f = File::open(&path)?;
        f.seek(SeekFrom::Start(0))?;

        let total = crate::fixtures::SEQ_FILE_BYTES;
        let n_reads = (total / READ_BLOCK as u64) as usize;

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

        Ok(vec![WorkloadResult::ok(
            self.name(),
            &samples,
            wall,
            d.rx_bytes,
            d.tx_bytes,
        )])
    }
}
