use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::time::{Duration, Instant};

use anyhow::Result;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use crate::metrics::WorkloadResult;
use crate::netstats::delta;
use crate::workload::{RunCtx, Workload};
use crate::workloads::sequential_read::READ_BLOCK;

const N_READS: usize = 1000;
const SEED: u64 = 0xC0FF_EEBE_EFF0_0DC0;

pub struct RandomRead;

impl Workload for RandomRead {
    fn name(&self) -> &'static str {
        "random-read"
    }

    fn run(&self, ctx: &RunCtx<'_>) -> Result<Vec<WorkloadResult>> {
        ctx.fixtures.ensure_root()?;
        ctx.fixtures.ensure_seq_file()?;
        let path = ctx.fixtures.seq_file();

        let mut buf = vec![0u8; READ_BLOCK];
        let mut f = File::open(&path)?;

        let total = crate::fixtures::SEQ_FILE_BYTES;
        let max_off = total - READ_BLOCK as u64;
        // Fixed seed so offsets are deterministic across runs (for stability).
        let mut rng = StdRng::seed_from_u64(SEED);
        let offsets: Vec<u64> = (0..N_READS).map(|_| rng.gen_range(0..=max_off)).collect();

        let before = ctx.iface.read()?;
        let wall_start = Instant::now();
        let mut samples: Vec<Duration> = Vec::with_capacity(N_READS);
        for &off in &offsets {
            f.seek(SeekFrom::Start(off))?;
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
