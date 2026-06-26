use std::fs;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::Result;

use crate::metrics::WorkloadResult;
use crate::netstats::delta;
use crate::workload::{RunCtx, Workload};

pub struct StatStorm;

impl Workload for StatStorm {
    fn name(&self) -> &'static str {
        "stat-storm"
    }

    fn run(&self, ctx: &RunCtx<'_>) -> Result<Vec<WorkloadResult>> {
        ctx.fixtures.ensure_root()?;
        ctx.fixtures.ensure_stat_storm()?;
        let dir = ctx.fixtures.stat_storm_dir();

        let entries: Arc<Vec<_>> = Arc::new(
            fs::read_dir(&dir)?
                .filter_map(|e| e.ok().map(|e| e.path()))
                .collect(),
        );

        // Warmup: prime kernel + server caches so we measure steady-state stats.
        for p in entries.iter() {
            let _ = fs::metadata(p);
        }

        let parallelism = ctx.parallelism.max(1).min(entries.len().max(1));
        let before = ctx.iface.read()?;
        let wall_start = Instant::now();

        let samples = if parallelism == 1 {
            stat_loop(&entries, 0, entries.len())
        } else {
            let chunk = entries.len().div_ceil(parallelism);
            let mut handles = Vec::with_capacity(parallelism);
            for i in 0..parallelism {
                let start = i * chunk;
                if start >= entries.len() {
                    break;
                }
                let end = (start + chunk).min(entries.len());
                let entries = Arc::clone(&entries);
                handles.push(thread::spawn(move || stat_loop(&entries, start, end)));
            }
            let mut all = Vec::with_capacity(entries.len());
            for h in handles {
                all.extend(h.join().unwrap_or_default());
            }
            all
        };

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

fn stat_loop(entries: &[std::path::PathBuf], start: usize, end: usize) -> Vec<Duration> {
    let mut samples = Vec::with_capacity(end - start);
    for p in &entries[start..end] {
        let t = Instant::now();
        let _ = fs::metadata(p);
        samples.push(t.elapsed());
    }
    samples
}
