use std::path::Path;

use anyhow::Result;

use crate::fixtures::Fixtures;
use crate::metrics::WorkloadResult;
use crate::netstats::IfaceStats;

pub struct RunCtx<'a> {
    pub mount: &'a Path,
    pub fixtures: &'a Fixtures,
    pub iface: &'a IfaceStats,
    pub mount_cmd: Option<&'a str>,
    pub unmount_cmd: Option<&'a str>,
    pub repeat: usize,
    pub parallelism: usize,
}

pub trait Workload {
    fn name(&self) -> &'static str;
    fn run(&self, ctx: &RunCtx<'_>) -> Result<Vec<WorkloadResult>>;
}
