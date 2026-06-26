pub mod cold_warm_cycle;
pub mod large_edit;
pub mod ls_large_dir;
pub mod random_read;
pub mod sequential_read;
pub mod small_edit;
pub mod stat_storm;

use crate::workload::Workload;

pub fn all() -> Vec<Box<dyn Workload>> {
    vec![
        Box::new(stat_storm::StatStorm),
        Box::new(ls_large_dir::LsLargeDir),
        Box::new(sequential_read::SequentialRead),
        Box::new(random_read::RandomRead),
        Box::new(small_edit::SmallEdit),
        Box::new(large_edit::LargeEdit),
        Box::new(cold_warm_cycle::ColdWarmCycle),
    ]
}

pub fn lookup(name: &str) -> Option<Box<dyn Workload>> {
    all().into_iter().find(|w| w.name() == name)
}
