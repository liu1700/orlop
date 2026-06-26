use std::time::Duration;

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Ok,
    Skipped,
    Error,
}

#[derive(Debug, Serialize)]
pub struct WorkloadResult {
    pub name: String,
    pub status: Status,
    pub p50_ms: f64,
    pub p99_ms: f64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub ops: u64,
    pub duration_s: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl WorkloadResult {
    pub fn ok(
        name: impl Into<String>,
        samples: &[Duration],
        wall: Duration,
        bytes_in: u64,
        bytes_out: u64,
    ) -> Self {
        let p50 = percentile_ms(samples, 50.0);
        let p99 = percentile_ms(samples, 99.0);
        Self {
            name: name.into(),
            status: Status::Ok,
            p50_ms: p50,
            p99_ms: p99,
            bytes_in,
            bytes_out,
            ops: samples.len() as u64,
            duration_s: wall.as_secs_f64(),
            skip_reason: None,
            error: None,
        }
    }

    pub fn skipped(name: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: Status::Skipped,
            p50_ms: 0.0,
            p99_ms: 0.0,
            bytes_in: 0,
            bytes_out: 0,
            ops: 0,
            duration_s: 0.0,
            skip_reason: Some(reason.into()),
            error: None,
        }
    }

    pub fn error(name: impl Into<String>, err: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: Status::Error,
            p50_ms: 0.0,
            p99_ms: 0.0,
            bytes_in: 0,
            bytes_out: 0,
            ops: 0,
            duration_s: 0.0,
            skip_reason: None,
            error: Some(err.into()),
        }
    }
}

fn percentile_ms(samples: &[Duration], p: f64) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let mut sorted: Vec<Duration> = samples.to_vec();
    sorted.sort_unstable();
    // Linear interpolation between adjacent ranks (matches numpy default).
    let rank = (p / 100.0) * (sorted.len() as f64 - 1.0);
    let lo = rank.floor() as usize;
    let hi = (lo + 1).min(sorted.len() - 1);
    let frac = rank - lo as f64;
    let lo_ms = sorted[lo].as_secs_f64() * 1000.0;
    let hi_ms = sorted[hi].as_secs_f64() * 1000.0;
    lo_ms + (hi_ms - lo_ms) * frac
}

#[derive(Debug, Serialize)]
pub struct SuiteOutput {
    pub git_sha: String,
    pub git_dirty: bool,
    pub timestamp: String,
    pub kernel: String,
    pub label: Option<String>,
    pub data_plane: Option<String>,
    pub mount: String,
    pub iface: String,
    pub workloads: Vec<WorkloadResult>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentiles_basic() {
        let samples: Vec<Duration> = (1..=100).map(Duration::from_millis).collect();
        assert!((percentile_ms(&samples, 50.0) - 50.0).abs() < 1.0);
        assert!((percentile_ms(&samples, 99.0) - 99.0).abs() < 1.0);
    }

    #[test]
    fn percentiles_empty() {
        assert_eq!(percentile_ms(&[], 50.0), 0.0);
    }

    #[test]
    fn percentiles_single() {
        let s = [Duration::from_millis(7)];
        assert_eq!(percentile_ms(&s, 50.0), 7.0);
        assert_eq!(percentile_ms(&s, 99.0), 7.0);
    }
}
