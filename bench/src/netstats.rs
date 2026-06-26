use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};

#[derive(Debug, Clone, Copy)]
pub struct IfaceCounters {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

pub struct IfaceStats {
    iface: String,
}

impl IfaceStats {
    pub fn new(iface: impl Into<String>) -> Self {
        Self {
            iface: iface.into(),
        }
    }

    pub fn read(&self) -> Result<IfaceCounters> {
        let base = PathBuf::from(format!("/sys/class/net/{}/statistics", self.iface));
        let rx = read_u64(&base.join("rx_bytes"))?;
        let tx = read_u64(&base.join("tx_bytes"))?;
        Ok(IfaceCounters {
            rx_bytes: rx,
            tx_bytes: tx,
        })
    }
}

fn read_u64(path: &std::path::Path) -> Result<u64> {
    let s = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    s.trim()
        .parse::<u64>()
        .with_context(|| format!("parse u64 from {}", path.display()))
}

pub fn delta(before: IfaceCounters, after: IfaceCounters) -> IfaceCounters {
    IfaceCounters {
        rx_bytes: after.rx_bytes.saturating_sub(before.rx_bytes),
        tx_bytes: after.tx_bytes.saturating_sub(before.tx_bytes),
    }
}
