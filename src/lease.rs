//! Client-side lease lifecycle manager. See
//! `an internal design spec`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU8, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use parking_lot::Mutex;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};

use crate::backend::backend_errno;
use crate::backend::dataplane::client::DataClient;
use crate::backend::dataplane::codec::Frame;
use crate::backend::dataplane::messages::{LeaseMode, LeaseRevokeRequest};
use crate::backend::dataplane::protocol::{errno, Op};

const STATE_HEALTHY: u8 = 0;
const STATE_REVOKING: u8 = 1;
const STATE_LOST: u8 = 2;

const REFRESH_INTERVAL: Duration = Duration::from_millis(7_500);

pub struct LeaseManager {
    client: Arc<DataClient>,
    state: Mutex<State>,
    runtime: Arc<tokio::runtime::Runtime>,
}

struct State {
    by_path: HashMap<String, Arc<LeaseEntry>>,
}

pub struct LeaseEntry {
    path: String,
    pub lease_id: [u8; 16],
    pub mode: LeaseMode,
    pub expires_at_unix_ms: AtomicI64,
    pub state: AtomicU8,
    pub refcount: AtomicUsize,
    pub on_revoke: Mutex<Vec<Box<dyn Fn() + Send + Sync>>>,
    client: Arc<DataClient>,
}

pub struct LeaseHandle {
    entry: Arc<LeaseEntry>,
    manager: Arc<LeaseManager>,
}

impl Drop for LeaseHandle {
    fn drop(&mut self) {
        if self.entry.refcount.fetch_sub(1, Ordering::AcqRel) == 1 {
            let _ = self.entry.client.lease_release(&self.entry.lease_id, true);
            self.manager.state.lock().by_path.remove(&self.entry.path);
        }
    }
}

impl LeaseManager {
    pub fn new(client: Arc<DataClient>) -> Arc<Self> {
        let runtime = client.runtime();
        let (push_tx, push_rx) = unbounded_channel::<Frame>();
        client.set_push_handler(push_tx);

        let mgr = Arc::new(Self {
            client,
            state: Mutex::new(State {
                by_path: HashMap::new(),
            }),
            runtime,
        });

        // Spawn push-frame dispatcher.
        {
            let mgr = Arc::clone(&mgr);
            mgr.runtime.spawn(push_dispatch(Arc::clone(&mgr), push_rx));
        }
        // Spawn refresh task.
        {
            let mgr = Arc::clone(&mgr);
            mgr.runtime.spawn(refresh_task(Arc::clone(&mgr)));
        }
        mgr
    }

    /// Acquire (or refcount-reuse) an EXCLUSIVE_WRITE lease for `path`.
    /// Returns `Ok(Some(handle))` on success, `Ok(None)` if the server says
    /// the path is held by another agent (caller falls back to write-through).
    pub fn acquire_exclusive(self: &Arc<Self>, path: &str) -> Result<Option<Arc<LeaseHandle>>> {
        if let Some(entry) = self.state.lock().by_path.get(path).cloned() {
            entry.refcount.fetch_add(1, Ordering::AcqRel);
            return Ok(Some(Arc::new(LeaseHandle {
                entry,
                manager: Arc::clone(self),
            })));
        }
        // Send LEASE_GRANT.
        let resp = match self.client.lease_grant(path, LeaseMode::ExclusiveWrite) {
            Ok(r) => r,
            Err(e) => {
                if backend_errno(&e, 0) == errno::EBUSY {
                    return Ok(None);
                }
                return Err(e);
            }
        };
        if resp.lease_id.len() != 16 {
            anyhow::bail!("server returned lease_id of length {}", resp.lease_id.len());
        }
        let mut id = [0u8; 16];
        id.copy_from_slice(&resp.lease_id);

        let entry = Arc::new(LeaseEntry {
            path: path.to_string(),
            lease_id: id,
            mode: resp.mode_granted,
            expires_at_unix_ms: AtomicI64::new(resp.expires_at_unix_ms),
            state: AtomicU8::new(STATE_HEALTHY),
            refcount: AtomicUsize::new(1),
            on_revoke: Mutex::new(Vec::new()),
            client: Arc::clone(&self.client),
        });
        self.state
            .lock()
            .by_path
            .insert(path.to_string(), Arc::clone(&entry));
        Ok(Some(Arc::new(LeaseHandle {
            entry,
            manager: Arc::clone(self),
        })))
    }

    /// If we currently hold a lease for `path`, refcount-bump and return a
    /// handle. Does not contact the server. Used for graceful flush+release on
    /// rename without re-acquiring across the rename gap.
    pub fn acquire_exclusive_if_present(self: &Arc<Self>, path: &str) -> Option<Arc<LeaseHandle>> {
        let entry = self.state.lock().by_path.get(path).cloned()?;
        entry.refcount.fetch_add(1, Ordering::AcqRel);
        Some(Arc::new(LeaseHandle {
            entry,
            manager: Arc::clone(self),
        }))
    }

    fn handle_revoke(&self, lease_id: [u8; 16], _reason: String) {
        let entry = {
            let st = self.state.lock();
            st.by_path
                .values()
                .find(|e| e.lease_id == lease_id)
                .cloned()
        };
        let Some(entry) = entry else { return };
        entry.state.store(STATE_REVOKING, Ordering::Release);
        // Fire flush callbacks.
        let cbs = std::mem::take(&mut *entry.on_revoke.lock());
        for cb in cbs {
            cb();
        }
        // Send LEASE_RELEASE.
        let _ = self.client.lease_release(&entry.lease_id, true);
        entry.state.store(STATE_LOST, Ordering::Release);
        self.state.lock().by_path.remove(&entry.path);
    }
}

impl LeaseHandle {
    pub fn entry(&self) -> &Arc<LeaseEntry> {
        &self.entry
    }

    pub fn on_revoke(&self, cb: Box<dyn Fn() + Send + Sync>) {
        self.entry.on_revoke.lock().push(cb);
    }

    pub fn is_healthy(&self) -> bool {
        self.entry.state.load(Ordering::Acquire) == STATE_HEALTHY
    }
}

async fn push_dispatch(mgr: Arc<LeaseManager>, mut rx: UnboundedReceiver<Frame>) {
    while let Some(frame) = rx.recv().await {
        if frame.op != Op::LeaseRevoke {
            continue;
        }
        let Ok(req) = rmp_serde::from_slice::<LeaseRevokeRequest>(&frame.payload) else {
            continue;
        };
        if req.lease_id.len() != 16 {
            continue;
        }
        let mut id = [0u8; 16];
        id.copy_from_slice(&req.lease_id);
        let mgr2 = Arc::clone(&mgr);
        tokio::task::spawn_blocking(move || mgr2.handle_revoke(id, req.reason))
            .await
            .ok();
    }
}

async fn refresh_task(mgr: Arc<LeaseManager>) {
    loop {
        tokio::time::sleep(REFRESH_INTERVAL).await;
        let entries: Vec<Arc<LeaseEntry>> = mgr.state.lock().by_path.values().cloned().collect();
        let now_ms = unix_now_ms();
        for entry in entries {
            if entry.state.load(Ordering::Acquire) != STATE_HEALTHY {
                continue;
            }
            let expires = entry.expires_at_unix_ms.load(Ordering::Acquire);
            if (expires - now_ms) > (REFRESH_INTERVAL.as_millis() as i64) {
                continue;
            }
            // Refresh in a blocking call (DataClient::lease_refresh is sync).
            let client = Arc::clone(&entry.client);
            let lease_id = entry.lease_id;
            let entry_ref = Arc::clone(&entry);
            let mgr_ref = Arc::clone(&mgr);
            tokio::task::spawn_blocking(move || match client.lease_refresh(&lease_id) {
                Ok(r) => {
                    entry_ref
                        .expires_at_unix_ms
                        .store(r.expires_at_unix_ms, Ordering::Release);
                }
                Err(_) => {
                    entry_ref.state.store(STATE_REVOKING, Ordering::Release);
                    let cbs = std::mem::take(&mut *entry_ref.on_revoke.lock());
                    for cb in cbs {
                        cb();
                    }
                    entry_ref.state.store(STATE_LOST, Ordering::Release);
                    mgr_ref.state.lock().by_path.remove(&entry_ref.path);
                }
            })
            .await
            .ok();
        }
    }
}

fn unix_now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_state_constants() {
        assert_eq!(STATE_HEALTHY, 0);
        assert_eq!(STATE_REVOKING, 1);
        assert_eq!(STATE_LOST, 2);
    }

    #[test]
    fn refresh_interval_is_quarter_ttl() {
        assert_eq!(REFRESH_INTERVAL, Duration::from_millis(7_500));
    }
}
