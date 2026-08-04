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

/// How many refreshes may be in flight at once.
///
/// The refresh pass used to await one blocking round trip at a time, which made
/// its duration proportional to the number of held leases. An agent that opens
/// a large tree (a repository checkout, a test run) holds thousands of leases
/// acquired in a burst, so they all fall due in the same pass: at a few ms per
/// round trip a few thousand leases overrun the refresh window, the server
/// expires them, and its sweeper removes them. Writes then fail with EACCES —
/// including the implicit `/` mount-session lease, whose loss silently breaks
/// every subsequent write on the mount (issue #111).
///
/// The transport multiplexes by request id, so these pipeline on one connection
/// rather than queueing. 32 keeps a pass over thousands of leases well inside
/// the window without flooding the server with a burst it has to serialise.
const MAX_CONCURRENT_REFRESHES: usize = 32;

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

    /// Discard the connection-local cache entry and obtain a fresh server
    /// lease. Used only when a failed live-handoff successor may have
    /// superseded this connection's lease id.
    pub fn force_reacquire_exclusive(
        self: &Arc<Self>,
        path: &str,
    ) -> Result<Option<Arc<LeaseHandle>>> {
        self.state.lock().by_path.remove(path);
        self.acquire_exclusive(path)
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

/// Decide which leases a refresh pass renews, and in what order.
///
/// Takes `(state, expires_at_unix_ms)` per lease and returns indices, so the
/// scheduling rule is testable without standing up a `DataClient`.
///
/// Ordering is the half of the fix that matters even when a pass does finish in
/// time: `by_path` is a `HashMap`, so an unordered walk can leave the lease
/// closest to expiry until last. The `/` mount session is acquired before any
/// file lease and therefore expires before them, which makes it exactly the
/// entry an arbitrary order is most likely to strand.
fn refresh_order(leases: &[(u8, i64)], now_ms: i64) -> Vec<usize> {
    let window = REFRESH_INTERVAL.as_millis() as i64;
    let mut due: Vec<usize> = (0..leases.len())
        .filter(|&i| leases[i].0 == STATE_HEALTHY)
        .filter(|&i| (leases[i].1 - now_ms) <= window)
        .collect();
    due.sort_by_key(|&i| leases[i].1);
    due
}

/// Pick the leases a refresh pass must renew, most urgent first.
fn due_for_refresh(entries: &[Arc<LeaseEntry>], now_ms: i64) -> Vec<Arc<LeaseEntry>> {
    let snapshot: Vec<(u8, i64)> = entries
        .iter()
        .map(|e| {
            (
                e.state.load(Ordering::Acquire),
                e.expires_at_unix_ms.load(Ordering::Acquire),
            )
        })
        .collect();
    refresh_order(&snapshot, now_ms)
        .into_iter()
        .map(|i| Arc::clone(&entries[i]))
        .collect()
}

/// Renew one lease, tearing it down locally if the server refuses.
fn refresh_one(mgr: &Arc<LeaseManager>, entry: &Arc<LeaseEntry>) {
    match entry.client.lease_refresh(&entry.lease_id) {
        Ok(r) => {
            entry
                .expires_at_unix_ms
                .store(r.expires_at_unix_ms, Ordering::Release);
        }
        Err(_) => {
            entry.state.store(STATE_REVOKING, Ordering::Release);
            let cbs = std::mem::take(&mut *entry.on_revoke.lock());
            for cb in cbs {
                cb();
            }
            entry.state.store(STATE_LOST, Ordering::Release);
            mgr.state.lock().by_path.remove(&entry.path);
        }
    }
}

async fn refresh_task(mgr: Arc<LeaseManager>) {
    loop {
        tokio::time::sleep(REFRESH_INTERVAL).await;
        let entries: Vec<Arc<LeaseEntry>> = mgr.state.lock().by_path.values().cloned().collect();
        let due = due_for_refresh(&entries, unix_now_ms());

        // Bounded fan-out: `DataClient::lease_refresh` is sync, so each renewal
        // occupies a blocking thread. Awaiting them one at a time is what let a
        // large lease set outlive the window (#111).
        let mut inflight = tokio::task::JoinSet::new();
        for entry in due {
            if inflight.len() >= MAX_CONCURRENT_REFRESHES {
                inflight.join_next().await;
            }
            let mgr_ref = Arc::clone(&mgr);
            inflight.spawn_blocking(move || refresh_one(&mgr_ref, &entry));
        }
        while inflight.join_next().await.is_some() {}
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

    const TTL_MS: i64 = 30_000; // orlop-server's lease TTL (config.go)
    const NOW: i64 = 1_785_000_000_000;

    /// The whole point of ordering: whichever lease dies first is renewed
    /// first, no matter where it sits in the map's iteration order.
    #[test]
    fn refresh_order_is_most_urgent_first() {
        let leases = [
            (STATE_HEALTHY, NOW + 5_000),
            (STATE_HEALTHY, NOW + 1_000),
            (STATE_HEALTHY, NOW + 3_000),
        ];
        assert_eq!(refresh_order(&leases, NOW), vec![1, 2, 0]);
    }

    /// #111: the `/` mount session is acquired before any file lease, so it
    /// expires before them. Under the old unordered walk it could be renewed
    /// after thousands of file leases and miss its deadline; losing it makes
    /// every later write on the mount fail with EACCES. It must come first.
    #[test]
    fn mount_session_lease_is_refreshed_before_the_file_leases_it_predates() {
        // `by_path` is a HashMap, so the mount session can surface anywhere in
        // the walk. Put it LAST — the position where only ordering saves it,
        // and the one an unsorted pass strands behind 3,000 file leases.
        let mut leases: Vec<(u8, i64)> =
            (0..3_000).map(|i| (STATE_HEALTHY, NOW + 500 + i)).collect();
        let mount_session = leases.len();
        leases.push((STATE_HEALTHY, NOW + 100));

        let order = refresh_order(&leases, NOW);
        assert_eq!(order.len(), 3_001, "every due lease must be scheduled");
        assert_eq!(
            order[0], mount_session,
            "the mount session expires soonest and must be renewed first, \
             wherever it fell in the map walk"
        );
    }

    /// A lease with more than one window of life left is left alone; renewing
    /// it early would multiply traffic for no gain.
    #[test]
    fn refresh_order_skips_leases_that_are_not_due_yet() {
        let leases = [
            (STATE_HEALTHY, NOW + TTL_MS), // fresh
            (STATE_HEALTHY, NOW + 2_000),  // inside the window
        ];
        assert_eq!(refresh_order(&leases, NOW), vec![1]);
    }

    /// Boundary: the loop refreshes at `expires - now <= REFRESH_INTERVAL`, so
    /// a lease sitting exactly one interval out is due. Off by one here and a
    /// lease is skipped for a whole pass.
    #[test]
    fn refresh_order_includes_a_lease_exactly_one_interval_out() {
        let window = REFRESH_INTERVAL.as_millis() as i64;
        let leases = [
            (STATE_HEALTHY, NOW + window),
            (STATE_HEALTHY, NOW + window + 1),
        ];
        assert_eq!(refresh_order(&leases, NOW), vec![0]);
    }

    /// An already-expired lease is still scheduled: the server may have been
    /// unreachable, and the refresh is what discovers that and tears the entry
    /// down. Dropping it here would leave a dead lease in the map forever.
    #[test]
    fn refresh_order_still_schedules_an_already_expired_lease() {
        let leases = [(STATE_HEALTHY, NOW - 10_000)];
        assert_eq!(refresh_order(&leases, NOW), vec![0]);
    }

    /// Leases already being revoked or lost are not renewed.
    #[test]
    fn refresh_order_ignores_non_healthy_leases() {
        let leases = [
            (STATE_REVOKING, NOW + 100),
            (STATE_LOST, NOW + 200),
            (STATE_HEALTHY, NOW + 300),
        ];
        assert_eq!(refresh_order(&leases, NOW), vec![2]);
    }

    /// The budget that keeps a pass inside the refresh window. With the old
    /// serial loop, a burst of file leases at a few ms per round trip took
    /// longer than the window and the server expired them mid-pass.
    #[test]
    fn concurrency_bound_keeps_a_large_pass_inside_the_window() {
        let window_ms = REFRESH_INTERVAL.as_millis();
        let leases = 3_086u128; // the count observed in the #111 incident
        let per_refresh_ms = 5u128; // a conservative loaded round trip

        let serial_ms = leases * per_refresh_ms;
        assert!(
            serial_ms > window_ms,
            "the serial pass must be the thing that overran: {serial_ms}ms vs {window_ms}ms"
        );

        let bounded_ms = leases.div_ceil(MAX_CONCURRENT_REFRESHES as u128) * per_refresh_ms;
        assert!(
            bounded_ms < window_ms,
            "a bounded pass must fit the window: {bounded_ms}ms vs {window_ms}ms"
        );
    }
}
