use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use chrono::Utc;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::backend::dataplane::messages::RecoveryHint;
use crate::write_handle::FlushStats;

/// Audit event names emitted by the client. Centralised so a typo at a call
/// site is a compile error and `--event` filters always match the strings the
/// client actually writes. The server emits its own additional names; they
/// stay raw strings on the deserialise side.
pub mod event {
    pub const LOOKUP: &str = "lookup";
    pub const LOOKUP_SYNTHETIC: &str = "lookup_synthetic";
    pub const OPENDIR: &str = "opendir";
    pub const READDIR_ENTRY: &str = "readdir_entry";
    pub const READDIRPLUS_ENTRY: &str = "readdirplus_entry";
    pub const READDIR_ENTRY_SYNTHETIC: &str = "readdir_entry_synthetic";
    pub const OPEN: &str = "open";
    pub const OPEN_SYNTHETIC: &str = "open_synthetic";
    pub const READ: &str = "read";
    pub const READ_SYNTHETIC: &str = "read_synthetic";
    pub const READLINK_SYNTHETIC: &str = "readlink_synthetic";
    pub const CREATE: &str = "create";
    pub const FLUSH: &str = "flush";
    pub const UNLINK: &str = "unlink";
    pub const RMDIR: &str = "rmdir";
    pub const MKDIR: &str = "mkdir";
    pub const RENAME: &str = "rename";
    pub const SETATTR: &str = "setattr";
    pub const SYMLINK: &str = "symlink";
    pub const LEASE_DENIED: &str = "lease_denied";
    pub const README_REAL_OVERRIDE: &str = "readme_real_override";
    pub const ENROLLMENT: &str = "enrollment";
}

pub struct AuditLog {
    file: Arc<Mutex<File>>,
}

impl Clone for AuditLog {
    fn clone(&self) -> Self {
        Self {
            file: Arc::clone(&self.file),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditIdentity {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub session_id: Option<String>,
    pub command: Option<String>,
}

impl AuditIdentity {
    pub fn with_session(mut self, id: Option<String>) -> Self {
        self.session_id = id;
        self
    }
}

/// Recovery hint, flattened into the top-level JSON object so
/// `orlop audit tail | jq '.recovery_suggested_action'` works without diving
/// into a nested object.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct FlatRecovery {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    recovery_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    recovery_suggested_action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    recovery_your_version: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    recovery_current_version: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    recovery_last_writer_agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    recovery_last_writer_session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    recovery_last_writer_at_unix_ms: Option<i64>,
}

impl From<&RecoveryHint> for FlatRecovery {
    fn from(h: &RecoveryHint) -> Self {
        let last_writer = h.last_writer.as_ref();
        Self {
            recovery_kind: Some(h.kind.as_wire_str().to_string()),
            recovery_suggested_action: Some(h.suggested_action.clone()),
            recovery_your_version: h.your_version,
            recovery_current_version: h.current_version,
            recovery_last_writer_agent_id: last_writer.and_then(|w| w.agent_id.clone()),
            recovery_last_writer_session_id: last_writer.and_then(|w| w.session_id.clone()),
            recovery_last_writer_at_unix_ms: last_writer.map(|w| w.at_unix_ms),
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AuditEvent {
    #[serde(default)]
    pub ts: String,
    pub event: String,
    pub path: String,
    pub size: Option<u64>,
    pub offset: Option<i64>,

    #[serde(flatten)]
    pub identity: AuditIdentity,

    pub allowed: bool,

    // Write-surface extensions
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub to_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub mode: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub setattr_fields: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub chunks_new: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub chunks_reused: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cas_retries: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub version_new: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub lease_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reason: Option<String>,

    // Server-only fields (chunk-store GC sweep summary). The client never
    // produces these; `serde(default)` lets `orlop audit tail` parse older or
    // server-emitted lines without losing them.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub bytes_freed: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub dry_run: Option<bool>,

    #[serde(flatten)]
    recovery: FlatRecovery,
}

impl AuditEvent {
    /// Convenience constructor — only the core fields. Builders below add
    /// write-surface metadata when needed.
    pub fn simple(event: &str, path: &str, allowed: bool, identity: AuditIdentity) -> Self {
        Self {
            event: event.to_string(),
            path: path.to_string(),
            allowed,
            identity,
            ..Self::default()
        }
    }

    pub fn with_size(mut self, size: u64) -> Self {
        self.size = Some(size);
        self
    }

    pub fn with_offset(mut self, offset: i64) -> Self {
        self.offset = Some(offset);
        self
    }

    pub fn with_to_path(mut self, p: &str) -> Self {
        self.to_path = Some(p.to_string());
        self
    }

    pub fn with_mode(mut self, m: u32) -> Self {
        self.mode = Some(m);
        self
    }

    pub fn with_setattr_fields(mut self, f: u32) -> Self {
        self.setattr_fields = Some(f);
        self
    }

    pub fn with_flush_stats(mut self, stats: &FlushStats) -> Self {
        self.size = Some(stats.bytes);
        self.chunks_new = Some(stats.chunks_new);
        self.chunks_reused = Some(stats.chunks_reused);
        self.cas_retries = Some(stats.cas_retries);
        self.version_new = Some(stats.version_new);
        if let Some(hint) = stats.recovery.as_ref() {
            self.recovery = FlatRecovery::from(hint);
        }
        self
    }

    pub fn with_lease_id(mut self, id: &[u8; 16]) -> Self {
        self.lease_id = Some(crate::backend::dataplane::cache::hex_encode(id));
        self
    }

    pub fn with_reason(mut self, reason: &str) -> Self {
        self.reason = Some(reason.to_string());
        self
    }

    pub fn with_recovery(mut self, hint: &RecoveryHint) -> Self {
        self.recovery = FlatRecovery::from(hint);
        self
    }
}

impl AuditLog {
    pub fn new(path: PathBuf) -> anyhow::Result<Self> {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            file: Arc::new(Mutex::new(file)),
        })
    }

    pub fn record(&self, mut event: AuditEvent) {
        event.ts = Utc::now().to_rfc3339();
        if let Ok(line) = serde_json::to_string(&event) {
            let mut file = self.file.lock();
            let _ = writeln!(file, "{line}");
        }
    }

    pub fn flush(&self) -> anyhow::Result<()> {
        self.file.lock().flush()?;
        Ok(())
    }
}

/// Filter spec for `audit::tail`. All fields AND together — an event must
/// match every set filter. Empty `events` means all event types pass.
#[derive(Default, Clone, Copy)]
pub struct TailFilter<'a> {
    pub events: &'a [String],
    pub lease_id: Option<&'a str>,
}

#[derive(Clone)]
struct CompiledFilter {
    events: Vec<String>,
    lease_id: Option<String>,
}

impl CompiledFilter {
    fn from(spec: TailFilter<'_>) -> anyhow::Result<Self> {
        Ok(Self {
            events: spec.events.to_vec(),
            lease_id: spec.lease_id.map(str::to_string),
        })
    }

    fn is_pass_through(&self) -> bool {
        self.events.is_empty() && self.lease_id.is_none()
    }
}

pub fn tail(
    path: &Path,
    filter: TailFilter<'_>,
    limit: Option<usize>,
    follow: bool,
) -> anyhow::Result<()> {
    let compiled = CompiledFilter::from(filter)?;
    let mut file = OpenOptions::new()
        .read(true)
        .create(true)
        .append(true)
        .open(path)?;

    if follow && limit.is_none() {
        file.seek(SeekFrom::End(0))?;
    } else {
        print_matching_lines(&file, &compiled, limit)?;
        if !follow {
            return Ok(());
        }
        file.seek(SeekFrom::End(0))?;
    }

    let mut reader = BufReader::new(file);
    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line)?;
        if read == 0 {
            sleep(Duration::from_millis(250));
            continue;
        }
        if event_matches(&line, &compiled) {
            print!("{line}");
            let _ = std::io::stdout().flush();
        }
    }
}

fn print_matching_lines(
    file: &File,
    filter: &CompiledFilter,
    limit: Option<usize>,
) -> anyhow::Result<()> {
    let reader = BufReader::new(file);
    let mut lines = Vec::new();
    for line in reader.lines() {
        let line = line?;
        if event_matches(&line, filter) {
            lines.push(line);
        }
    }

    let start = limit
        .map(|limit| lines.len().saturating_sub(limit))
        .unwrap_or(0);
    for line in &lines[start..] {
        println!("{line}");
    }
    Ok(())
}

fn event_matches(line: &str, filter: &CompiledFilter) -> bool {
    if filter.is_pass_through() {
        return true;
    }
    let Ok(event) = serde_json::from_str::<AuditEvent>(line) else {
        return false;
    };
    if !filter.events.is_empty() && !filter.events.iter().any(|e| e == &event.event) {
        return false;
    }
    if let Some(lease_id) = &filter.lease_id {
        if event.lease_id.as_deref() != Some(lease_id.as_str()) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(event: &str, lease_id: Option<&str>) -> String {
        let mut v = serde_json::json!({
            "ts": "2026-05-02T00:00:00Z",
            "event": event,
            "path": "/x",
            "size": null,
            "offset": null,
            "command": null,
            "allowed": true,
        });
        if let Some(id) = lease_id {
            v["lease_id"] = serde_json::Value::String(id.to_string());
        }
        v.to_string()
    }

    fn compile(events: &[&str], lease_id: Option<&str>) -> CompiledFilter {
        let owned: Vec<String> = events.iter().map(|s| s.to_string()).collect();
        CompiledFilter::from(TailFilter {
            events: &owned,
            lease_id,
        })
        .expect("filter compiles")
    }

    #[test]
    fn empty_filter_is_pass_through() {
        let filter = compile(&[], None);
        assert!(event_matches(&line("manifest_get", None), &filter));
        assert!(event_matches(&line("lease_grant", Some("abc")), &filter));
    }

    #[test]
    fn event_filter_matches_any_listed() {
        let filter = compile(&["manifest_put", "lease_revoke"], None);
        assert!(event_matches(&line("manifest_put", None), &filter));
        assert!(event_matches(&line("lease_revoke", None), &filter));
        assert!(!event_matches(&line("chunk_get", None), &filter));
    }

    #[test]
    fn lease_id_filter_requires_match() {
        let filter = compile(&[], Some("deadbeef"));
        assert!(event_matches(
            &line("lease_grant", Some("deadbeef")),
            &filter
        ));
        assert!(!event_matches(
            &line("lease_grant", Some("cafebabe")),
            &filter
        ));
        // Events without lease_id never match a lease_id filter.
        assert!(!event_matches(&line("manifest_get", None), &filter));
    }

    #[test]
    fn event_and_lease_id_combine_with_and() {
        let filter = compile(&["lease_revoke"], Some("deadbeef"));
        assert!(event_matches(
            &line("lease_revoke", Some("deadbeef")),
            &filter
        ));
        // Right lease, wrong event → reject.
        assert!(!event_matches(
            &line("lease_grant", Some("deadbeef")),
            &filter
        ));
        // Right event, wrong lease → reject.
        assert!(!event_matches(
            &line("lease_revoke", Some("cafebabe")),
            &filter
        ));
    }

    use crate::backend::dataplane::messages::{LastWriter, RecoveryHint, RecoveryKind};

    fn read_one_event(log_path: &Path) -> serde_json::Value {
        let raw = std::fs::read_to_string(log_path).expect("audit log readable");
        let line = raw.lines().next().expect("at least one audit line");
        serde_json::from_str(line).expect("parses as JSON")
    }

    #[test]
    fn audit_record_with_recovery_hint_emits_top_level_fields() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("audit.log");
        let log = AuditLog::new(log_path.clone()).unwrap();

        let hint = RecoveryHint {
            kind: RecoveryKind::CasConflict,
            your_version: Some(5),
            current_version: Some(7),
            last_writer: Some(LastWriter {
                agent_id: Some("agent_a".into()),
                session_id: None,
                at_unix_ms: 1_700_000_000_123,
            }),
            suggested_action: "re-put with expected=7".into(),
        };
        let event = AuditEvent::simple("manifest_put", "/x", true, AuditIdentity::default())
            .with_recovery(&hint);
        log.record(event);
        log.flush().unwrap();

        let evt = read_one_event(&log_path);
        assert_eq!(evt["recovery_kind"], "cas_conflict");
        assert_eq!(evt["recovery_suggested_action"], "re-put with expected=7");
        assert_eq!(evt["recovery_current_version"], 7);
        assert_eq!(evt["recovery_your_version"], 5);
        assert_eq!(evt["recovery_last_writer_agent_id"], "agent_a");
        assert_eq!(
            evt["recovery_last_writer_at_unix_ms"],
            1_700_000_000_123_i64
        );
        // session_id is None in v0 → field omitted.
        assert!(evt.get("recovery_last_writer_session_id").is_none());
    }

    #[test]
    fn flush_stats_recovery_propagates_to_audit_via_with_flush_stats() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("audit.log");
        let log = AuditLog::new(log_path.clone()).unwrap();

        let stats = crate::write_handle::FlushStats {
            bytes: 100,
            chunks_new: 1,
            chunks_reused: 0,
            cas_retries: 1,
            version_new: 8,
            recovery: Some(RecoveryHint {
                kind: RecoveryKind::CasConflict,
                your_version: Some(7),
                current_version: Some(8),
                last_writer: None,
                suggested_action: "use 8".into(),
            }),
        };
        let event = AuditEvent::simple("manifest_put", "/x", true, AuditIdentity::default())
            .with_flush_stats(&stats);
        log.record(event);
        log.flush().unwrap();

        let evt = read_one_event(&log_path);
        assert_eq!(evt["cas_retries"], 1);
        assert_eq!(evt["version_new"], 8);
        assert_eq!(evt["recovery_kind"], "cas_conflict");
        assert_eq!(evt["recovery_suggested_action"], "use 8");
        assert_eq!(evt["recovery_current_version"], 8);
    }

    #[test]
    fn audit_record_emits_session_id_when_set() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("audit.log");
        let log = AuditLog::new(log_path.clone()).unwrap();

        let identity = AuditIdentity {
            agent_pid: Some(42),
            session_id: Some("s_test".into()),
            ..AuditIdentity::default()
        };
        log.record(AuditEvent::simple("manifest_put", "/x", true, identity));
        log.flush().unwrap();
        let evt = read_one_event(&log_path);
        assert_eq!(evt["session_id"], "s_test");
    }

    #[test]
    fn audit_record_omits_session_id_when_unset() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("audit.log");
        let log = AuditLog::new(log_path.clone()).unwrap();

        log.record(AuditEvent::simple(
            "manifest_get",
            "/x",
            true,
            AuditIdentity::default(),
        ));
        log.flush().unwrap();
        let evt = read_one_event(&log_path);
        assert!(
            evt.get("session_id").is_none(),
            "session_id key must be omitted when AuditIdentity has none"
        );
    }

    #[test]
    fn audit_record_without_recovery_omits_recovery_fields() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("audit.log");
        let log = AuditLog::new(log_path.clone()).unwrap();

        let event = AuditEvent::simple("manifest_get", "/x", true, AuditIdentity::default());
        log.record(event);
        log.flush().unwrap();

        let evt = read_one_event(&log_path);
        for key in [
            "recovery_kind",
            "recovery_suggested_action",
            "recovery_current_version",
            "recovery_your_version",
            "recovery_last_writer_agent_id",
            "recovery_last_writer_at_unix_ms",
            "recovery_last_writer_session_id",
        ] {
            assert!(
                evt.get(key).is_none(),
                "key {key} must be omitted when no recovery hint is attached"
            );
        }
    }
}
