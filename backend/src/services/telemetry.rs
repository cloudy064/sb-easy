//! Per-device telemetry relayed by agents.
//!
//! The panel can't reach a managed host's sing-box Clash API directly (the agent
//! connects over a userspace WireGuard), so each agent samples its own sing-box
//! (traffic rate, connections, recent log lines) and POSTs a snapshot. We keep
//! the latest snapshot per host in memory; the device's Monitor/Logs tabs read it.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HostTelemetry {
    /// rfc3339 timestamp of the last report.
    #[serde(default)]
    pub at: String,
    /// Current up/down rate (bytes/sec) the agent computed from total deltas.
    #[serde(default)]
    pub up: i64,
    #[serde(default)]
    pub down: i64,
    /// Cumulative totals reported by the running sing-box.
    #[serde(default)]
    pub up_total: i64,
    #[serde(default)]
    pub down_total: i64,
    #[serde(default)]
    pub conn_count: usize,
    /// Snapshot of active connections (Clash `/connections` "connections" array).
    #[serde(default)]
    pub connections: Value,
    /// Recent sing-box log lines.
    #[serde(default)]
    pub logs: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DiagnosticUpload {
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub app_version: String,
    #[serde(default)]
    pub core_version: String,
    #[serde(default)]
    pub device: Value,
    #[serde(default)]
    pub vpn: Value,
    #[serde(default)]
    pub network: Value,
    #[serde(default)]
    pub config: Value,
    #[serde(default)]
    pub runtime_log_count: usize,
    #[serde(default)]
    pub connection_count: usize,
    #[serde(default)]
    pub logs: Vec<String>,
}

impl DiagnosticUpload {
    pub fn clamp(&mut self) {
        self.reason = truncate(&self.reason, 80);
        self.app_version = truncate(&self.app_version, 80);
        self.core_version = truncate(&self.core_version, 120);
        if self.logs.len() > 1_500 {
            let start = self.logs.len() - 1_500;
            self.logs.drain(0..start);
        }
        self.logs.iter_mut().for_each(|line| *line = truncate(line, 4_000));
    }
}

fn truncate(value: &str, max_chars: usize) -> String {
    value.chars().take(max_chars).collect()
}

pub type TelemetryStore = Arc<RwLock<HashMap<String, HostTelemetry>>>;

pub fn new_store() -> TelemetryStore {
    Arc::new(RwLock::new(HashMap::new()))
}

/// Store the latest snapshot for a host (overwrites the previous one).
pub fn put(store: &TelemetryStore, host_id: &str, mut t: HostTelemetry) {
    // Cap the relayed log buffer so a chatty host can't grow memory unbounded.
    if t.logs.len() > 500 {
        let start = t.logs.len() - 500;
        t.logs.drain(0..start);
    }
    if let Ok(mut map) = store.write() {
        map.insert(host_id.to_string(), t);
    }
}

/// Latest snapshot for a host, if any.
pub fn get(store: &TelemetryStore, host_id: &str) -> Option<HostTelemetry> {
    store.read().ok().and_then(|m| m.get(host_id).cloned())
}

#[cfg(test)]
mod tests {
    use super::{truncate, DiagnosticUpload};

    #[test]
    fn diagnostic_upload_keeps_only_recent_bounded_logs() {
        let mut report = DiagnosticUpload {
            reason: "r".repeat(100),
            logs: (0..1_510)
                .map(|index| format!("line-{index}-{}", "x".repeat(4_100)))
                .collect(),
            ..DiagnosticUpload::default()
        };

        report.clamp();

        assert_eq!(report.reason.chars().count(), 80);
        assert_eq!(report.logs.len(), 1_500);
        assert!(report.logs[0].starts_with("line-10-"));
        assert!(report.logs.iter().all(|line| line.chars().count() <= 4_000));
    }

    #[test]
    fn truncate_is_unicode_safe() {
        assert_eq!(truncate("网络切换正常", 4), "网络切换");
    }
}
