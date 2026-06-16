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
