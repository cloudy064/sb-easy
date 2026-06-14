//! Managed host model (a machine running the agent / sing-box / WG member).
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Host {
    pub id: String,
    pub name: String,
    /// Per-host bearer token the agent presents. Never serialize to clients by
    /// default — exposed only via the dedicated "reveal token" endpoint.
    #[serde(skip_serializing)]
    pub agent_token: String,
    /// JSON: runs_singbox / is_wg_member / is_wg_hub / is_self.
    pub capabilities: String,
    pub profile_id: Option<String>,
    pub wg_address: Option<String>,
    pub wg_public_key: Option<String>,
    pub wg_endpoint: Option<String>,
    /// Clash API base URL reachable over the WG intranet, e.g. http://10.59.32.10:9090
    pub clash_api: Option<String>,
    #[serde(skip_serializing)]
    pub clash_secret: String,
    pub last_seen: Option<String>,
    /// JSON blob last reported by the agent: version / running / etag.
    pub singbox_state: Option<String>,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

impl Host {
    /// Parse the capabilities JSON, tolerating malformed/empty values.
    pub fn caps(&self) -> Capabilities {
        serde_json::from_str(&self.capabilities).unwrap_or_default()
    }

    pub fn is_self(&self) -> bool {
        self.caps().is_self
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Capabilities {
    #[serde(default)]
    pub runs_singbox: bool,
    #[serde(default)]
    pub is_wg_member: bool,
    #[serde(default)]
    pub is_wg_hub: bool,
    #[serde(default)]
    pub is_self: bool,
}

#[derive(Debug, Deserialize)]
pub struct CreateHostRequest {
    pub name: String,
    #[serde(default)]
    pub capabilities: Option<Capabilities>,
    #[serde(default)]
    pub profile_id: Option<String>,
    #[serde(default)]
    pub wg_address: Option<String>,
    /// Public `host:port` this host can be dialed at — promotes it to a mesh peer.
    #[serde(default)]
    pub wg_endpoint: Option<String>,
    #[serde(default)]
    pub clash_api: Option<String>,
    #[serde(default)]
    pub clash_secret: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateHostRequest {
    pub name: Option<String>,
    pub capabilities: Option<Capabilities>,
    pub profile_id: Option<String>,
    pub wg_address: Option<String>,
    pub wg_public_key: Option<String>,
    pub wg_endpoint: Option<String>,
    pub clash_api: Option<String>,
    pub clash_secret: Option<String>,
    pub enabled: Option<bool>,
}

/// Status payload the agent POSTs on heartbeat.
#[derive(Debug, Deserialize)]
pub struct AgentStatusReport {
    #[serde(default)]
    pub singbox_version: Option<String>,
    #[serde(default)]
    pub singbox_running: Option<bool>,
    #[serde(default)]
    pub config_etag: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct HostCommand {
    pub id: String,
    pub host_id: String,
    pub command: String,
    pub status: String,
    pub result: Option<String>,
    pub created_at: String,
    pub acked_at: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct EnqueueCommandRequest {
    pub command: String,
}

/// Result the agent posts back after running a command.
#[derive(Debug, Deserialize)]
pub struct CommandAck {
    pub status: String, // done | failed
    #[serde(default)]
    pub result: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ConfigProfile {
    pub id: String,
    pub name: String,
    /// JSON: sing-box config minus the outbounds array.
    pub template: String,
    pub created_at: String,
    pub updated_at: String,
}
