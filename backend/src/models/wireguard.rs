//! WireGuard peer model.
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct WireGuardPeer {
    pub id: String,
    pub name: String,
    pub private_key: String,
    pub public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preshared_key: Option<String>,
    pub address: String,
    pub dns: String,
    pub enabled: bool,
    pub persistent_keepalive: i32,
    pub allowed_ips: String,
    pub expire_at: Option<String>,
    #[serde(default)]
    pub quota_bytes: i64,
    pub created_at: String,
    pub updated_at: String,
    pub notes: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreatePeerRequest {
    pub name: String,
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default = "default_dns")]
    pub dns: Option<String>,
    #[serde(default = "default_keepalive")]
    pub persistent_keepalive: Option<i32>,
    #[serde(default = "default_allowed_ips")]
    pub allowed_ips: Option<String>,
    pub expire_at: Option<String>,
    #[serde(default)]
    pub quota_bytes: Option<i64>,
    pub notes: Option<String>,
}

fn default_dns() -> Option<String> { Some("10.59.32.1".into()) }
fn default_keepalive() -> Option<i32> { Some(25) }
fn default_allowed_ips() -> Option<String> { Some("0.0.0.0/0, ::/0".into()) }

#[derive(Debug, Deserialize)]
pub struct UpdatePeerRequest {
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub dns: Option<String>,
    pub persistent_keepalive: Option<i32>,
    pub allowed_ips: Option<String>,
    pub expire_at: Option<String>,
    pub quota_bytes: Option<i64>,
    pub notes: Option<String>,
}

/// Live stats parsed from `wg show wg0 dump`.
#[derive(Debug, Clone, Serialize)]
pub struct PeerStats {
    pub public_key: String,
    pub endpoint: Option<String>,
    pub latest_handshake: Option<i64>, // unix timestamp
    pub transfer_rx: i64,              // bytes received
    pub transfer_tx: i64,              // bytes sent
}
