//! Proxy node model (sing-box outbound).
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ProxyNode {
    pub id: String,
    pub tag: String,
    pub node_type: String,
    pub enabled: bool,
    pub server: String,
    pub server_port: i32,
    pub protocol_config: String, // JSON string
    pub subscription_id: Option<String>,
    pub fingerprint: String,
    pub latency: Option<f64>,
    pub last_latency_test: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateNodeRequest {
    pub tag: String,
    pub node_type: String,
    pub server: String,
    pub server_port: i32,
    pub protocol_config: serde_json::Value,
    #[serde(default)]
    pub enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateNodeRequest {
    pub tag: Option<String>,
    pub server: Option<String>,
    pub server_port: Option<i32>,
    pub protocol_config: Option<serde_json::Value>,
    pub enabled: Option<bool>,
}
