//! Agent API — endpoint for sb-easy-agent running on sing-box node (10.168.1.5).
use axum::{
    extract::State,
    http::HeaderMap,
    Json, Router,
};
use axum::routing::get;
use sha2::{Digest, Sha256};

use crate::error::{AppError, Result};
use crate::models::proxy_node::ProxyNode;
use crate::services::proxy_config;
use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/config", get(agent_config))
        .route("/health", get(agent_health))
}

/// GET /api/agent/config
/// Returns full sing-box config with ETag support for incremental updates.
/// Agent sends If-None-Match header with last ETag; server returns 304 if unchanged.
async fn agent_config(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<axum::response::Response> {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    let nodes = sqlx::query_as::<_, ProxyNode>(
        "SELECT * FROM proxy_nodes WHERE enabled = 1"
    ).fetch_all(&state.db).await?;

    let config = proxy_config::generate_full_config(&nodes);
    let config_str = serde_json::to_string_pretty(&config).unwrap_or_default();

    // Compute ETag from config content + cached config hash
    let mut hasher = Sha256::new();
    hasher.update(config_str.as_bytes());
    hasher.update(state.cfg.config_hash_seed.as_bytes());
    let etag = format!("\"{:x}\"", hasher.finalize());

    // Check If-None-Match header
    if let Some(if_none_match) = headers.get("if-none-match").and_then(|v| v.to_str().ok()) {
        if if_none_match == etag {
            let mut resp = axum::response::Response::new(axum::body::Body::empty());
            *resp.status_mut() = StatusCode::NOT_MODIFIED;
            resp.headers_mut().insert(
                axum::http::header::ETAG,
                axum::http::HeaderValue::from_str(&etag).unwrap(),
            );
            return Ok(resp);
        }
    }

    let mut resp = axum::response::Response::new(
        axum::body::Body::from(config_str),
    );
    *resp.status_mut() = StatusCode::OK;
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    resp.headers_mut().insert(
        axum::http::header::ETAG,
        axum::http::HeaderValue::from_str(&etag).unwrap(),
    );
    Ok(resp)
}

/// GET /api/agent/health — simple health check for the agent.
async fn agent_health() -> Json<serde_json::Value> {
    serde_json::json!({"status": "ok"}).into()
}
