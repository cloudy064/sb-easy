//! Proxy node management API.
use axum::{
    extract::{Path, State},
    Json, Router,
};
use axum::routing::{delete, get, post, put};
use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::models::proxy_node::{CreateNodeRequest, ProxyNode, UpdateNodeRequest};
use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/nodes", get(list_nodes).post(create_node))
        .route("/nodes/import", post(import_nodes))
        .route("/nodes/{id}", get(get_node).put(update_node).delete(delete_node))
        .route("/nodes/{id}/test-latency", post(test_latency_single))
}

#[derive(serde::Deserialize)]
struct ImportRequest {
    /// Import the `outbounds` of an existing config profile.
    profile_id: Option<String>,
    /// Or paste a raw sing-box config / outbounds array (JSON string).
    config: Option<String>,
}

/// POST /api/proxy/nodes/import — populate the structured node list from an
/// existing sing-box config (a stored profile's outbounds, or pasted JSON).
///
/// Purely additive: it inserts/updates `proxy_nodes` (deduplicated by
/// fingerprint) and never touches a running config. Groups (selector/urltest)
/// and built-in outbounds are skipped; the response reports exactly what was
/// imported and what was skipped so the operator can verify before relying on it.
async fn import_nodes(
    State(state): State<AppState>,
    Json(req): Json<ImportRequest>,
) -> Result<Json<serde_json::Value>> {
    use crate::models::host::ConfigProfile;

    // Resolve the source config JSON.
    let config: serde_json::Value = if let Some(pid) = req.profile_id.as_deref() {
        let profile = sqlx::query_as::<_, ConfigProfile>("SELECT * FROM config_profiles WHERE id = ?")
            .bind(pid)
            .fetch_optional(&state.db)
            .await?
            .ok_or_else(|| AppError::NotFound("Profile not found".into()))?;
        serde_json::from_str(&profile.template)
            .map_err(|e| AppError::BadRequest(format!("Profile template is not valid JSON: {e}")))?
    } else if let Some(raw) = req.config.as_deref() {
        serde_json::from_str(raw.trim())
            .map_err(|e| AppError::BadRequest(format!("Pasted config is not valid JSON: {e}")))?
    } else {
        return Err(AppError::BadRequest(
            "Provide either profile_id or config".into(),
        ));
    };

    let parse = crate::services::outbound_parser::parse_config(&config);
    let found = parse.nodes.len();
    let (added, updated, errors) =
        crate::services::subscription::upsert_nodes(&state.db, &parse.nodes, None).await;

    Ok(Json(json!({
        "found": found,
        "added": added,
        "updated": updated,
        "skipped": parse.skipped,
        "errors": errors,
    })))
}

/// GET /api/proxy/nodes
async fn list_nodes(State(state): State<AppState>) -> Result<Json<Vec<ProxyNode>>> {
    let nodes = sqlx::query_as::<_, ProxyNode>(
        "SELECT * FROM proxy_nodes ORDER BY node_type, tag"
    )
    .fetch_all(&state.db)
    .await?;
    Ok(Json(nodes))
}

/// POST /api/proxy/nodes — create a new proxy node manually.
async fn create_node(
    State(state): State<AppState>,
    Json(req): Json<CreateNodeRequest>,
) -> Result<Json<ProxyNode>> {
    use sha2::{Digest, Sha256};

    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let protocol_config_str = serde_json::to_string(&req.protocol_config)?;

    // Generate fingerprint
    let raw = format!("{}:{}:{}:{}", req.server, req.server_port, req.node_type,
        extract_key_material(&req.node_type, &req.protocol_config));
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    let fingerprint = format!("{:x}", hasher.finalize());

    let node = ProxyNode {
        id,
        tag: req.tag,
        node_type: req.node_type,
        enabled: req.enabled.unwrap_or(true),
        server: req.server,
        server_port: req.server_port,
        protocol_config: protocol_config_str,
        subscription_id: None,
        fingerprint,
        latency: None,
        last_latency_test: None,
        created_at: now.clone(),
        updated_at: now,
    };

    sqlx::query(
        "INSERT INTO proxy_nodes (id, tag, node_type, enabled, server, server_port, protocol_config, subscription_id, fingerprint, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)"
    )
    .bind(&node.id).bind(&node.tag).bind(&node.node_type).bind(node.enabled)
    .bind(&node.server).bind(node.server_port).bind(&node.protocol_config)
    .bind(&node.subscription_id).bind(&node.fingerprint).bind(&node.created_at).bind(&node.updated_at)
    .execute(&state.db)
    .await?;

    Ok(Json(node))
}

/// GET /api/proxy/nodes/{id}
async fn get_node(State(state): State<AppState>, Path(id): Path<String>) -> Result<Json<ProxyNode>> {
    let node = sqlx::query_as::<_, ProxyNode>("SELECT * FROM proxy_nodes WHERE id = ?")
        .bind(&id).fetch_optional(&state.db).await?
        .ok_or_else(|| AppError::NotFound("Node not found".into()))?;
    Ok(Json(node))
}

/// PUT /api/proxy/nodes/{id}
async fn update_node(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateNodeRequest>,
) -> Result<Json<ProxyNode>> {
    let mut node = sqlx::query_as::<_, ProxyNode>("SELECT * FROM proxy_nodes WHERE id = ?")
        .bind(&id).fetch_optional(&state.db).await?
        .ok_or_else(|| AppError::NotFound("Node not found".into()))?;

    if let Some(tag) = req.tag { node.tag = tag; }
    if let Some(server) = req.server { node.server = server; }
    if let Some(port) = req.server_port { node.server_port = port; }
    if let Some(config) = req.protocol_config { node.protocol_config = serde_json::to_string(&config)?; }
    if let Some(enabled) = req.enabled { node.enabled = enabled; }
    node.updated_at = Utc::now().to_rfc3339();

    sqlx::query(
        "UPDATE proxy_nodes SET tag=?, server=?, server_port=?, protocol_config=?, enabled=?, updated_at=? WHERE id=?"
    )
    .bind(&node.tag).bind(&node.server).bind(node.server_port).bind(&node.protocol_config)
    .bind(node.enabled).bind(&node.updated_at).bind(&node.id)
    .execute(&state.db)
    .await?;

    Ok(Json(node))
}

/// DELETE /api/proxy/nodes/{id}
async fn delete_node(State(state): State<AppState>, Path(id): Path<String>) -> Result<Json<serde_json::Value>> {
    sqlx::query("DELETE FROM proxy_nodes WHERE id = ?").bind(&id).execute(&state.db).await?;
    Ok(Json(json!({"success": true})))
}

/// POST /api/proxy/nodes/{id}/test-latency
async fn test_latency_single(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let node = sqlx::query_as::<_, ProxyNode>("SELECT * FROM proxy_nodes WHERE id = ?")
        .bind(&id).fetch_optional(&state.db).await?
        .ok_or_else(|| AppError::NotFound("Node not found".into()))?;

    let latency = test_node_latency(&state, &node).await?;
    let now = Utc::now().to_rfc3339();

    sqlx::query("UPDATE proxy_nodes SET latency = ?, last_latency_test = ? WHERE id = ?")
        .bind(latency).bind(&now).bind(&id).execute(&state.db).await?;

    Ok(Json(json!({"node_id": id, "latency": latency, "tested_at": now})))
}

/// Test latency of a single node via sing-box Clash API.
async fn test_node_latency(state: &AppState, node: &ProxyNode) -> Result<Option<f64>> {
    use std::time::Duration;

    let timeout = 5000;
    let url = format!(
        "{}/proxies/{}/delay?url={}&timeout={}",
        state.cfg.singbox_api_url.trim_end_matches('/'),
        crate::util::encode_query_component(&node.tag),
        crate::util::encode_query_component("https://www.gstatic.com/generate_204"),
        timeout,
    );

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let mut req = client.get(&url);
    if !state.cfg.singbox_api_secret.is_empty() {
        req = req.header("Authorization", format!("Bearer {}", state.cfg.singbox_api_secret));
    }

    let response = req.send().await;
    match response {
        Ok(resp) if resp.status().is_success() => {
            let body: serde_json::Value = resp.json().await.unwrap_or(json!({}));
            Ok(body["delay"].as_f64())
        }
        Ok(_) => {
            // Node might be unreachable
            Ok(None)
        }
        Err(_) => Ok(None),
    }
}

fn extract_key_material(node_type: &str, config: &serde_json::Value) -> String {
    match node_type {
        "shadowsocks" => config["password"].as_str().unwrap_or("").to_string(),
        "vmess" | "vless" => config["uuid"].as_str().unwrap_or("").to_string(),
        "trojan" | "hysteria2" => config["password"].as_str().unwrap_or("").to_string(),
        "tuic" => format!("{}:{}", config["uuid"].as_str().unwrap_or(""), config["password"].as_str().unwrap_or("")),
        _ => String::new(),
    }
}
