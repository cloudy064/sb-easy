//! Sing-box Clash API proxy — forwards to sing-box instance.
use axum::{
    extract::{Path, State},
    Json, Router,
};
use axum::routing::{delete, get, put};
use crate::error::{AppError, Result};
use crate::util::encode_query_component;
use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/proxies", get(proxy_proxies))
        .route("/proxies/{name}", get(proxy_detail).put(select_proxy))
        .route("/proxies/{name}/delay", get(proxy_delay))
        .route("/group/{name}/delay", get(group_delay))
        .route("/rules", get(proxy_rules))
        .route("/connections", get(proxy_connections).delete(close_all_connections))
        .route("/connections/{id}", delete(close_one_connection))
        .route("/version", get(proxy_version))
}

async fn singbox_get(state: &AppState, path: &str) -> Result<serde_json::Value> {
    let base = state.cfg.singbox_api_url.trim_end_matches('/');
    let client = reqwest::Client::new();
    let mut req = client.get(format!("{base}{path}"));
    if !state.cfg.singbox_api_secret.is_empty() {
        req = req.header("Authorization", format!("Bearer {}", state.cfg.singbox_api_secret));
    }
    let resp = req.send().await.map_err(|e| AppError::Internal(format!("sing-box API: {e}")))?;
    Ok(resp.json().await.unwrap_or_default())
}

async fn singbox_delete(state: &AppState, path: &str) -> Result<serde_json::Value> {
    let base = state.cfg.singbox_api_url.trim_end_matches('/');
    let client = reqwest::Client::new();
    let mut req = client.delete(format!("{base}{path}"));
    if !state.cfg.singbox_api_secret.is_empty() {
        req = req.header("Authorization", format!("Bearer {}", state.cfg.singbox_api_secret));
    }
    let resp = req.send().await.map_err(|e| AppError::Internal(format!("sing-box API: {e}")))?;
    Ok(resp.json().await.unwrap_or_default())
}

async fn proxy_proxies(State(state): State<AppState>) -> Result<Json<serde_json::Value>> {
    Ok(Json(singbox_get(&state, "/proxies").await?))
}

async fn proxy_detail(State(state): State<AppState>, Path(name): Path<String>) -> Result<Json<serde_json::Value>> {
    Ok(Json(singbox_get(&state, &format!("/proxies/{}", encode_query_component(&name))).await?))
}

/// PUT /api/sing-box/proxies/{name} — select the active node in a proxy group.
/// Body: { "name": "<node tag>" } — forwarded to sing-box Clash API.
async fn select_proxy(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>> {
    let base = state.cfg.singbox_api_url.trim_end_matches('/');
    let client = reqwest::Client::new();
    let mut req = client
        .put(format!("{base}/proxies/{}", encode_query_component(&name)))
        .json(&body);
    if !state.cfg.singbox_api_secret.is_empty() {
        req = req.header("Authorization", format!("Bearer {}", state.cfg.singbox_api_secret));
    }
    let resp = req.send().await.map_err(|e| AppError::Internal(format!("sing-box API: {e}")))?;
    if resp.status().is_success() {
        Ok(Json(serde_json::json!({"success": true})))
    } else {
        Err(AppError::BadRequest(format!("sing-box returned {}", resp.status())))
    }
}

async fn proxy_delay(
    State(state): State<AppState>,
    Path(name): Path<String>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<serde_json::Value>> {
    let url = params.get("url").map(|s| s.as_str())
        .unwrap_or("https://www.gstatic.com/generate_204");
    let timeout = params.get("timeout").map(|s| s.as_str()).unwrap_or("5000");
    let path = format!(
        "/proxies/{}/delay?url={}&timeout={}",
        encode_query_component(&name),
        encode_query_component(url),
        encode_query_component(timeout),
    );
    Ok(Json(singbox_get(&state, &path).await?))
}

async fn group_delay(
    State(state): State<AppState>,
    Path(name): Path<String>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<serde_json::Value>> {
    let url = params.get("url").map(|s| s.as_str())
        .unwrap_or("https://www.gstatic.com/generate_204");
    let timeout = params.get("timeout").map(|s| s.as_str()).unwrap_or("5000");
    let path = format!(
        "/group/{}/delay?url={}&timeout={}",
        encode_query_component(&name),
        encode_query_component(url),
        encode_query_component(timeout),
    );
    Ok(Json(singbox_get(&state, &path).await?))
}

async fn proxy_rules(State(state): State<AppState>) -> Result<Json<serde_json::Value>> {
    Ok(Json(singbox_get(&state, "/rules").await?))
}

async fn proxy_connections(State(state): State<AppState>) -> Result<Json<serde_json::Value>> {
    Ok(Json(singbox_get(&state, "/connections").await?))
}

async fn close_all_connections(State(state): State<AppState>) -> Result<Json<serde_json::Value>> {
    Ok(Json(singbox_delete(&state, "/connections").await?))
}

async fn close_one_connection(State(state): State<AppState>, Path(id): Path<String>) -> Result<Json<serde_json::Value>> {
    Ok(Json(singbox_delete(&state, &format!("/connections/{id}")).await?))
}

async fn proxy_version(State(state): State<AppState>) -> Result<Json<serde_json::Value>> {
    Ok(Json(singbox_get(&state, "/version").await?))
}
