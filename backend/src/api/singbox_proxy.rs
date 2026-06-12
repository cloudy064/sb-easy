//! Sing-box Clash API proxy — transparently forwards requests.
use axum::{
    extract::State,
    Json, Router,
};
use axum::routing::get;

use crate::error::{AppError, Result};
use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/proxies", get(proxy_proxies))
        .route("/version", get(proxy_version))
}

async fn proxy_proxies(State(state): State<AppState>) -> Result<Json<serde_json::Value>> {
    let url = format!("{}/proxies", state.cfg.singbox_api_url.trim_end_matches('/'));
    let client = reqwest::Client::new();
    let mut req = client.get(&url);
    if !state.cfg.singbox_api_secret.is_empty() {
        req = req.header("Authorization", format!("Bearer {}", state.cfg.singbox_api_secret));
    }
    let resp = req.send().await.map_err(|e| AppError::Internal(format!("sing-box API unreachable: {e}")))?;
    let body: serde_json::Value = resp.json().await.unwrap_or_default();
    Ok(Json(body))
}

async fn proxy_version(State(state): State<AppState>) -> Result<Json<serde_json::Value>> {
    let url = format!("{}/version", state.cfg.singbox_api_url.trim_end_matches('/'));
    let client = reqwest::Client::new();
    let resp = client.get(&url).send().await.map_err(|e| AppError::Internal(format!("sing-box API unreachable: {e}")))?;
    let body: serde_json::Value = resp.json().await.unwrap_or_default();
    Ok(Json(body))
}
