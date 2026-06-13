//! Sing-box Clash API proxy — forwards to a sing-box instance.
//!
//! Every endpoint accepts an optional `?host=<id>` query param selecting which
//! managed host's Clash API to talk to (reached over the WG intranet). When
//! omitted — or `host=self` — it targets the local sing-box configured via env.
use axum::{
    extract::{Path, Query, State},
    Json, Router,
};
use axum::routing::{delete, get, put};
use std::collections::HashMap;

use crate::api::hosts::resolve_clash_target;
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

/// The Clash API endpoint (base URL + bearer secret) resolved for a request.
struct Target {
    base: String,
    secret: String,
}

impl Target {
    async fn from(state: &AppState, params: &HashMap<String, String>) -> Self {
        let (base, secret) = resolve_clash_target(state, params.get("host").map(|s| s.as_str())).await;
        Target { base, secret }
    }

    fn auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if self.secret.is_empty() {
            req
        } else {
            req.header("Authorization", format!("Bearer {}", self.secret))
        }
    }

    async fn get(&self, path: &str) -> Result<serde_json::Value> {
        let client = reqwest::Client::new();
        let req = self.auth(client.get(format!("{}{path}", self.base)));
        let resp = req.send().await.map_err(|e| AppError::Internal(format!("sing-box API: {e}")))?;
        Ok(resp.json().await.unwrap_or_default())
    }

    async fn delete(&self, path: &str) -> Result<serde_json::Value> {
        let client = reqwest::Client::new();
        let req = self.auth(client.delete(format!("{}{path}", self.base)));
        let resp = req.send().await.map_err(|e| AppError::Internal(format!("sing-box API: {e}")))?;
        Ok(resp.json().await.unwrap_or_default())
    }
}

async fn proxy_proxies(State(state): State<AppState>, Query(p): Query<HashMap<String, String>>) -> Result<Json<serde_json::Value>> {
    Ok(Json(Target::from(&state, &p).await.get("/proxies").await?))
}

async fn proxy_detail(State(state): State<AppState>, Path(name): Path<String>, Query(p): Query<HashMap<String, String>>) -> Result<Json<serde_json::Value>> {
    Ok(Json(Target::from(&state, &p).await.get(&format!("/proxies/{}", encode_query_component(&name))).await?))
}

/// PUT /api/sing-box/proxies/{name} — select the active node in a proxy group.
/// Body: { "name": "<node tag>" } — forwarded to the target sing-box Clash API.
async fn select_proxy(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(p): Query<HashMap<String, String>>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>> {
    let target = Target::from(&state, &p).await;
    let client = reqwest::Client::new();
    let req = target.auth(
        client
            .put(format!("{}/proxies/{}", target.base, encode_query_component(&name)))
            .json(&body),
    );
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
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>> {
    let url = params.get("url").map(|s| s.as_str()).unwrap_or("https://www.gstatic.com/generate_204");
    let timeout = params.get("timeout").map(|s| s.as_str()).unwrap_or("5000");
    let path = format!(
        "/proxies/{}/delay?url={}&timeout={}",
        encode_query_component(&name),
        encode_query_component(url),
        encode_query_component(timeout),
    );
    Ok(Json(Target::from(&state, &params).await.get(&path).await?))
}

async fn group_delay(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>> {
    let url = params.get("url").map(|s| s.as_str()).unwrap_or("https://www.gstatic.com/generate_204");
    let timeout = params.get("timeout").map(|s| s.as_str()).unwrap_or("5000");
    let path = format!(
        "/group/{}/delay?url={}&timeout={}",
        encode_query_component(&name),
        encode_query_component(url),
        encode_query_component(timeout),
    );
    Ok(Json(Target::from(&state, &params).await.get(&path).await?))
}

async fn proxy_rules(State(state): State<AppState>, Query(p): Query<HashMap<String, String>>) -> Result<Json<serde_json::Value>> {
    Ok(Json(Target::from(&state, &p).await.get("/rules").await?))
}

async fn proxy_connections(State(state): State<AppState>, Query(p): Query<HashMap<String, String>>) -> Result<Json<serde_json::Value>> {
    Ok(Json(Target::from(&state, &p).await.get("/connections").await?))
}

async fn close_all_connections(State(state): State<AppState>, Query(p): Query<HashMap<String, String>>) -> Result<Json<serde_json::Value>> {
    Ok(Json(Target::from(&state, &p).await.delete("/connections").await?))
}

async fn close_one_connection(State(state): State<AppState>, Path(id): Path<String>, Query(p): Query<HashMap<String, String>>) -> Result<Json<serde_json::Value>> {
    Ok(Json(Target::from(&state, &p).await.delete(&format!("/connections/{id}")).await?))
}

async fn proxy_version(State(state): State<AppState>, Query(p): Query<HashMap<String, String>>) -> Result<Json<serde_json::Value>> {
    Ok(Json(Target::from(&state, &p).await.get("/version").await?))
}
