//! Agent API — endpoints for sb-easy-agent running on a managed host.
//!
//! Each host authenticates with its own per-host `agent_token` (provisioned when
//! the host is created). The endpoint resolves the calling host from that token
//! and serves a config rendered specifically for it. For backward compatibility
//! the legacy global `AGENT_TOKEN` env still maps to the built-in `self` host.
use axum::{
    extract::State,
    http::HeaderMap,
    Json, Router,
};
use axum::routing::{get, post};
use chrono::Utc;

use crate::error::{AppError, Result};
use crate::models::host::{AgentStatusReport, CommandAck, Host, HostCommand};
use crate::services::proxy_config;
use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/config", get(agent_config))
        .route("/status", post(agent_status))
        .route("/commands", get(agent_commands))
        .route("/commands/{cmd_id}/ack", post(agent_command_ack))
        .route("/proxy-latency", post(agent_proxy_latency))
        .route("/health", get(agent_health))
}

/// POST /api/agent/proxy-latency — an agent reports delay-test results from its
/// local sing-box (`{ "results": { "<tag>": <ms|null> } }`). We patch the
/// matching `proxy_nodes` rows by tag. Auth ties the report to a known host.
async fn agent_proxy_latency(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>> {
    let _host = resolve_host(&state, &headers).await?;
    let now = Utc::now().to_rfc3339();
    let mut updated = 0u64;
    if let Some(results) = body.get("results").and_then(|v| v.as_object()) {
        for (tag, delay) in results {
            let latency = delay.as_f64();
            if let Ok(r) = sqlx::query(
                "UPDATE proxy_nodes SET latency = ?, last_latency_test = ? WHERE tag = ?",
            )
            .bind(latency)
            .bind(&now)
            .bind(tag)
            .execute(&state.db)
            .await
            {
                updated += r.rows_affected();
            }
        }
    }
    Ok(Json(serde_json::json!({ "ok": true, "updated": updated })))
}

/// GET /api/agent/config
/// Returns the sing-box config rendered for the calling host, with ETag support
/// (agent sends If-None-Match; server returns 304 when unchanged).
async fn agent_config(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<axum::response::Response> {
    use axum::http::StatusCode;

    let host = resolve_host(&state, &headers).await?;

    let config = crate::api::hosts::render_host_served(&state, &host).await;
    let config_str = serde_json::to_string_pretty(&config).unwrap_or_default();

    // ETag scoped per host so different hosts get independent caching.
    let etag = proxy_config::config_etag(&host.id, &config_str, &state.cfg.config_hash_seed);

    // Touch last_seen on every poll so the UI can show liveness.
    let _ = sqlx::query("UPDATE hosts SET last_seen = ? WHERE id = ?")
        .bind(Utc::now().to_rfc3339())
        .bind(&host.id)
        .execute(&state.db)
        .await;

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

    let mut resp = axum::response::Response::new(axum::body::Body::from(config_str));
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

/// POST /api/agent/status — agent heartbeat: report sing-box state.
async fn agent_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(report): Json<AgentStatusReport>,
) -> Result<Json<serde_json::Value>> {
    let host = resolve_host(&state, &headers).await?;

    let state_json = serde_json::json!({
        "version": report.singbox_version,
        "running": report.singbox_running,
        "etag": report.config_etag,
    })
    .to_string();

    sqlx::query("UPDATE hosts SET last_seen = ?, singbox_state = ? WHERE id = ?")
        .bind(Utc::now().to_rfc3339())
        .bind(&state_json)
        .bind(&host.id)
        .execute(&state.db)
        .await?;

    Ok(Json(serde_json::json!({"ok": true})))
}

/// GET /api/agent/commands — pending commands for the calling host.
async fn agent_commands(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<HostCommand>>> {
    let host = resolve_host(&state, &headers).await?;
    let cmds = sqlx::query_as::<_, HostCommand>(
        "SELECT * FROM host_commands WHERE host_id = ? AND status = 'pending' ORDER BY created_at",
    )
    .bind(&host.id)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(cmds))
}

/// POST /api/agent/commands/{cmd_id}/ack — agent reports a command's result.
async fn agent_command_ack(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(cmd_id): axum::extract::Path<String>,
    Json(ack): Json<CommandAck>,
) -> Result<Json<serde_json::Value>> {
    let host = resolve_host(&state, &headers).await?;
    let status = if ack.status == "done" { "done" } else { "failed" };
    // Scope the update to the calling host so an agent can only ack its own commands.
    sqlx::query("UPDATE host_commands SET status = ?, result = ?, acked_at = ? WHERE id = ? AND host_id = ?")
        .bind(status)
        .bind(&ack.result)
        .bind(Utc::now().to_rfc3339())
        .bind(&cmd_id)
        .bind(&host.id)
        .execute(&state.db)
        .await?;
    Ok(Json(serde_json::json!({"ok": true})))
}

/// GET /api/agent/health — simple health check for the agent.
async fn agent_health() -> Json<serde_json::Value> {
    serde_json::json!({"status": "ok"}).into()
}

/// Resolve the calling host from its bearer token.
///
/// 1. Match a host whose per-host `agent_token` equals the presented token.
/// 2. Backward compatibility: if the legacy global `AGENT_TOKEN` is set and
///    matches, serve the built-in `self` host.
/// Otherwise reject. An empty/missing token is always rejected.
async fn resolve_host(state: &AppState, headers: &HeaderMap) -> Result<Host> {
    let presented = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|t| t.trim())
        .filter(|t| !t.is_empty())
        .ok_or_else(|| AppError::Unauthorized("Missing agent token".into()))?;

    if let Some(host) = sqlx::query_as::<_, Host>(
        "SELECT * FROM hosts WHERE agent_token = ? AND agent_token != '' AND enabled = 1",
    )
    .bind(presented)
    .fetch_optional(&state.db)
    .await?
    {
        return Ok(host);
    }

    let global = state.cfg.agent_token.trim();
    if !global.is_empty() && presented == global {
        if let Some(host) = sqlx::query_as::<_, Host>("SELECT * FROM hosts WHERE id = 'self'")
            .fetch_optional(&state.db)
            .await?
        {
            return Ok(host);
        }
    }

    Err(AppError::Unauthorized("Invalid agent token".into()))
}
