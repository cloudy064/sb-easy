//! Config download API — generates and serves config files for clients.
use axum::{
    extract::{Path, State},
    Json, Router,
};
use axum::routing::get;

use crate::error::{AppError, Result};
use crate::models::proxy_node::ProxyNode;
use crate::services::proxy_config;
use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/sing-box/full", get(full_config))
        .route("/sing-box/outbounds", get(outbounds))
        .route("/sing-box/outbound/{id}", get(single_outbound))
}

/// GET /api/config/sing-box/full
async fn full_config(State(state): State<AppState>) -> Result<Json<serde_json::Value>> {
    let nodes = sqlx::query_as::<_, ProxyNode>(
        "SELECT * FROM proxy_nodes WHERE enabled = 1"
    ).fetch_all(&state.db).await?;

    let config = proxy_config::generate_full_config(&nodes);
    Ok(Json(config))
}

/// GET /api/config/sing-box/outbounds
async fn outbounds(State(state): State<AppState>) -> Result<Json<serde_json::Value>> {
    let nodes = sqlx::query_as::<_, ProxyNode>(
        "SELECT * FROM proxy_nodes WHERE enabled = 1"
    ).fetch_all(&state.db).await?;

    let outbounds_array = proxy_config::generate_outbounds_array(&nodes);
    Ok(Json(serde_json::json!(outbounds_array)))
}

/// GET /api/config/sing-box/outbound/{id}
async fn single_outbound(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let node = sqlx::query_as::<_, ProxyNode>("SELECT * FROM proxy_nodes WHERE id = ?")
        .bind(&id).fetch_optional(&state.db).await?
        .ok_or_else(|| AppError::NotFound("Node not found".into()))?;

    let outbound = proxy_config::generate_outbound(&node);
    Ok(Json(outbound))
}
