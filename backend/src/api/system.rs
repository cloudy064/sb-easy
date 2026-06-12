//! System status API.
use axum::{
    extract::State,
    Json, Router,
};
use axum::routing::{get, post};
use serde_json::json;

use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/migrate/wg-easy", post(migrate_wg_easy))
}

pub async fn status_handler(State(state): State<AppState>) -> Json<serde_json::Value> {
    let peer_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM wireguard_peers")
        .fetch_one(&state.db).await.unwrap_or((0,));
    let node_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM proxy_nodes")
        .fetch_one(&state.db).await.unwrap_or((0,));
    let sub_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM subscriptions")
        .fetch_one(&state.db).await.unwrap_or((0,));

    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "status": "running",
        "wireguard": { "peer_count": peer_count.0 },
        "sing_box": { "node_count": node_count.0 },
        "subscriptions": { "count": sub_count.0 },
    }))
}

async fn migrate_wg_easy(State(state): State<AppState>) -> Json<serde_json::Value> {
    // Placeholder for wg-easy data migration
    Json(json!({
        "status": "not_implemented",
        "message": "wg-easy migration coming in a future update. Use manual import for now."
    }))
}
