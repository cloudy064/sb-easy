//! Application settings API.
use axum::{
    extract::State,
    Json, Router,
};
use axum::routing::{get, put};
use serde_json::{json, Value};

use crate::error::Result;
use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(get_settings).put(update_settings))
}

async fn get_settings(State(state): State<AppState>) -> Result<Json<Value>> {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT key, value FROM app_settings"
    ).fetch_all(&state.db).await?;

    let mut result = json!({});
    for (key, value) in rows {
        if let Ok(parsed) = serde_json::from_str::<Value>(&value) {
            result[key] = parsed;
        }
    }

    // Override wireguard_interface with actual runtime config (from env)
    result["wireguard_interface"] = json!({
        "interface": state.cfg.wg_interface,
        "listen_port": state.cfg.wg_port,
        "address": state.cfg.wg_address,
        "dns": state.cfg.wg_dns,
        "mtu": state.cfg.wg_mtu,
    });

    Ok(Json(result))
}

async fn update_settings(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> Result<Json<Value>> {
    // Only persist singbox_connection and general — wireguard is read-only (env)
    for key in &["singbox_connection", "general"] {
        if let Some(value) = body.get(*key) {
            let value_str = serde_json::to_string(value)?;
            sqlx::query(
                "INSERT INTO app_settings (key, value, updated_at) VALUES (?, ?, datetime('now')) ON CONFLICT(key) DO UPDATE SET value = ?, updated_at = datetime('now')"
            )
            .bind(*key).bind(&value_str).bind(&value_str)
            .execute(&state.db).await?;
        }
    }

    get_settings(State(state)).await
}
