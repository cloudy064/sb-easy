//! Application settings API.
use axum::{
    extract::State,
    Json, Router,
};
use axum::routing::{get, put};
use serde_json::{json, Value};

use crate::error::{AppError, Result};
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

    Ok(Json(result))
}

async fn update_settings(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> Result<Json<Value>> {
    for (key, value) in body.as_object().unwrap_or(&serde_json::Map::new()) {
        let value_str = serde_json::to_string(value)?;
        sqlx::query(
            "INSERT INTO app_settings (key, value, updated_at) VALUES (?, ?, datetime('now')) ON CONFLICT(key) DO UPDATE SET value = ?, updated_at = datetime('now')"
        )
        .bind(key).bind(&value_str).bind(&value_str)
        .execute(&state.db).await?;
    }

    get_settings(State(state)).await
}
