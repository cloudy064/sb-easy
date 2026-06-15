//! Subscription management API.
use axum::{
    extract::{Path, State},
    Json, Router,
};
use axum::routing::{delete, get, post, put};
use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::models::subscription::{CreateSubscriptionRequest, FetchResult, Subscription};
use crate::services::subscription as sub_svc;
use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_subs).post(create_sub))
        .route("/{id}", get(get_sub).put(update_sub).delete(delete_sub))
        .route("/{id}/fetch", post(fetch_sub))
        .route("/fetch-all", post(fetch_all))
}

async fn list_subs(State(state): State<AppState>) -> Result<Json<Vec<Subscription>>> {
    let subs = sqlx::query_as::<_, Subscription>("SELECT * FROM subscriptions ORDER BY name")
        .fetch_all(&state.db).await?;
    Ok(Json(subs))
}

async fn create_sub(
    State(state): State<AppState>,
    Json(req): Json<CreateSubscriptionRequest>,
) -> Result<Json<Subscription>> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    // Default a friendly name from the URL host when blank, so every imported
    // proxy can be attributed to a named source.
    let name = if req.name.trim().is_empty() {
        default_sub_name(&req.url)
    } else {
        req.name.trim().to_string()
    };
    let sub = Subscription {
        id, name, url: req.url,
        enabled: true, refresh_interval: req.refresh_interval.unwrap_or(3600),
        last_fetched_at: None, last_fetch_result: None,
        created_at: now.clone(), updated_at: now,
    };
    sqlx::query(
        "INSERT INTO subscriptions (id, name, url, enabled, refresh_interval, last_fetched_at, last_fetch_result, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)"
    )
    .bind(&sub.id).bind(&sub.name).bind(&sub.url).bind(sub.enabled).bind(sub.refresh_interval)
    .bind(&sub.last_fetched_at).bind(&sub.last_fetch_result).bind(&sub.created_at).bind(&sub.updated_at)
    .execute(&state.db).await?;
    Ok(Json(sub))
}

/// Derive a readable subscription name from its URL host (e.g. `sub.example.com`),
/// falling back to a generic label.
fn default_sub_name(url: &str) -> String {
    let host = url
        .split("://")
        .nth(1)
        .unwrap_or(url)
        .split('/')
        .next()
        .unwrap_or("")
        .split('@')
        .next_back()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .trim();
    if host.is_empty() {
        "Subscription".to_string()
    } else {
        host.to_string()
    }
}

async fn get_sub(State(state): State<AppState>, Path(id): Path<String>) -> Result<Json<Subscription>> {
    let sub = sqlx::query_as::<_, Subscription>("SELECT * FROM subscriptions WHERE id = ?")
        .bind(&id).fetch_optional(&state.db).await?
        .ok_or_else(|| AppError::NotFound("Subscription not found".into()))?;
    Ok(Json(sub))
}

async fn update_sub(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<Subscription>> {
    let mut sub = sqlx::query_as::<_, Subscription>("SELECT * FROM subscriptions WHERE id = ?")
        .bind(&id).fetch_optional(&state.db).await?
        .ok_or_else(|| AppError::NotFound("Subscription not found".into()))?;

    if let Some(name) = body["name"].as_str() { sub.name = name.to_string(); }
    if let Some(url) = body["url"].as_str() { sub.url = url.to_string(); }
    if let Some(enabled) = body["enabled"].as_bool() { sub.enabled = enabled; }
    if let Some(interval) = body["refresh_interval"].as_i64() { sub.refresh_interval = interval as i32; }
    sub.updated_at = Utc::now().to_rfc3339();

    sqlx::query("UPDATE subscriptions SET name=?, url=?, enabled=?, refresh_interval=?, updated_at=? WHERE id=?")
        .bind(&sub.name).bind(&sub.url).bind(sub.enabled).bind(sub.refresh_interval)
        .bind(&sub.updated_at).bind(&sub.id)
        .execute(&state.db).await?;

    Ok(Json(sub))
}

async fn delete_sub(State(state): State<AppState>, Path(id): Path<String>) -> Result<Json<serde_json::Value>> {
    sqlx::query("DELETE FROM subscriptions WHERE id = ?").bind(&id).execute(&state.db).await?;
    Ok(Json(json!({"success": true})))
}

async fn fetch_sub(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<FetchResult>> {
    let sub = sqlx::query_as::<_, Subscription>("SELECT * FROM subscriptions WHERE id = ?")
        .bind(&id).fetch_optional(&state.db).await?
        .ok_or_else(|| AppError::NotFound("Subscription not found".into()))?;

    let result = sub_svc::fetch_subscription(&state.db, &sub.id, &sub.url).await?;
    Ok(Json(result))
}

async fn fetch_all(State(state): State<AppState>) -> Result<Json<Vec<serde_json::Value>>> {
    let subs = sqlx::query_as::<_, Subscription>(
        "SELECT * FROM subscriptions WHERE enabled = 1"
    ).fetch_all(&state.db).await?;

    let mut results = Vec::new();
    for sub in subs {
        match sub_svc::fetch_subscription(&state.db, &sub.id, &sub.url).await {
            Ok(result) => results.push(json!({"id": sub.id, "name": sub.name, "added": result.added, "updated": result.updated, "errors": result.errors})),
            Err(e) => results.push(json!({"id": sub.id, "name": sub.name, "error": e.to_string()})),
        }
    }
    Ok(Json(results))
}
