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
        .route("/backup", get(export_backup))
        .route("/restore", axum::routing::post(import_backup))
}

/// GET /api/settings/backup — export nodes, peers, subscriptions and app
/// settings as a single JSON document for backup/migration.
async fn export_backup(State(state): State<AppState>) -> Result<Json<Value>> {
    let nodes: Vec<Value> = json_rows(&state, "SELECT * FROM proxy_nodes").await?;
    let peers: Vec<Value> = json_rows(&state, "SELECT * FROM wireguard_peers").await?;
    let subs: Vec<Value> = json_rows(&state, "SELECT * FROM subscriptions").await?;
    let settings: Vec<(String, String)> =
        sqlx::query_as("SELECT key, value FROM app_settings").fetch_all(&state.db).await?;
    let settings_obj: serde_json::Map<String, Value> = settings
        .into_iter()
        .filter_map(|(k, v)| serde_json::from_str(&v).ok().map(|val| (k, val)))
        .collect();

    Ok(Json(json!({
        "version": 1,
        "exported_at": chrono::Utc::now().to_rfc3339(),
        "proxy_nodes": nodes,
        "wireguard_peers": peers,
        "subscriptions": subs,
        "app_settings": settings_obj,
    })))
}

/// POST /api/settings/restore — import a backup produced by /backup.
/// Upserts rows (INSERT OR REPLACE) so an import is idempotent; it never drops
/// data the backup doesn't mention.
async fn import_backup(State(state): State<AppState>, Json(body): Json<Value>) -> Result<Json<Value>> {
    let mut counts = serde_json::Map::new();

    if let Some(settings) = body.get("app_settings").and_then(|v| v.as_object()) {
        for (k, v) in settings {
            let vs = serde_json::to_string(v)?;
            sqlx::query(
                "INSERT INTO app_settings (key, value, updated_at) VALUES (?, ?, datetime('now')) ON CONFLICT(key) DO UPDATE SET value = ?, updated_at = datetime('now')"
            ).bind(k).bind(&vs).bind(&vs).execute(&state.db).await?;
        }
        counts.insert("app_settings".into(), json!(settings.len()));
    }

    let nodes = restore_nodes(&state, &body).await?;
    counts.insert("proxy_nodes".into(), json!(nodes));
    let subs = restore_subscriptions(&state, &body).await?;
    counts.insert("subscriptions".into(), json!(subs));

    if state.cfg.wg_enabled {
        let _ = crate::services::wireguard::sync_config(&state.db, &state.cfg).await;
    }
    Ok(Json(json!({ "restored": counts })))
}

async fn restore_nodes(state: &AppState, body: &Value) -> Result<usize> {
    let Some(arr) = body.get("proxy_nodes").and_then(|v| v.as_array()) else { return Ok(0) };
    let mut n = 0;
    for node in arr {
        let get = |k: &str| node.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
        let port = node.get("server_port").and_then(|v| v.as_i64()).unwrap_or(0);
        let enabled = node.get("enabled").and_then(|v| v.as_i64()).unwrap_or(1);
        let cfg = node.get("protocol_config")
            .map(|v| if v.is_string() { v.as_str().unwrap_or("{}").to_string() } else { v.to_string() })
            .unwrap_or_else(|| "{}".into());
        if get("id").is_empty() || get("tag").is_empty() { continue; }
        sqlx::query(
            "INSERT OR REPLACE INTO proxy_nodes (id, tag, node_type, enabled, server, server_port, protocol_config, subscription_id, fingerprint, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,COALESCE((SELECT created_at FROM proxy_nodes WHERE id = ?), datetime('now')),datetime('now'))"
        )
        .bind(get("id")).bind(get("tag")).bind(get("node_type")).bind(enabled)
        .bind(get("server")).bind(port).bind(&cfg)
        .bind(node.get("subscription_id").and_then(|v| v.as_str()))
        .bind(get("fingerprint")).bind(get("id"))
        .execute(&state.db).await?;
        n += 1;
    }
    Ok(n)
}

async fn restore_subscriptions(state: &AppState, body: &Value) -> Result<usize> {
    let Some(arr) = body.get("subscriptions").and_then(|v| v.as_array()) else { return Ok(0) };
    let mut n = 0;
    for s in arr {
        let get = |k: &str| s.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
        let enabled = s.get("enabled").and_then(|v| v.as_i64()).unwrap_or(1);
        let interval = s.get("refresh_interval").and_then(|v| v.as_i64()).unwrap_or(3600);
        if get("id").is_empty() || get("url").is_empty() { continue; }
        sqlx::query(
            "INSERT OR REPLACE INTO subscriptions (id, name, url, enabled, refresh_interval, created_at, updated_at) VALUES (?,?,?,?,?,COALESCE((SELECT created_at FROM subscriptions WHERE id = ?), datetime('now')),datetime('now'))"
        )
        .bind(get("id")).bind(get("name")).bind(get("url")).bind(enabled).bind(interval).bind(get("id"))
        .execute(&state.db).await?;
        n += 1;
    }
    Ok(n)
}

async fn json_rows(state: &AppState, query: &str) -> Result<Vec<Value>> {
    use sqlx::Column;
    use sqlx::Row;
    let rows = sqlx::query(query).fetch_all(&state.db).await?;
    let mut out = Vec::new();
    for row in &rows {
        let mut obj = serde_json::Map::new();
        for (i, col) in row.columns().iter().enumerate() {
            // SQLite columns are dynamically typed; probe String → i64 → f64 so
            // TEXT, INTEGER and REAL values all round-trip.
            let val = if let Ok(Some(s)) = row.try_get::<Option<String>, _>(i) {
                Value::String(s)
            } else if let Ok(Some(n)) = row.try_get::<Option<i64>, _>(i) {
                Value::from(n)
            } else if let Ok(Some(f)) = row.try_get::<Option<f64>, _>(i) {
                Value::from(f)
            } else {
                Value::Null
            };
            obj.insert(col.name().to_string(), val);
        }
        out.push(Value::Object(obj));
    }
    Ok(out)
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

    // WireGuard: merge DB-persisted settings with runtime env fallbacks
    // DB has priority (set via UI), env is the baseline default.
    let wg_db = result.get("wireguard_interface").cloned();
    let wg_cfg = json!({
        "interface": state.cfg.wg_interface,
        "listen_port": state.cfg.wg_port,
        "address": state.cfg.wg_address,
        "dns": state.cfg.wg_dns,
        "mtu": state.cfg.wg_mtu,
    });

    // If DB has a value, merge (DB wins); otherwise show env default
    if let Some(db_val) = wg_db {
        let mut merged = wg_cfg;
        for (k, v) in db_val.as_object().unwrap_or(&serde_json::Map::new()) {
            if !v.is_null() { merged[k] = v.clone(); }
        }
        result["wireguard_interface"] = merged;
    } else {
        result["wireguard_interface"] = wg_cfg;
    }

    Ok(Json(result))
}

async fn update_settings(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> Result<Json<Value>> {
    // Persist all sections
    for key in &["wireguard_interface", "singbox_connection", "general"] {
        if let Some(value) = body.get(*key) {
            let value_str = serde_json::to_string(value)?;
            sqlx::query(
                "INSERT INTO app_settings (key, value, updated_at) VALUES (?, ?, datetime('now')) ON CONFLICT(key) DO UPDATE SET value = ?, updated_at = datetime('now')"
            )
            .bind(*key).bind(&value_str).bind(&value_str)
            .execute(&state.db).await?;
        }
    }

    // If WG is enabled, trigger live reconfiguration
    if state.cfg.wg_enabled {
        let _ = crate::services::wireguard::sync_config(&state.db, &state.cfg).await;
    }

    get_settings(State(state)).await
}
