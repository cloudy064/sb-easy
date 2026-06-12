//! WireGuard peer management API.
use axum::{
    extract::{Path, State},
    Json, Router,
};
use axum::routing::{delete, get, post, put};
use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::models::wireguard::{CreatePeerRequest, UpdatePeerRequest, WireGuardPeer};
use crate::services::wireguard as wg;
use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/peers", get(list_peers).post(create_peer))
        .route("/peers/{id}", get(get_peer).put(update_peer).delete(delete_peer))
        .route("/peers/{id}/enable", post(enable_peer))
        .route("/peers/{id}/disable", post(disable_peer))
        .route("/peers/{id}/config", get(download_config))
        .route("/peers/{id}/qr", get(get_qr))
        .route("/peers/{id}/one-time-link", post(create_one_time_link))
        .route("/stats", get(get_stats))
        .route("/sync", post(sync_config))
}

/// GET /api/wireguard/peers — list all peers with live stats merged.
async fn list_peers(State(state): State<AppState>) -> Result<Json<Vec<serde_json::Value>>> {
    let peers = sqlx::query_as::<_, WireGuardPeer>("SELECT * FROM wireguard_peers ORDER BY address")
        .fetch_all(&state.db)
        .await?;

    let stats = wg::get_peer_stats(&state.cfg.wg_interface).unwrap_or_default();

    let result: Vec<serde_json::Value> = peers
        .into_iter()
        .map(|peer| {
            let stat = stats.iter().find(|s| s.public_key == peer.public_key);
            let mut v = serde_json::to_value(&peer).unwrap_or(json!({}));
            if let Some(s) = stat {
                v["endpoint"] = json!(s.endpoint);
                v["latest_handshake"] = json!(s.latest_handshake);
                v["transfer_rx"] = json!(s.transfer_rx);
                v["transfer_tx"] = json!(s.transfer_tx);
            }
            v
        })
        .collect();

    Ok(Json(result))
}

/// POST /api/wireguard/peers — create a new WireGuard peer.
async fn create_peer(
    State(state): State<AppState>,
    Json(req): Json<CreatePeerRequest>,
) -> Result<Json<WireGuardPeer>> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    let (private_key, public_key) = wg::generate_keypair()?;
    let preshared_key = wg::generate_psk()?;

    let address = match req.address {
        Some(addr) => addr,
        None => wg::next_available_ip(&state.db, &state.cfg.wg_address).await?,
    };

    let peer = WireGuardPeer {
        id,
        name: req.name,
        private_key,
        public_key,
        preshared_key: Some(preshared_key),
        address,
        dns: req.dns.unwrap_or_else(|| "10.59.32.1".into()),
        enabled: true,
        persistent_keepalive: req.persistent_keepalive.unwrap_or(25),
        allowed_ips: req.allowed_ips.unwrap_or_else(|| "0.0.0.0/0, ::/0".into()),
        expire_at: req.expire_at,
        created_at: now.clone(),
        updated_at: now,
        notes: req.notes,
    };

    sqlx::query(
        "INSERT INTO wireguard_peers (id, name, private_key, public_key, preshared_key, address, dns, enabled, persistent_keepalive, allowed_ips, expire_at, created_at, updated_at, notes) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
    )
    .bind(&peer.id).bind(&peer.name).bind(&peer.private_key).bind(&peer.public_key)
    .bind(&peer.preshared_key).bind(&peer.address).bind(&peer.dns)
    .bind(peer.enabled).bind(peer.persistent_keepalive).bind(&peer.allowed_ips)
    .bind(&peer.expire_at).bind(&peer.created_at).bind(&peer.updated_at).bind(&peer.notes)
    .execute(&state.db)
    .await?;

    // Sync to WireGuard
    let _ = wg::sync_config(&state.db, &state.cfg).await;

    Ok(Json(peer))
}

/// GET /api/wireguard/peers/{id}
async fn get_peer(State(state): State<AppState>, Path(id): Path<String>) -> Result<Json<WireGuardPeer>> {
    let peer = sqlx::query_as::<_, WireGuardPeer>("SELECT * FROM wireguard_peers WHERE id = ?")
        .bind(&id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| AppError::NotFound("Peer not found".into()))?;
    Ok(Json(peer))
}

/// PUT /api/wireguard/peers/{id}
async fn update_peer(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdatePeerRequest>,
) -> Result<Json<WireGuardPeer>> {
    let mut peer = sqlx::query_as::<_, WireGuardPeer>("SELECT * FROM wireguard_peers WHERE id = ?")
        .bind(&id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| AppError::NotFound("Peer not found".into()))?;

    if let Some(name) = req.name { peer.name = name; }
    if let Some(enabled) = req.enabled { peer.enabled = enabled; }
    if let Some(dns) = req.dns { peer.dns = dns; }
    if let Some(ka) = req.persistent_keepalive { peer.persistent_keepalive = ka; }
    if let Some(ips) = req.allowed_ips { peer.allowed_ips = ips; }
    if let Some(exp) = req.expire_at { peer.expire_at = Some(exp); }
    if let Some(notes) = req.notes { peer.notes = Some(notes); }
    peer.updated_at = Utc::now().to_rfc3339();

    sqlx::query(
        "UPDATE wireguard_peers SET name=?, enabled=?, dns=?, persistent_keepalive=?, allowed_ips=?, expire_at=?, updated_at=?, notes=? WHERE id=?"
    )
    .bind(&peer.name).bind(peer.enabled).bind(&peer.dns).bind(peer.persistent_keepalive)
    .bind(&peer.allowed_ips).bind(&peer.expire_at).bind(&peer.updated_at).bind(&peer.notes)
    .bind(&peer.id)
    .execute(&state.db)
    .await?;

    let _ = wg::sync_config(&state.db, &state.cfg).await;
    Ok(Json(peer))
}

/// DELETE /api/wireguard/peers/{id}
async fn delete_peer(State(state): State<AppState>, Path(id): Path<String>) -> Result<Json<serde_json::Value>> {
    let peer = sqlx::query_as::<_, WireGuardPeer>("SELECT * FROM wireguard_peers WHERE id = ?")
        .bind(&id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| AppError::NotFound("Peer not found".into()))?;

    wg::remove_peer(&state.cfg.wg_interface, &peer.public_key).ok();
    sqlx::query("DELETE FROM wireguard_peers WHERE id = ?").bind(&id).execute(&state.db).await?;

    Ok(Json(json!({"success": true})))
}

/// POST /api/wireguard/peers/{id}/enable
async fn enable_peer(State(state): State<AppState>, Path(id): Path<String>) -> Result<Json<serde_json::Value>> {
    sqlx::query("UPDATE wireguard_peers SET enabled = 1, updated_at = ? WHERE id = ?")
        .bind(Utc::now().to_rfc3339()).bind(&id).execute(&state.db).await?;
    let _ = wg::sync_config(&state.db, &state.cfg).await;
    Ok(Json(json!({"success": true})))
}

/// POST /api/wireguard/peers/{id}/disable
async fn disable_peer(State(state): State<AppState>, Path(id): Path<String>) -> Result<Json<serde_json::Value>> {
    sqlx::query("UPDATE wireguard_peers SET enabled = 0, updated_at = ? WHERE id = ?")
        .bind(Utc::now().to_rfc3339()).bind(&id).execute(&state.db).await?;
    let _ = wg::sync_config(&state.db, &state.cfg).await;
    Ok(Json(json!({"success": true})))
}

/// GET /api/wireguard/peers/{id}/config — download WireGuard client config.
async fn download_config(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<(axum::http::StatusCode, [(String, String); 2], String)> {
    let peer = sqlx::query_as::<_, WireGuardPeer>("SELECT * FROM wireguard_peers WHERE id = ?")
        .bind(&id).fetch_optional(&state.db).await?
        .ok_or_else(|| AppError::NotFound("Peer not found".into()))?;

    let server_public_key = wg::get_server_private_key(&state.cfg)
        .and_then(|pk| wg::public_key_from_private(&pk))
        .unwrap_or_else(|_| "UNKNOWN".into());

    let config = wg::generate_client_config(&state.cfg, &peer, &server_public_key)?;
    let filename = format!("{}.conf", peer.name.replace(' ', "_"));

    Ok((
        axum::http::StatusCode::OK,
        [
            ("Content-Type".into(), "application/octet-stream".into()),
            ("Content-Disposition".into(), format!("attachment; filename=\"{}\"", filename)),
        ],
        config,
    ))
}

/// GET /api/wireguard/peers/{id}/qr — QR code PNG.
async fn get_qr(State(state): State<AppState>, Path(id): Path<String>) -> Result<(axum::http::StatusCode, [(String, String); 1], Vec<u8>)> {
    use qrcode::QrCode;
    use qrcode::render::svg;

    let peer = sqlx::query_as::<_, WireGuardPeer>("SELECT * FROM wireguard_peers WHERE id = ?")
        .bind(&id).fetch_optional(&state.db).await?
        .ok_or_else(|| AppError::NotFound("Peer not found".into()))?;

    let server_public_key = wg::get_server_private_key(&state.cfg)
        .and_then(|pk| wg::public_key_from_private(&pk))
        .unwrap_or_else(|_| "UNKNOWN".into());

    let config = wg::generate_client_config(&state.cfg, &peer, &server_public_key)?;
    let code = QrCode::new(&config).map_err(|e| AppError::Internal(e.to_string()))?;
    let svg_str = code.render::<qrcode::render::svg::Color>().build();
    Ok((
        axum::http::StatusCode::OK,
        [("Content-Type".into(), "image/svg+xml".into())],
        svg_str.into_bytes(),
    ))
}

/// POST /api/wireguard/peers/{id}/one-time-link
async fn create_one_time_link(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    // Verify peer exists
    sqlx::query_as::<_, WireGuardPeer>("SELECT * FROM wireguard_peers WHERE id = ?")
        .bind(&id).fetch_optional(&state.db).await?
        .ok_or_else(|| AppError::NotFound("Peer not found".into()))?;

    let token = Uuid::new_v4().to_string();
    let expires = (Utc::now() + chrono::Duration::minutes(5)).to_rfc3339();

    sqlx::query("INSERT INTO one_time_links (id, peer_id, expires_at, used, created_at) VALUES (?,?,?,0,?)")
        .bind(&token).bind(&id).bind(&expires).bind(Utc::now().to_rfc3339())
        .execute(&state.db).await?;

    Ok(Json(json!({
        "url": format!("https://{}/api/one-time/{}", state.cfg.external_hostname, token),
        "expires_at": expires,
    })))
}

/// GET /api/wireguard/stats
async fn get_stats(State(state): State<AppState>) -> Result<Json<serde_json::Value>> {
    let stats = wg::get_peer_stats(&state.cfg.wg_interface).unwrap_or_default();
    Ok(Json(json!({ "peers": stats })))
}

/// POST /api/wireguard/sync — manually trigger config sync.
async fn sync_config(State(state): State<AppState>) -> Result<Json<serde_json::Value>> {
    wg::sync_config(&state.db, &state.cfg).await?;
    Ok(Json(json!({"success": true})))
}
