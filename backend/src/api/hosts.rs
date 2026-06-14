//! Managed hosts API — CRUD, outbound assignment, per-host agent token.
use axum::{
    extract::{Path, State},
    Json, Router,
};
use axum::routing::{get, post, put};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::models::host::{
    Capabilities, ConfigProfile, CreateHostRequest, EnqueueCommandRequest, Host, HostCommand,
    UpdateHostRequest,
};
use crate::models::ProxyNode;
use crate::services::wireguard as wg;
use crate::AppState;

/// Commands the panel may enqueue for an agent to run.
const ALLOWED_COMMANDS: [&str; 2] = ["reload", "restart"];

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_hosts).post(create_host))
        .route("/profiles", get(list_profiles).post(create_profile))
        .route("/profiles/{pid}", get(get_profile).put(update_profile).delete(delete_profile))
        .route("/{id}", get(get_host).put(update_host).delete(delete_host))
        .route("/{id}/token", get(reveal_token))
        .route("/{id}/rotate-token", post(rotate_token))
        .route("/{id}/outbounds", put(set_outbounds).get(get_outbounds))
        .route("/{id}/wg-config", get(download_wg_config))
        .route("/{id}/commands", get(list_commands).post(enqueue_command))
}

/// Generate a fresh per-host agent token (64 hex chars).
fn new_agent_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

/// GET /api/hosts — list hosts with assigned-proxy counts.
async fn list_hosts(State(state): State<AppState>) -> Result<Json<Vec<serde_json::Value>>> {
    let hosts = sqlx::query_as::<_, Host>("SELECT * FROM hosts ORDER BY created_at")
        .fetch_all(&state.db)
        .await?;

    let mut out = Vec::with_capacity(hosts.len());
    for h in hosts {
        let count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM host_outbounds WHERE host_id = ?")
                .bind(&h.id)
                .fetch_one(&state.db)
                .await
                .unwrap_or((0,));
        let mut v = serde_json::to_value(&h).unwrap_or(json!({}));
        v["capabilities"] = serde_json::to_value(h.caps()).unwrap_or(json!({}));
        v["assigned_outbounds"] = json!(count.0);
        v["has_token"] = json!(!h.agent_token.is_empty());
        // Config drift: the agent is running a config whose ETag no longer matches
        // what the server would serve now (it hasn't repolled, or its reload failed).
        // Only meaningful for remote hosts that have reported a running etag.
        if !h.is_self() {
            if let Some(reported) = reported_etag(&h) {
                let expected = expected_config_etag(&state, &h).await;
                v["config_drift"] = json!(reported != expected);
            }
        }
        out.push(v);
    }
    Ok(Json(out))
}

/// POST /api/hosts — create a managed host. Returns the host plus its fresh token.
async fn create_host(
    State(state): State<AppState>,
    Json(req): Json<CreateHostRequest>,
) -> Result<Json<serde_json::Value>> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let caps = req.capabilities.unwrap_or(Capabilities {
        runs_singbox: true,
        is_wg_member: true,
        ..Default::default()
    });
    let caps_str = serde_json::to_string(&caps)?;
    let token = new_agent_token();
    let profile_id = req.profile_id.unwrap_or_else(|| "default".into());

    sqlx::query(
        "INSERT INTO hosts (id, name, agent_token, capabilities, profile_id, wg_address, wg_endpoint, clash_api, clash_secret, enabled, created_at, updated_at) \
         VALUES (?,?,?,?,?,?,?,?,?,1,?,?)",
    )
    .bind(&id)
    .bind(&req.name)
    .bind(&token)
    .bind(&caps_str)
    .bind(&profile_id)
    .bind(&req.wg_address)
    .bind(req.wg_endpoint.as_deref().filter(|e| !e.trim().is_empty()))
    .bind(&req.clash_api)
    .bind(req.clash_secret.unwrap_or_default())
    .bind(&now)
    .bind(&now)
    .execute(&state.db)
    .await?;

    // WG-member hosts join the intranet: provision a peer and auto-fill the WG
    // address / public key, plus a default Clash API reachable over the tunnel.
    if caps.is_wg_member {
        provision_wg(&state, &id, &req.name, req.clash_api.is_none()).await;
    }

    let host = fetch_host(&state, &id).await?;
    let mut v = serde_json::to_value(&host).unwrap_or(json!({}));
    v["capabilities"] = serde_json::to_value(host.caps()).unwrap_or(json!({}));
    v["has_token"] = json!(true);
    // Token is returned exactly once at creation so the admin can copy it.
    v["agent_token"] = json!(token);
    Ok(Json(v))
}

/// GET /api/hosts/{id}
async fn get_host(State(state): State<AppState>, Path(id): Path<String>) -> Result<Json<serde_json::Value>> {
    let host = fetch_host(&state, &id).await?;
    let mut v = serde_json::to_value(&host).unwrap_or(json!({}));
    v["capabilities"] = serde_json::to_value(host.caps()).unwrap_or(json!({}));
    v["has_token"] = json!(!host.agent_token.is_empty());
    Ok(Json(v))
}

/// PUT /api/hosts/{id}
async fn update_host(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateHostRequest>,
) -> Result<Json<serde_json::Value>> {
    let mut host = fetch_host(&state, &id).await?;
    let was_wg_member = host.caps().is_wg_member;

    if let Some(name) = req.name { host.name = name; }
    if let Some(caps) = req.capabilities { host.capabilities = serde_json::to_string(&caps)?; }
    if let Some(p) = req.profile_id { host.profile_id = Some(p); }
    if req.wg_address.is_some() { host.wg_address = req.wg_address; }
    if req.wg_public_key.is_some() { host.wg_public_key = req.wg_public_key; }
    if req.wg_endpoint.is_some() { host.wg_endpoint = req.wg_endpoint; }
    if req.clash_api.is_some() { host.clash_api = req.clash_api; }
    if let Some(s) = req.clash_secret { host.clash_secret = s; }
    if let Some(e) = req.enabled { host.enabled = e; }
    host.updated_at = Utc::now().to_rfc3339();

    sqlx::query(
        "UPDATE hosts SET name=?, capabilities=?, profile_id=?, wg_address=?, wg_public_key=?, wg_endpoint=?, clash_api=?, clash_secret=?, enabled=?, updated_at=? WHERE id=?",
    )
    .bind(&host.name).bind(&host.capabilities).bind(&host.profile_id)
    .bind(&host.wg_address).bind(&host.wg_public_key).bind(&host.wg_endpoint)
    .bind(&host.clash_api).bind(&host.clash_secret).bind(host.enabled)
    .bind(&host.updated_at).bind(&host.id)
    .execute(&state.db)
    .await?;

    // React to a WG-membership toggle: provision/deprovision the intranet peer.
    let is_wg_member = host.caps().is_wg_member;
    if is_wg_member && !was_wg_member && id != "self" {
        provision_wg(&state, &id, &host.name, host.clash_api.is_none()).await;
        host = fetch_host(&state, &id).await?;
    } else if !is_wg_member && was_wg_member {
        wg::deprovision_host_peer(&state.db, &state.cfg, &id).await;
    }

    let mut v = serde_json::to_value(&host).unwrap_or(json!({}));
    v["capabilities"] = serde_json::to_value(host.caps()).unwrap_or(json!({}));
    Ok(Json(v))
}

/// DELETE /api/hosts/{id} — the built-in `self` host cannot be deleted.
async fn delete_host(State(state): State<AppState>, Path(id): Path<String>) -> Result<Json<serde_json::Value>> {
    if id == "self" {
        return Err(AppError::BadRequest("Cannot delete the built-in self host".into()));
    }
    wg::deprovision_host_peer(&state.db, &state.cfg, &id).await;
    sqlx::query("DELETE FROM host_outbounds WHERE host_id = ?").bind(&id).execute(&state.db).await?;
    sqlx::query("DELETE FROM hosts WHERE id = ?").bind(&id).execute(&state.db).await?;
    Ok(Json(json!({"success": true})))
}

/// GET /api/hosts/{id}/wg-config — download the WG config the host installs.
async fn download_wg_config(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<(axum::http::StatusCode, [(String, String); 2], String)> {
    let host = fetch_host(&state, &id).await?;
    let config = wg::generate_host_wg_config(&state.db, &state.cfg, &id).await?;
    let filename = format!("{}-wg.conf", host.name.replace(' ', "_"));
    Ok((
        axum::http::StatusCode::OK,
        [
            ("Content-Type".into(), "application/octet-stream".into()),
            ("Content-Disposition".into(), format!("attachment; filename=\"{}\"", filename)),
        ],
        config,
    ))
}

/// Provision a WG peer for a host and back-fill its wg_address / wg_public_key,
/// and (when `set_clash`) a default Clash API URL reachable over the tunnel.
/// Best-effort: WG sync failures (e.g. no root in dev) don't fail the request.
async fn provision_wg(state: &AppState, host_id: &str, host_name: &str, set_clash: bool) {
    if let Ok((ip, pubkey)) = wg::provision_host_peer(&state.db, &state.cfg, host_id, host_name).await {
        let addr = format!("{ip}/32");
        let now = Utc::now().to_rfc3339();
        if set_clash {
            let clash = format!("http://{ip}:9090");
            let _ = sqlx::query("UPDATE hosts SET wg_address=?, wg_public_key=?, clash_api=?, updated_at=? WHERE id=?")
                .bind(&addr).bind(&pubkey).bind(&clash).bind(&now).bind(host_id).execute(&state.db).await;
        } else {
            let _ = sqlx::query("UPDATE hosts SET wg_address=?, wg_public_key=?, updated_at=? WHERE id=?")
                .bind(&addr).bind(&pubkey).bind(&now).bind(host_id).execute(&state.db).await;
        }
    }
}

/// GET /api/hosts/{id}/token — reveal the current agent token (admin only).
async fn reveal_token(State(state): State<AppState>, Path(id): Path<String>) -> Result<Json<serde_json::Value>> {
    let host = fetch_host(&state, &id).await?;
    Ok(Json(json!({
        "host_id": host.id,
        "agent_token": host.agent_token,
        "server": state.cfg.external_hostname,
    })))
}

/// POST /api/hosts/{id}/rotate-token — issue a new token, invalidating the old.
async fn rotate_token(State(state): State<AppState>, Path(id): Path<String>) -> Result<Json<serde_json::Value>> {
    let _ = fetch_host(&state, &id).await?;
    let token = new_agent_token();
    sqlx::query("UPDATE hosts SET agent_token=?, updated_at=? WHERE id=?")
        .bind(&token).bind(Utc::now().to_rfc3339()).bind(&id)
        .execute(&state.db).await?;
    Ok(Json(json!({ "host_id": id, "agent_token": token })))
}

#[derive(Deserialize)]
struct SetOutboundsRequest {
    node_ids: Vec<String>,
}

/// PUT /api/hosts/{id}/outbounds — replace this host's proxy assignments.
async fn set_outbounds(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<SetOutboundsRequest>,
) -> Result<Json<serde_json::Value>> {
    let _ = fetch_host(&state, &id).await?;
    let mut tx = state.db.begin().await?;
    sqlx::query("DELETE FROM host_outbounds WHERE host_id = ?").bind(&id).execute(&mut *tx).await?;
    for node_id in &req.node_ids {
        sqlx::query("INSERT OR IGNORE INTO host_outbounds (host_id, node_id) VALUES (?, ?)")
            .bind(&id).bind(node_id).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(Json(json!({ "host_id": id, "node_ids": req.node_ids })))
}

/// GET /api/hosts/{id}/outbounds — list assigned proxy node ids (empty = all enabled).
async fn get_outbounds(State(state): State<AppState>, Path(id): Path<String>) -> Result<Json<serde_json::Value>> {
    let _ = fetch_host(&state, &id).await?;
    let ids: Vec<(String,)> = sqlx::query_as("SELECT node_id FROM host_outbounds WHERE host_id = ?")
        .bind(&id).fetch_all(&state.db).await?;
    let node_ids: Vec<String> = ids.into_iter().map(|(n,)| n).collect();
    Ok(Json(json!({ "host_id": id, "node_ids": node_ids, "uses_all_when_empty": true })))
}

/// POST /api/hosts/{id}/commands — enqueue a command for the host's agent.
async fn enqueue_command(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<EnqueueCommandRequest>,
) -> Result<Json<serde_json::Value>> {
    let host = fetch_host(&state, &id).await?;
    if host.is_self() {
        return Err(AppError::BadRequest("The self host has no remote agent".into()));
    }
    let cmd = req.command.trim().to_lowercase();
    if !ALLOWED_COMMANDS.contains(&cmd.as_str()) {
        return Err(AppError::BadRequest(format!("Unknown command: {cmd}")));
    }
    let cmd_id = Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO host_commands (id, host_id, command, status, created_at) VALUES (?,?,?,'pending',?)")
        .bind(&cmd_id).bind(&id).bind(&cmd).bind(Utc::now().to_rfc3339())
        .execute(&state.db).await?;
    Ok(Json(json!({ "id": cmd_id, "command": cmd, "status": "pending" })))
}

/// GET /api/hosts/{id}/commands — recent commands and their status.
async fn list_commands(State(state): State<AppState>, Path(id): Path<String>) -> Result<Json<Vec<HostCommand>>> {
    let cmds = sqlx::query_as::<_, HostCommand>(
        "SELECT * FROM host_commands WHERE host_id = ? ORDER BY created_at DESC LIMIT 20",
    )
    .bind(&id)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(cmds))
}

/// GET /api/hosts/profiles — list config profiles.
async fn list_profiles(State(state): State<AppState>) -> Result<Json<Vec<ConfigProfile>>> {
    let profiles = sqlx::query_as::<_, ConfigProfile>("SELECT * FROM config_profiles ORDER BY name")
        .fetch_all(&state.db).await?;
    Ok(Json(profiles))
}

#[derive(Deserialize)]
struct ProfileRequest {
    name: String,
    /// 'managed' (config minus outbounds) or 'full' (complete config). Default managed.
    #[serde(default)]
    mode: Option<String>,
    /// sing-box config (full or minus-outbounds per mode). Must be a JSON object.
    template: serde_json::Value,
}

fn normalize_mode(m: Option<&str>) -> String {
    match m {
        Some("full") => "full".into(),
        _ => "managed".into(),
    }
}

/// Reject templates that aren't a JSON object (render injects `outbounds` into it).
fn validate_template(t: &serde_json::Value) -> Result<String> {
    if !t.is_object() {
        return Err(AppError::BadRequest("Profile template must be a JSON object".into()));
    }
    Ok(t.to_string())
}

/// GET /api/hosts/profiles/{pid}
async fn get_profile(State(state): State<AppState>, Path(pid): Path<String>) -> Result<Json<ConfigProfile>> {
    let p = sqlx::query_as::<_, ConfigProfile>("SELECT * FROM config_profiles WHERE id = ?")
        .bind(&pid).fetch_optional(&state.db).await?
        .ok_or_else(|| AppError::NotFound("Profile not found".into()))?;
    Ok(Json(p))
}

/// POST /api/hosts/profiles — create a config profile.
async fn create_profile(State(state): State<AppState>, Json(req): Json<ProfileRequest>) -> Result<Json<ConfigProfile>> {
    let template = validate_template(&req.template)?;
    let mode = normalize_mode(req.mode.as_deref());
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    sqlx::query("INSERT INTO config_profiles (id, name, template, mode, created_at, updated_at) VALUES (?,?,?,?,?,?)")
        .bind(&id).bind(&req.name).bind(&template).bind(&mode).bind(&now).bind(&now)
        .execute(&state.db).await?;
    get_profile(State(state), Path(id)).await
}

/// PUT /api/hosts/profiles/{pid}
async fn update_profile(State(state): State<AppState>, Path(pid): Path<String>, Json(req): Json<ProfileRequest>) -> Result<Json<ConfigProfile>> {
    let template = validate_template(&req.template)?;
    let exists = sqlx::query_as::<_, ConfigProfile>("SELECT * FROM config_profiles WHERE id = ?")
        .bind(&pid).fetch_optional(&state.db).await?;
    if exists.is_none() {
        return Err(AppError::NotFound("Profile not found".into()));
    }
    let mode = normalize_mode(req.mode.as_deref());
    sqlx::query("UPDATE config_profiles SET name=?, template=?, mode=?, updated_at=? WHERE id=?")
        .bind(&req.name).bind(&template).bind(&mode).bind(Utc::now().to_rfc3339()).bind(&pid)
        .execute(&state.db).await?;
    get_profile(State(state), Path(pid)).await
}

/// DELETE /api/hosts/profiles/{pid} — `default` is protected; hosts using the
/// deleted profile fall back to `default`.
async fn delete_profile(State(state): State<AppState>, Path(pid): Path<String>) -> Result<Json<serde_json::Value>> {
    if pid == "default" {
        return Err(AppError::BadRequest("Cannot delete the default profile".into()));
    }
    sqlx::query("UPDATE hosts SET profile_id = 'default' WHERE profile_id = ?").bind(&pid).execute(&state.db).await?;
    sqlx::query("DELETE FROM config_profiles WHERE id = ?").bind(&pid).execute(&state.db).await?;
    Ok(Json(json!({"success": true})))
}

async fn fetch_host(state: &AppState, id: &str) -> Result<Host> {
    sqlx::query_as::<_, Host>("SELECT * FROM hosts WHERE id = ?")
        .bind(id).fetch_optional(&state.db).await?
        .ok_or_else(|| AppError::NotFound("Host not found".into()))
}

/// Look up a host's config profile row (with mode), if any.
pub async fn host_profile(state: &AppState, host: &Host) -> Option<ConfigProfile> {
    let pid = host.profile_id.as_deref()?;
    sqlx::query_as::<_, ConfigProfile>("SELECT * FROM config_profiles WHERE id = ?")
        .bind(pid)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten()
}

/// Render a host's full config honoring its profile mode, then ensure a Clash
/// API is present (at `controller`/`secret`) so the panel can monitor it.
/// - 'full' mode: the profile template IS the complete config, run verbatim.
/// - 'managed' mode: template (config minus outbounds) + injected proxies.
pub async fn render_config_for(
    state: &AppState,
    host: &Host,
    controller: &str,
    secret: &str,
) -> serde_json::Value {
    use crate::services::proxy_config;
    let profile = host_profile(state, host).await;
    let mode = profile.as_ref().map(|p| p.mode.as_str()).unwrap_or("managed");

    let mut config = if mode == "full" {
        profile
            .as_ref()
            .and_then(|p| serde_json::from_str::<serde_json::Value>(&p.template).ok())
            .filter(|v| v.is_object())
            .unwrap_or_else(|| serde_json::json!({}))
    } else {
        let nodes = host_outbound_nodes(state, &host.id).await.unwrap_or_default();
        let template = host_profile_template(state, host).await;
        proxy_config::render_host_config(&template, &nodes)
    };

    proxy_config::inject_clash_api(&mut config, controller, secret);
    config
}

/// Render the exact config served to a (remote) host. Clash API listens at the
/// address the panel reaches it (host.clash_api) or all interfaces. Single
/// source of truth for the agent endpoint and drift detection.
pub async fn render_host_served(state: &AppState, host: &Host) -> serde_json::Value {
    use crate::services::proxy_config;
    let controller = host
        .clash_api
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .map(proxy_config::controller_addr)
        .unwrap_or_else(|| "0.0.0.0:9090".to_string());
    render_config_for(state, host, &controller, &host.clash_secret).await
}

/// Compute the ETag of the config the server would currently serve to a host.
pub async fn expected_config_etag(state: &AppState, host: &Host) -> String {
    let config = render_host_served(state, host).await;
    let config_str = serde_json::to_string_pretty(&config).unwrap_or_default();
    crate::services::proxy_config::config_etag(&host.id, &config_str, &state.cfg.config_hash_seed)
}

/// The ETag the agent last reported running (from singbox_state JSON), if any.
fn reported_etag(host: &Host) -> Option<String> {
    let st = host.singbox_state.as_ref()?;
    let v: serde_json::Value = serde_json::from_str(st).ok()?;
    v.get("etag").and_then(|e| e.as_str()).map(|s| s.to_string())
}

// ─── Shared helpers used by the agent endpoint ──────────────────────────────

/// Resolve the outbound proxies assigned to a host. A host with no explicit
/// assignments falls back to all enabled proxies (backward compatible).
pub async fn host_outbound_nodes(state: &AppState, host_id: &str) -> Result<Vec<ProxyNode>> {
    let assigned: Vec<ProxyNode> = sqlx::query_as::<_, ProxyNode>(
        "SELECT p.* FROM proxy_nodes p \
         JOIN host_outbounds h ON h.node_id = p.id \
         WHERE h.host_id = ? AND p.enabled = 1 \
         ORDER BY p.node_type, p.tag",
    )
    .bind(host_id)
    .fetch_all(&state.db)
    .await?;

    if !assigned.is_empty() {
        return Ok(assigned);
    }

    let all = sqlx::query_as::<_, ProxyNode>("SELECT * FROM proxy_nodes WHERE enabled = 1 ORDER BY node_type, tag")
        .fetch_all(&state.db)
        .await?;
    Ok(all)
}

/// Resolve which sing-box Clash API to talk to for live monitoring/control,
/// returning `(base_url, secret)`. A non-self `host` with a configured `clash_api`
/// is reached over the WG intranet; otherwise fall back to the local sing-box
/// (the `self` host) configured via env.
pub async fn resolve_clash_target(state: &AppState, host_id: Option<&str>) -> (String, String) {
    if let Some(id) = host_id.filter(|h| !h.is_empty() && *h != "self") {
        if let Ok(Some(h)) = sqlx::query_as::<_, Host>("SELECT * FROM hosts WHERE id = ?")
            .bind(id)
            .fetch_optional(&state.db)
            .await
        {
            if let Some(api) = h.clash_api.filter(|s| !s.trim().is_empty()) {
                return (api.trim_end_matches('/').to_string(), h.clash_secret);
            }
        }
    }
    (
        state.cfg.singbox_api_url.trim_end_matches('/').to_string(),
        state.cfg.singbox_api_secret.clone(),
    )
}

/// Resolve the profile template JSON for a host, falling back to the built-in default.
pub async fn host_profile_template(state: &AppState, host: &Host) -> serde_json::Value {
    if let Some(pid) = &host.profile_id {
        if let Ok(Some(p)) = sqlx::query_as::<_, ConfigProfile>("SELECT * FROM config_profiles WHERE id = ?")
            .bind(pid)
            .fetch_optional(&state.db)
            .await
        {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&p.template) {
                if v.is_object() {
                    return v;
                }
            }
        }
    }
    crate::services::proxy_config::default_profile_template()
}
