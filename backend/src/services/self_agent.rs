//! In-process "agent" for the built-in `self` host.
//!
//! The central server can itself run sing-box (the `self` host). Rather than run
//! a separate agent process against localhost, this loop manages that config in
//! process: it polls the `self` host's effective config, and when the rendered
//! ETag changes it writes the file and reloads sing-box — the same poll/ETag/
//! write/reload model the remote agent uses, just without HTTP.
//!
//! Opt-in: disabled unless `SELF_SINGBOX_CONFIG_PATH` is set, so existing
//! deployments are unaffected.

use std::process::Command;
use std::time::Duration;

use tracing::{error, info, warn};

use crate::api::hosts::{host_outbound_nodes, host_profile_template};
use crate::models::Host;
use crate::services::proxy_config;
use crate::AppState;

/// Run the self-host config loop forever. Returns immediately (logging why) when
/// auto-apply is disabled.
pub async fn run(state: AppState) {
    let path = state.cfg.self_singbox_config_path.trim().to_string();
    if path.is_empty() {
        info!("self sing-box auto-apply disabled (set SELF_SINGBOX_CONFIG_PATH to enable)");
        return;
    }
    let interval = Duration::from_secs(state.cfg.self_singbox_interval);
    info!(
        "self sing-box auto-apply enabled: {path} (every {}s)",
        state.cfg.self_singbox_interval
    );

    let mut last_etag = String::new();
    loop {
        match render_self(&state).await {
            Some((etag, config_str)) if etag != last_etag => {
                match tokio::fs::write(&path, &config_str).await {
                    Ok(_) => {
                        info!("self sing-box config changed → wrote {path}, reloading");
                        reload(&state.cfg.self_reload_cmd);
                        last_etag = etag;
                    }
                    Err(e) => error!("self config write to {path} failed: {e}"),
                }
            }
            _ => {}
        }
        tokio::time::sleep(interval).await;
    }
}

/// Render the self host's config and its ETag, or None if self isn't an enabled
/// sing-box host. Shared with the in-process sing-box supervisor.
pub async fn render_self(state: &AppState) -> Option<(String, String)> {
    let host = sqlx::query_as::<_, Host>("SELECT * FROM hosts WHERE id = 'self'")
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten()?;
    if !host.enabled || !host.caps().runs_singbox {
        return None;
    }
    let nodes = host_outbound_nodes(state, "self").await.ok()?;
    let template = host_profile_template(state, &host).await;
    let config = proxy_config::render_host_config(&template, &nodes);
    let config_str = serde_json::to_string_pretty(&config).unwrap_or_default();
    let etag = proxy_config::config_etag("self", &config_str, &state.cfg.config_hash_seed);
    Some((etag, config_str))
}

/// Run the configured reload command (whitespace-split, no shell).
fn reload(reload_cmd: &str) {
    let parts: Vec<&str> = reload_cmd.split_whitespace().collect();
    let Some((cmd, args)) = parts.split_first() else { return };
    match Command::new(cmd).args(args).output() {
        Ok(o) if o.status.success() => info!("self sing-box reloaded"),
        Ok(o) => warn!("self reload failed: {}", String::from_utf8_lossy(&o.stderr)),
        Err(e) => error!("self reload command failed: {e}"),
    }
}
