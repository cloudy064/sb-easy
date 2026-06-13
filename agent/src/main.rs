//! sb-easy-agent: Configuration sync agent for sing-box hosts.
//!
//! Authenticates with its per-host `AGENT_TOKEN`, polls the sb-easy server for
//! this host's sing-box configuration, writes it when changed, reloads sing-box,
//! and reports status back on each cycle.
//!
//! Usage: sb-easy-agent [--server URL] [--interval SECONDS]

use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result};
use tracing::{error, info, warn};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "info".into()))
        .init();

    // Load .env if present
    let _ = dotenvy::dotenv();

    let server_url = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("SB_EASY_SERVER").ok())
        .unwrap_or_else(|| "http://127.0.0.1:51821".to_string());

    // Per-host token provisioned when the host was created in the panel.
    // Required: the server rejects unauthenticated config requests with 401.
    let agent_token = std::env::var("AGENT_TOKEN").unwrap_or_default();
    if agent_token.trim().is_empty() {
        warn!("AGENT_TOKEN is empty — the server will reject requests (401). Set it to this host's token.");
    }

    let interval_secs: u64 = std::env::var("AGENT_INTERVAL")
        .unwrap_or_else(|_| "30".into())
        .parse()
        .unwrap_or(30);

    let config_path = std::env::var("SINGBOX_CONFIG_PATH")
        .unwrap_or_else(|_| "/etc/sing-box/config.d/90-generated.json".to_string());

    let reload_cmd = std::env::var("RELOAD_CMD")
        .unwrap_or_else(|_| "sudo systemctl reload sing-box".to_string());

    info!("sb-easy-agent starting");
    info!("  server: {server_url}");
    info!("  interval: {interval_secs}s");
    info!("  config_path: {config_path}");
    info!("  reload_cmd: {reload_cmd}");

    let client = reqwest::Client::new();
    let mut last_etag: Option<String> = None;

    loop {
        let mut singbox_running: Option<bool> = None;
        match poll_config(&client, &server_url, &agent_token, &mut last_etag).await {
            Ok(Some(config)) => match tokio::fs::write(&config_path, &config).await {
                Ok(_) => {
                    info!("Config written to {config_path}, reloading sing-box...");
                    singbox_running = Some(reload_singbox(&reload_cmd));
                }
                Err(e) => {
                    error!("Failed to write config: {e}");
                    singbox_running = Some(false);
                }
            },
            Ok(None) => { /* 304 Not Modified — config unchanged */ }
            Err(e) => error!("Poll error: {e}"),
        }

        // Best-effort heartbeat; failures here must not stop the loop.
        if let Err(e) = report_status(
            &client,
            &server_url,
            &agent_token,
            last_etag.as_deref(),
            singbox_running,
        )
        .await
        {
            warn!("status report failed: {e}");
        }

        tokio::time::sleep(Duration::from_secs(interval_secs)).await;
    }
}

/// Run the configured reload command; returns whether it succeeded.
fn reload_singbox(reload_cmd: &str) -> bool {
    let parts: Vec<&str> = reload_cmd.split_whitespace().collect();
    let (cmd, args) = parts.split_first().unwrap_or((&"echo", &["reload"] as &[&str]));
    match Command::new(cmd).args(args).output() {
        Ok(o) if o.status.success() => {
            info!("sing-box reloaded successfully");
            true
        }
        Ok(o) => {
            warn!("reload failed: {}", String::from_utf8_lossy(&o.stderr));
            false
        }
        Err(e) => {
            error!("reload command failed: {e}");
            false
        }
    }
}

async fn poll_config(
    client: &reqwest::Client,
    server_url: &str,
    token: &str,
    last_etag: &mut Option<String>,
) -> Result<Option<String>> {
    let url = format!("{}/api/agent/config", server_url.trim_end_matches('/'));
    let mut req = client
        .get(&url)
        .bearer_auth(token)
        .timeout(Duration::from_secs(15));

    if let Some(ref etag) = last_etag {
        req = req.header("If-None-Match", etag);
    }

    let response = req.send().await.context("Failed to reach sb-easy server")?;

    if response.status() == reqwest::StatusCode::NOT_MODIFIED {
        return Ok(None);
    }

    if !response.status().is_success() {
        error!("Server returned {}", response.status());
        return Ok(None);
    }

    if let Some(etag) = response.headers().get("etag").and_then(|v| v.to_str().ok()) {
        *last_etag = Some(etag.to_string());
    }

    let config = response.text().await.context("Failed to read config")?;
    Ok(Some(config))
}

/// Report a heartbeat with the current config etag and sing-box run state.
async fn report_status(
    client: &reqwest::Client,
    server_url: &str,
    token: &str,
    etag: Option<&str>,
    singbox_running: Option<bool>,
) -> Result<()> {
    let url = format!("{}/api/agent/status", server_url.trim_end_matches('/'));
    let body = serde_json::json!({
        "singbox_version": option_env!("CARGO_PKG_VERSION"),
        "singbox_running": singbox_running,
        "config_etag": etag,
    });
    client
        .post(&url)
        .bearer_auth(token)
        .json(&body)
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .context("Failed to POST status")?;
    Ok(())
}
