//! sb-easy-agent: Configuration sync agent for sing-box nodes.
//!
//! Polls the sb-easy server for the latest sing-box configuration,
//! downloads it when changed, and reloads sing-box.
//!
//! Usage: sb-easy-agent [--server URL] [--interval SECONDS]

use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result};
use serde_json::Value;
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
        .unwrap_or_else(|| "http://39.108.98.208:51821".to_string());

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
        match poll_config(&client, &server_url, &mut last_etag).await {
            Ok(Some(config)) => {
                // Write config
                match tokio::fs::write(&config_path, &config).await {
                    Ok(_) => {
                        info!("Config written to {config_path}, reloading sing-box...");
                        // Reload sing-box
                        let parts: Vec<&str> = reload_cmd.split_whitespace().collect();
                        let (cmd, args) = parts.split_first().unwrap_or((&"echo", &["reload"] as &[&str]));
                        let output = Command::new(cmd).args(args).output();
                        match output {
                            Ok(o) if o.status.success() => info!("sing-box reloaded successfully"),
                            Ok(o) => warn!("reload failed: {}", String::from_utf8_lossy(&o.stderr)),
                            Err(e) => error!("reload command failed: {e}"),
                        }
                    }
                    Err(e) => error!("Failed to write config: {e}"),
                }
            }
            Ok(None) => {
                // 304 Not Modified — config unchanged
            }
            Err(e) => {
                error!("Poll error: {e}");
            }
        }

        tokio::time::sleep(Duration::from_secs(interval_secs)).await;
    }
}

async fn poll_config(
    client: &reqwest::Client,
    server_url: &str,
    last_etag: &mut Option<String>,
) -> Result<Option<String>> {
    let url = format!("{}/api/agent/config", server_url.trim_end_matches('/'));
    let mut req = client.get(&url).timeout(Duration::from_secs(15));

    if let Some(ref etag) = last_etag {
        req = req.header("If-None-Match", etag);
    }

    let response = req.send().await.context("Failed to reach sb-easy server")?;

    if response.status() == reqwest::StatusCode::NOT_MODIFIED {
        // Config unchanged
        return Ok(None);
    }

    if !response.status().is_success() {
        error!("Server returned {}", response.status());
        return Ok(None);
    }

    // Store new ETag
    if let Some(etag) = response.headers().get("etag").and_then(|v| v.to_str().ok()) {
        *last_etag = Some(etag.to_string());
    }

    let config = response.text().await.context("Failed to read config")?;
    Ok(Some(config))
}
