//! Agent run mode: `sb-easy agent`.
//!
//! Lets a managed node run the SAME `sb-easy` binary instead of a separate
//! `sb-easy-agent`. It connects to a remote panel, pulls this host's config,
//! supervises sing-box in process (Route A), runs queued commands, and reports
//! status — so a client machine also only runs/manages one thing.

use std::time::Duration;

use anyhow::{Context, Result};
use tracing::{error, info, warn};

use crate::services::singbox_supervisor::{Singbox, DEFAULT_CONFIG_PATH};

pub async fn run() -> Result<()> {
    let server = std::env::var("SB_EASY_SERVER")
        .context("SB_EASY_SERVER must be set in agent mode (URL of the panel)")?;
    let token = std::env::var("AGENT_TOKEN").unwrap_or_default();
    if token.trim().is_empty() {
        warn!("AGENT_TOKEN is empty — the panel will reject requests (401). Set this host's token.");
    }
    let bin = std::env::var("SINGBOX_BIN").unwrap_or_else(|_| "sing-box".into());
    let path = std::env::var("SINGBOX_CONFIG_PATH")
        .or_else(|_| std::env::var("SELF_SINGBOX_CONFIG_PATH"))
        .unwrap_or_else(|_| DEFAULT_CONFIG_PATH.into());
    let interval = std::env::var("AGENT_INTERVAL")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10u64)
        .max(2);

    info!("sb-easy agent mode → server={server} config={path} bin={bin} (every {interval}s)");

    let client = reqwest::Client::new();
    let mut sb = Singbox::new(bin, path);
    let mut last_etag: Option<String> = None;

    loop {
        match poll_config(&client, &server, &token, last_etag.as_deref()).await {
            Ok(Some((etag, body))) => {
                if let Err(e) = sb.apply(&body).await {
                    error!("failed to apply config: {e}");
                } else {
                    last_etag = Some(etag);
                }
            }
            Ok(None) => {}
            Err(e) => error!("config poll: {e}"),
        }

        sb.ensure_alive();

        if let Err(e) = run_commands(&client, &server, &token, &mut sb).await {
            warn!("command poll: {e}");
        }

        let running = sb.is_alive();
        if let Err(e) = report_status(&client, &server, &token, last_etag.as_deref(), running).await {
            warn!("status report: {e}");
        }

        tokio::time::sleep(Duration::from_secs(interval)).await;
    }
}

/// GET the host config; Ok(Some((etag, body))) on change, Ok(None) on 304.
async fn poll_config(
    client: &reqwest::Client,
    server: &str,
    token: &str,
    last_etag: Option<&str>,
) -> Result<Option<(String, String)>> {
    let url = format!("{}/api/agent/config", server.trim_end_matches('/'));
    let mut req = client.get(&url).bearer_auth(token).timeout(Duration::from_secs(15));
    if let Some(etag) = last_etag {
        req = req.header("If-None-Match", etag);
    }
    let resp = req.send().await.context("reach panel")?;
    if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
        return Ok(None);
    }
    if !resp.status().is_success() {
        anyhow::bail!("panel returned {}", resp.status());
    }
    let etag = resp
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let body = resp.text().await.context("read config body")?;
    Ok(Some((etag, body)))
}

/// Pull pending commands, run them against the supervised sing-box, and ack.
async fn run_commands(
    client: &reqwest::Client,
    server: &str,
    token: &str,
    sb: &mut Singbox,
) -> Result<()> {
    let url = format!("{}/api/agent/commands", server.trim_end_matches('/'));
    let resp = client.get(&url).bearer_auth(token).timeout(Duration::from_secs(15)).send().await?;
    if !resp.status().is_success() {
        return Ok(());
    }
    let commands: Vec<serde_json::Value> = resp.json().await.unwrap_or_default();
    for c in commands {
        let id = c["id"].as_str().unwrap_or_default().to_string();
        let command = c["command"].as_str().unwrap_or_default().to_string();
        if id.is_empty() {
            continue;
        }
        info!("running command: {command}");
        let (status, result) = match command.as_str() {
            "reload" => {
                sb.reload_now();
                ("done", "reloaded".to_string())
            }
            "restart" => {
                sb.restart().await;
                ("done", "restarted".to_string())
            }
            other => ("failed", format!("unknown command: {other}")),
        };
        let ack = format!("{}/api/agent/commands/{}/ack", server.trim_end_matches('/'), id);
        let _ = client
            .post(&ack)
            .bearer_auth(token)
            .json(&serde_json::json!({ "status": status, "result": result }))
            .timeout(Duration::from_secs(10))
            .send()
            .await;
    }
    Ok(())
}

async fn report_status(
    client: &reqwest::Client,
    server: &str,
    token: &str,
    etag: Option<&str>,
    running: bool,
) -> Result<()> {
    let url = format!("{}/api/agent/status", server.trim_end_matches('/'));
    let body = serde_json::json!({
        "singbox_version": option_env!("CARGO_PKG_VERSION"),
        "singbox_running": running,
        "config_etag": etag,
    });
    client
        .post(&url)
        .bearer_auth(token)
        .json(&body)
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .context("post status")?;
    Ok(())
}
