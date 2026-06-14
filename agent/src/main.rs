//! sb-easy-agent: standalone configuration sync agent for sing-box hosts.
//!
//! DEPRECATED: prefer `sb-easy agent` (the agent folded into the main binary),
//! which also supervises sing-box in process so a node runs only one thing.
//! This standalone binary is kept for compatibility; it writes the config and
//! runs an external reload command instead of supervising sing-box.
//!
//! Authenticates with its per-host `AGENT_TOKEN`, polls the sb-easy server for
//! this host's sing-box configuration, writes it when changed, reloads sing-box,
//! and reports status back on each cycle.

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

    // Poll interval. Shorter = lower config-change latency (the panel pushes no
    // signal; the agent discovers changes by polling with ETag/304). Clamped to a
    // 2s floor so a misconfiguration can't hammer the server.
    let interval_secs: u64 = std::env::var("AGENT_INTERVAL")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10)
        .max(2);

    let config_path = std::env::var("SINGBOX_CONFIG_PATH")
        .unwrap_or_else(|_| "/etc/sing-box/config.d/90-generated.json".to_string());

    let reload_cmd = std::env::var("RELOAD_CMD")
        .unwrap_or_else(|_| "sudo systemctl reload sing-box".to_string());

    let restart_cmd = std::env::var("RESTART_CMD")
        .unwrap_or_else(|_| "sudo systemctl restart sing-box".to_string());

    info!("sb-easy-agent starting");
    info!("  server: {server_url}");
    info!("  interval: {interval_secs}s");
    info!("  config_path: {config_path}");
    info!("  reload_cmd: {reload_cmd}");
    info!("  restart_cmd: {restart_cmd}");

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

        // Run any pending downlink commands (reload / restart). Best-effort.
        if let Err(e) = run_commands(&client, &server_url, &agent_token, &reload_cmd, &restart_cmd).await {
            warn!("command poll failed: {e}");
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
    run_shell_command(reload_cmd).map(|_| true).unwrap_or(false)
}

/// Run a whitespace-split command; Ok(stdout/empty) on success, Err(detail) otherwise.
fn run_shell_command(cmd_line: &str) -> std::result::Result<String, String> {
    let parts: Vec<&str> = cmd_line.split_whitespace().collect();
    let (cmd, args) = parts.split_first().unwrap_or((&"echo", &["noop"] as &[&str]));
    match Command::new(cmd).args(args).output() {
        Ok(o) if o.status.success() => Ok(String::from_utf8_lossy(&o.stdout).trim().to_string()),
        Ok(o) => Err(String::from_utf8_lossy(&o.stderr).trim().to_string()),
        Err(e) => Err(e.to_string()),
    }
}

/// Pull pending commands, execute each, and ack the result.
async fn run_commands(
    client: &reqwest::Client,
    server_url: &str,
    token: &str,
    reload_cmd: &str,
    restart_cmd: &str,
) -> Result<()> {
    let url = format!("{}/api/agent/commands", server_url.trim_end_matches('/'));
    let resp = client
        .get(&url)
        .bearer_auth(token)
        .timeout(Duration::from_secs(15))
        .send()
        .await
        .context("fetch commands")?;
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
        let outcome = match command.as_str() {
            "reload" => run_shell_command(reload_cmd),
            "restart" => run_shell_command(restart_cmd),
            other => Err(format!("unknown command: {other}")),
        };
        let (status, result) = match outcome {
            Ok(out) => ("done", out),
            Err(e) => {
                warn!("command {command} failed: {e}");
                ("failed", e)
            }
        };
        let ack_url = format!("{}/api/agent/commands/{}/ack", server_url.trim_end_matches('/'), id);
        let _ = client
            .post(&ack_url)
            .bearer_auth(token)
            .json(&serde_json::json!({ "status": status, "result": result }))
            .timeout(Duration::from_secs(10))
            .send()
            .await;
    }
    Ok(())
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
