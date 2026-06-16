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
    let mut sb = Singbox::new(bin, path.clone());
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

        if let Err(e) = run_commands(&client, &server, &token, &mut sb, &path).await {
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
    config_path: &str,
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
        // `test-proxies` may carry an optional JSON array of tags to test a
        // subset (e.g. a single node's re-test); bare = test every proxy.
        let (status, result): (&str, String) = if command == "reload" {
            sb.reload_now();
            ("done", "reloaded".to_string())
        } else if command == "restart" {
            sb.restart().await;
            ("done", "restarted".to_string())
        } else if command == "test-proxies" || command.starts_with("test-proxies ") {
            let tags: Option<Vec<String>> = command
                .strip_prefix("test-proxies")
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .and_then(|s| serde_json::from_str(s).ok());
            match test_proxies(client, server, token, config_path, tags.as_deref()).await {
                Ok(n) => ("done", format!("tested {n} proxies")),
                Err(e) => ("failed", format!("test-proxies: {e}")),
            }
        } else {
            ("failed", format!("unknown command: {command}"))
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

/// Delay-test the locally-running sing-box's proxies, one at a time, reporting
/// each result to the panel as it completes so the UI fills in progressively.
/// `tags` limits the test to a subset (a single node's re-test); `None` = all.
/// Returns the number of proxies tested. Clash controller/secret are read from
/// the running config so we always match what sing-box actually serves.
async fn test_proxies(
    client: &reqwest::Client,
    server: &str,
    token: &str,
    config_path: &str,
    tags: Option<&[String]>,
) -> Result<usize> {
    let cfg_str = tokio::fs::read_to_string(config_path)
        .await
        .with_context(|| format!("read config {config_path}"))?;
    let cfg: serde_json::Value = serde_json::from_str(&cfg_str).context("parse config")?;
    let controller = cfg
        .pointer("/experimental/clash_api/external_controller")
        .and_then(|v| v.as_str())
        .unwrap_or("127.0.0.1:9090");
    let secret = cfg
        .pointer("/experimental/clash_api/secret")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    // A wildcard controller bind is reached locally via loopback.
    let base = format!("http://{}", controller.replace("0.0.0.0", "127.0.0.1").replace("[::]", "127.0.0.1"));

    let proxies = clash_get(client, &base, &secret, "/proxies").await?;
    let map = proxies
        .get("proxies")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();

    // Skip groups (they carry an `all` array) and built-in outbounds.
    const SKIP: &[&str] = &[
        "Selector", "URLTest", "Fallback", "LoadBalance", "Direct", "Reject",
        "Compatible", "Pass", "Dns", "Block", "Loopback",
    ];
    let names: Vec<String> = map
        .iter()
        .filter(|(name, p)| {
            let ty = p.get("type").and_then(|v| v.as_str()).unwrap_or("");
            let is_proxy = !SKIP.contains(&ty) && p.get("all").is_none();
            let wanted = tags.map(|t| t.iter().any(|x| x == *name)).unwrap_or(true);
            is_proxy && wanted
        })
        .map(|(name, _)| name.clone())
        .collect();

    let url = format!("{}/api/agent/proxy-latency", server.trim_end_matches('/'));
    let mut tested = 0usize;
    for name in &names {
        let path = format!(
            "/proxies/{}/delay?url={}&timeout=5000",
            crate::util::encode_query_component(name),
            crate::util::encode_query_component("https://www.gstatic.com/generate_204"),
        );
        let delay = clash_get(client, &base, &secret, &path)
            .await
            .ok()
            .and_then(|v| v.get("delay").and_then(|d| d.as_f64()));
        let value = delay.map(|d| serde_json::json!(d)).unwrap_or(serde_json::Value::Null);
        // Report this node's result immediately (progressive UI fill-in).
        let _ = client
            .post(&url)
            .bearer_auth(token)
            .json(&serde_json::json!({ "results": { name: value } }))
            .timeout(Duration::from_secs(10))
            .send()
            .await;
        tested += 1;
    }
    Ok(tested)
}

/// GET a Clash API path with the optional bearer secret, parsing JSON (or `{}`).
async fn clash_get(
    client: &reqwest::Client,
    base: &str,
    secret: &str,
    path: &str,
) -> Result<serde_json::Value> {
    let mut req = client.get(format!("{base}{path}")).timeout(Duration::from_secs(8));
    if !secret.is_empty() {
        req = req.bearer_auth(secret);
    }
    let resp = req.send().await.context("reach clash api")?;
    Ok(resp.json().await.unwrap_or(serde_json::json!({})))
}
