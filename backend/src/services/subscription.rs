//! Subscription service: fetch, decode, parse, deduplicate, store.
use std::time::Duration;

use base64::Engine;
use chrono::Utc;
use sqlx::SqlitePool;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::models::subscription::FetchResult;
use crate::services::uri_parser::{self, ParsedNode};

/// Fetch a subscription URL, parse all proxy URIs, deduplicate vs existing nodes, store.
pub async fn fetch_subscription(
    pool: &SqlitePool,
    sub_id: &str,
    sub_url: &str,
) -> Result<FetchResult> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("sb-easy/0.1")
        .build()
        .map_err(|e| AppError::Internal(format!("HTTP client error: {e}")))?;

    // Fetch the subscription
    let response = client
        .get(sub_url)
        .send()
        .await
        .map_err(|e| AppError::BadRequest(format!("Failed to fetch subscription: {e}")))?;

    let body = response
        .text()
        .await
        .map_err(|e| AppError::BadRequest(format!("Failed to read response: {e}")))?;

    // Detect format and parse
    let nodes = parse_subscription_body(&body)?;
    let total = nodes.len();
    info!("Subscription fetch: {total} nodes found");

    // Insert/update nodes in database
    let mut added = 0usize;
    let mut updated = 0usize;
    let mut skipped = 0usize;
    let mut errors = Vec::new();

    for node in nodes {
        let fingerprint = node.fingerprint();

        // Check if node already exists by fingerprint
        let existing: Option<(String,)> = sqlx::query_as(
            "SELECT id FROM proxy_nodes WHERE fingerprint = ?"
        )
        .bind(&fingerprint)
        .fetch_optional(pool)
        .await?;

        if let Some((existing_id,)) = existing {
            // Update existing node
            let now = Utc::now().to_rfc3339();
            let result = sqlx::query(
                "UPDATE proxy_nodes SET tag = ?, server = ?, server_port = ?, protocol_config = ?, subscription_id = ?, updated_at = ? WHERE id = ?"
            )
            .bind(&node.tag)
            .bind(&node.server)
            .bind(node.server_port)
            .bind(serde_json::to_string(&node.protocol_config).unwrap_or_default())
            .bind(sub_id)
            .bind(&now)
            .bind(&existing_id)
            .execute(pool)
            .await;

            match result {
                Ok(_) => updated += 1,
                Err(e) => errors.push(format!("Failed to update {}: {e}", node.tag)),
            }
        } else {
            // Insert new node
            let id = Uuid::new_v4().to_string();
            let now = Utc::now().to_rfc3339();
            let result = sqlx::query(
                "INSERT INTO proxy_nodes (id, tag, node_type, enabled, server, server_port, protocol_config, subscription_id, fingerprint, created_at, updated_at) VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)"
            )
            .bind(&id)
            .bind(&node.tag)
            .bind(&node.node_type)
            .bind(&node.server)
            .bind(node.server_port)
            .bind(serde_json::to_string(&node.protocol_config).unwrap_or_default())
            .bind(sub_id)
            .bind(&fingerprint)
            .bind(&now)
            .bind(&now)
            .execute(pool)
            .await;

            match result {
                Ok(_) => added += 1,
                Err(e) => errors.push(format!("Failed to insert {}: {e}", node.tag)),
            }
        }
    }

    // Update subscription metadata
    let result_json = serde_json::json!({
        "added": added,
        "updated": updated,
        "skipped": skipped,
        "total": total,
        "errors": errors,
    });

    let now = Utc::now().to_rfc3339();
    sqlx::query(
        "UPDATE subscriptions SET last_fetched_at = ?, last_fetch_result = ? WHERE id = ?"
    )
    .bind(&now)
    .bind(serde_json::to_string(&result_json).unwrap_or_default())
    .bind(sub_id)
    .execute(pool)
    .await?;

    info!(
        "Subscription processed: {} added, {} updated, {} errors",
        added, updated, errors.len()
    );

    Ok(FetchResult {
        added,
        updated,
        skipped,
        errors,
    })
}

/// Parse a subscription response body into a list of ParsedNodes.
/// Handles:
/// - Base64-encoded list of proxy URIs (v2ray format)
/// - Plain text list of proxy URIs
/// - Clash YAML (basic support: proxies array)
fn parse_subscription_body(body: &str) -> Result<Vec<ParsedNode>> {
    // Check if base64-encoded
    let decoded = if is_likely_base64(body) {
        let mut decoded_str = String::new();
        // Try standard base64
        if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(body.trim()) {
            decoded_str = String::from_utf8(decoded).unwrap_or_default();
        }
        if decoded_str.is_empty() {
            // Try URL-safe
            if let Ok(decoded) = base64::engine::general_purpose::URL_SAFE.decode(body.trim()) {
                decoded_str = String::from_utf8(decoded).unwrap_or_default();
            }
        }
        if decoded_str.is_empty() {
            body.to_string()
        } else {
            decoded_str
        }
    } else {
        body.to_string()
    };

    // Try Clash YAML first (if starts with "proxies:" or has yaml-like structure)
    if decoded.trim().starts_with("proxies:") || decoded.contains("type: ss") || decoded.contains("type: vmess") {
        return parse_clash_yaml_proxies(&decoded);
    }

    // Otherwise treat as newline-separated proxy URIs
    let mut nodes = Vec::new();
    for line in decoded.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }
        if let Some(node) = uri_parser::parse_uri(line) {
            nodes.push(node);
        } else {
            debug!("Skipping unrecognized line: {}...", &line[..line.len().min(60)]);
        }
    }

    Ok(nodes)
}

/// Rough check if text looks like base64.
fn is_likely_base64(s: &str) -> bool {
    let s = s.trim();
    // Base64 contains only A-Z, a-z, 0-9, +, /, = (and possibly -_ for URL-safe)
    let valid = s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '-' || c == '_' || c == '=');
    valid && s.len() > 20 && !s.contains(' ') && !s.contains('\n')
}

/// Minimal Clash YAML proxy list parser - extracts proxies from a Clash config.
fn parse_clash_yaml_proxies(yaml: &str) -> Result<Vec<ParsedNode>> {
    let mut nodes = Vec::new();
    let mut in_proxies = false;
    let mut current: Option<ProxyBuilder> = None;

    for line in yaml.lines() {
        let trimmed = line.trim();

        if trimmed == "proxies:" || trimmed.starts_with("proxies:") {
            in_proxies = true;

            // Flush any previous node
            if let Some(builder) = current.take() {
                if let Some(node) = builder.build() {
                    nodes.push(node);
                }
            }
            continue;
        }

        if !in_proxies {
            continue;
        }

        // Detect new proxy entry: "- name:" or "- {"
        if trimmed.starts_with("- name:") {
            // Flush previous
            if let Some(builder) = current.take() {
                if let Some(node) = builder.build() {
                    nodes.push(node);
                }
            }
            current = Some(ProxyBuilder::new());
            let name = trimmed.strip_prefix("- name:").unwrap_or("").trim().trim_matches('"').to_string();
            if let Some(ref mut b) = current {
                b.tag = name;
            }
        } else if trimmed.starts_with("- {") {
            // Inline JSON-like node, skip for now
            if let Some(builder) = current.take() {
                if let Some(node) = builder.build() {
                    nodes.push(node);
                }
            }
            current = None;
        } else if let Some(ref mut b) = current {
            if trimmed.starts_with("type:") {
                b.node_type = trimmed.strip_prefix("type:").unwrap_or("").trim().trim_matches('"').to_string();
            } else if trimmed.starts_with("server:") {
                b.server = trimmed.strip_prefix("server:").unwrap_or("").trim().trim_matches('"').to_string();
            } else if trimmed.starts_with("port:") {
                b.port = trimmed.strip_prefix("port:").unwrap_or("0").trim().parse().unwrap_or(0);
            } else if trimmed.starts_with("cipher:") || trimmed.starts_with("method:") {
                b.method = trimmed.split(':').nth(1).unwrap_or("").trim().trim_matches('"').to_string();
            } else if trimmed.starts_with("password:") {
                b.password = trimmed.strip_prefix("password:").unwrap_or("").trim().trim_matches('"').to_string();
            } else if trimmed.starts_with("uuid:") {
                b.uuid = trimmed.strip_prefix("uuid:").unwrap_or("").trim().trim_matches('"').to_string();
            }
        }
    }

    // Flush last
    if let Some(builder) = current.take() {
        if let Some(node) = builder.build() {
            nodes.push(node);
        }
    }

    Ok(nodes)
}

#[derive(Default)]
struct ProxyBuilder {
    tag: String,
    node_type: String,
    server: String,
    port: i32,
    method: String,
    password: String,
    uuid: String,
}

impl ProxyBuilder {
    fn new() -> Self { Self::default() }

    fn build(&self) -> Option<ParsedNode> {
        if self.server.is_empty() || self.port == 0 || self.node_type.is_empty() {
            return None;
        }

        let protocol_config = match self.node_type.as_str() {
            "ss" | "shadowsocks" => serde_json::json!({
                "method": self.method,
                "password": self.password,
            }),
            "vmess" => serde_json::json!({
                "uuid": self.uuid,
                "alter_id": 0,
                "security": "auto",
            }),
            "trojan" => serde_json::json!({
                "password": self.password,
                "tls": { "enabled": true }
            }),
            _ => serde_json::json!({}),
        };

        Some(ParsedNode {
            tag: if self.tag.is_empty() { format!("{}:{}", self.server, self.port) } else { self.tag.clone() },
            node_type: map_clash_type(&self.node_type),
            server: self.server.clone(),
            server_port: self.port,
            protocol_config,
        })
    }
}

fn map_clash_type(t: &str) -> String {
    match t {
        "ss" => "shadowsocks",
        "vmess" => "vmess",
        "trojan" => "trojan",
        "vless" => "vless",
        "hysteria2" | "hy2" => "hysteria2",
        "tuic" => "tuic",
        other => other,
    }.to_string()
}
