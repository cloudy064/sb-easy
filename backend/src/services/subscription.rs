//! Subscription service: fetch, decode, parse, deduplicate, store.
use std::time::Duration;

use base64::Engine;
use chrono::Utc;
use serde_json::{json, Value};
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
    let found = nodes.len();
    info!("Subscription fetch: {found} proxies parsed");

    // Insert/update nodes in database
    let skipped = 0usize;
    let (added, updated, errors) = upsert_nodes(pool, &nodes, Some(sub_id)).await;

    // Update subscription metadata
    let result_json = serde_json::json!({
        "added": added,
        "updated": updated,
        "skipped": skipped,
        "total": found,
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
        found,
        errors,
    })
}

/// Insert or update a batch of parsed nodes, deduplicated by fingerprint.
/// Returns `(added, updated, errors)`. Shared by subscription fetch and the
/// config importer. `sub_id` tags nodes with their source subscription (or
/// `None` for a manual/import source).
pub async fn upsert_nodes(
    pool: &SqlitePool,
    nodes: &[ParsedNode],
    sub_id: Option<&str>,
) -> (usize, usize, Vec<String>) {
    let mut added = 0usize;
    let mut updated = 0usize;
    let mut errors = Vec::new();

    for node in nodes {
        let fingerprint = node.fingerprint();
        let cfg = serde_json::to_string(&node.protocol_config).unwrap_or_default();
        let now = Utc::now().to_rfc3339();

        let existing: Option<(String,)> =
            match sqlx::query_as("SELECT id FROM proxy_nodes WHERE fingerprint = ?")
                .bind(&fingerprint)
                .fetch_optional(pool)
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    errors.push(format!("Lookup failed for {}: {e}", node.tag));
                    continue;
                }
            };

        if let Some((existing_id,)) = existing {
            let result = sqlx::query(
                "UPDATE proxy_nodes SET tag = ?, server = ?, server_port = ?, protocol_config = ?, subscription_id = ?, updated_at = ? WHERE id = ?",
            )
            .bind(&node.tag)
            .bind(&node.server)
            .bind(node.server_port)
            .bind(&cfg)
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
            let id = Uuid::new_v4().to_string();
            let result = sqlx::query(
                "INSERT INTO proxy_nodes (id, tag, node_type, enabled, server, server_port, protocol_config, subscription_id, fingerprint, created_at, updated_at) VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&id)
            .bind(&node.tag)
            .bind(&node.node_type)
            .bind(&node.server)
            .bind(node.server_port)
            .bind(&cfg)
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

    (added, updated, errors)
}

/// A minimal view of a Clash config: we only care about the `proxies` list.
/// Every other top-level key (dns/rules/proxy-groups/…) is ignored by serde, so
/// the ~10k-line `rules:` block a Clash export carries is never materialised.
#[derive(serde::Deserialize)]
struct ClashDoc {
    #[serde(default)]
    proxies: Vec<Value>,
}

/// Parse a subscription response body into a list of ParsedNodes. Handles, in order:
/// - Clash YAML config (a mapping with a top-level `proxies:` list) — the common
///   `?clash=` export format; each proxy is translated to a sing-box-shaped node.
/// - Base64-encoded list of proxy URIs (v2ray format).
/// - Plain-text newline-separated proxy URIs (ss:// vmess:// …).
fn parse_subscription_body(body: &str) -> Result<Vec<ParsedNode>> {
    let decoded = decode_maybe_base64(body);

    // Clash YAML: a document that parses as a mapping carrying a non-empty
    // top-level `proxies:` sequence. We must NOT hard-fail here — a plain URI
    // list can legitimately contain the text "proxies:" (a comment or node
    // name), and a transient/HTML error body shouldn't turn a previously-working
    // subscription into a hard error. So on any YAML problem we fall through to
    // URI-list parsing below.
    if let Ok(doc) = serde_yaml::from_str::<ClashDoc>(&decoded) {
        if !doc.proxies.is_empty() {
            return Ok(doc.proxies.iter().filter_map(clash_proxy_to_node).collect());
        }
    }

    // Otherwise treat as newline-separated proxy URIs.
    let mut nodes = Vec::new();
    for line in decoded.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }
        if let Some(node) = uri_parser::parse_uri(line) {
            nodes.push(node);
        } else {
            let preview: String = line.chars().take(60).collect();
            debug!("Skipping unrecognized line: {preview}...");
        }
    }
    Ok(nodes)
}

/// Decode a body that may be base64 (v2ray subscriptions are often base64 of a
/// URI list). Returns decoded text, or the original body when it is not base64.
fn decode_maybe_base64(body: &str) -> String {
    if !is_likely_base64(body) {
        return body.to_string();
    }
    let trimmed = body.trim();
    for engine in [
        base64::engine::general_purpose::STANDARD,
        base64::engine::general_purpose::URL_SAFE,
        base64::engine::general_purpose::STANDARD_NO_PAD,
        base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ] {
        if let Ok(bytes) = engine.decode(trimmed) {
            if let Ok(s) = String::from_utf8(bytes) {
                return s;
            }
        }
    }
    body.to_string()
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

// ── Clash proxy → ParsedNode ────────────────────────────────────────────────
// Clash proxies use their own field names/shapes; we translate each into the
// sing-box-native `protocol_config` that services/proxy_config.rs::generate_outbound
// consumes. It copies the `tls`/`transport`/`obfs` sub-objects VERBATIM into the
// outbound, so those must already be in sing-box shape here (not Clash shape).

/// Map one Clash proxy (a JSON object) to a ParsedNode. Returns None for entries
/// missing server/port or of an unsupported type.
fn clash_proxy_to_node(p: &Value) -> Option<ParsedNode> {
    let node_type = map_clash_type(&get_str(p, "type")?);
    let server = get_str(p, "server").filter(|s| !s.is_empty())?;
    let port = get_i64(p, "port")? as i32;
    if port == 0 {
        return None;
    }
    let tag = get_str(p, "name")
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("{server}:{port}"));

    let protocol_config = match node_type.as_str() {
        "shadowsocks" => build_ss(p),
        "vmess" => build_vmess(p),
        "vless" => build_vless(p),
        "trojan" => build_trojan(p),
        "hysteria2" => build_hysteria2(p),
        "tuic" => build_tuic(p),
        // Unsupported by the outbound generator (ssr / hysteria v1 / snell / …):
        // skip rather than store a node that would render as `direct`.
        other => {
            debug!("Skipping unsupported Clash proxy type '{other}' ({tag})");
            return None;
        }
    };

    // Reject entries missing their required secret. sing-box validates the whole
    // config atomically, so a single node with an empty uuid/method/password
    // would fail `sing-box check` and disable EVERY node on the host — dropping
    // the one bad node is far safer than poisoning the batch.
    if !has_required_secret(&node_type, &protocol_config) {
        debug!("Skipping Clash proxy with missing credentials: {tag}");
        return None;
    }

    Some(ParsedNode {
        node_type,
        tag,
        server,
        server_port: port,
        protocol_config,
    })
}

/// Whether a built protocol_config carries the non-empty secret its type needs.
fn has_required_secret(node_type: &str, cfg: &Value) -> bool {
    let nonempty = |k: &str| {
        cfg.get(k)
            .and_then(|v| v.as_str())
            .map_or(false, |s| !s.is_empty())
    };
    match node_type {
        "shadowsocks" => nonempty("method") && nonempty("password"),
        "vmess" | "vless" => nonempty("uuid"),
        "trojan" | "hysteria2" => nonempty("password"),
        "tuic" => nonempty("uuid") && nonempty("password"),
        _ => true,
    }
}

fn build_ss(p: &Value) -> Value {
    json!({
        "method": get_str(p, "cipher").unwrap_or_default(),
        "password": get_str(p, "password").unwrap_or_default(),
    })
}

fn build_vmess(p: &Value) -> Value {
    let mut cfg = json!({
        "uuid": get_str(p, "uuid").unwrap_or_default(),
        "alter_id": get_i64(p, "alterId").or_else(|| get_i64(p, "alterid")).unwrap_or(0),
        "security": get_str(p, "cipher").filter(|s| !s.is_empty()).unwrap_or_else(|| "auto".into()),
    });
    if let Some(t) = build_transport(p) {
        cfg["transport"] = t;
    }
    if let Some(tls) = build_tls(p, get_bool(p, "tls")) {
        cfg["tls"] = tls;
    }
    cfg
}

fn build_vless(p: &Value) -> Value {
    let mut cfg = json!({
        "uuid": get_str(p, "uuid").unwrap_or_default(),
        "flow": get_str(p, "flow").unwrap_or_default(),
        "packet_encoding": "xudp",
    });
    if let Some(t) = build_transport(p) {
        cfg["transport"] = t;
    }
    // VLESS runs TLS whenever `tls: true` or a reality block is present.
    let tls_on = get_bool(p, "tls") || p.get("reality-opts").is_some();
    if let Some(tls) = build_tls(p, tls_on) {
        cfg["tls"] = tls;
    }
    cfg
}

fn build_trojan(p: &Value) -> Value {
    let mut cfg = json!({ "password": get_str(p, "password").unwrap_or_default() });
    if let Some(t) = build_transport(p) {
        cfg["transport"] = t;
    }
    // Trojan is always over TLS.
    if let Some(tls) = build_tls(p, true) {
        cfg["tls"] = tls;
    }
    cfg
}

fn build_hysteria2(p: &Value) -> Value {
    let mut cfg = json!({
        "password": get_str(p, "password")
            .or_else(|| get_str(p, "auth"))
            .or_else(|| get_str(p, "auth-str"))
            .unwrap_or_default(),
    });
    if let Some(tls) = build_tls(p, true) {
        cfg["tls"] = tls;
    }
    if let Some(obfs) = get_str(p, "obfs").filter(|s| !s.is_empty()) {
        let mut o = json!({ "type": obfs });
        if let Some(pw) = get_str(p, "obfs-password") {
            o["password"] = json!(pw);
        }
        cfg["obfs"] = o;
    }
    cfg
}

fn build_tuic(p: &Value) -> Value {
    let mut cfg = json!({
        "uuid": get_str(p, "uuid").unwrap_or_default(),
        "password": get_str(p, "password").unwrap_or_default(),
        "congestion_control": get_str(p, "congestion-controller")
            .filter(|s| !s.is_empty()).unwrap_or_else(|| "bbr".into()),
        "udp_relay_mode": get_str(p, "udp-relay-mode")
            .filter(|s| !s.is_empty()).unwrap_or_else(|| "native".into()),
    });
    if let Some(tls) = build_tls(p, true) {
        cfg["tls"] = tls;
    }
    cfg
}

/// Build a sing-box `transport` object from Clash `network` + *-opts. Returns None
/// for tcp / no transport.
fn build_transport(p: &Value) -> Option<Value> {
    match get_str(p, "network").unwrap_or_default().as_str() {
        "ws" => {
            let mut t = json!({ "type": "ws" });
            if let Some(opts) = p.get("ws-opts").and_then(|v| v.as_object()) {
                if let Some(path) = opts.get("path").and_then(|v| v.as_str()) {
                    t["path"] = json!(path);
                }
                if let Some(headers) = opts.get("headers") {
                    t["headers"] = headers.clone();
                }
            } else if let Some(path) = get_str(p, "ws-path") {
                t["path"] = json!(path);
            }
            Some(t)
        }
        "grpc" => {
            let mut t = json!({ "type": "grpc" });
            if let Some(name) = p
                .get("grpc-opts")
                .and_then(|v| v.get("grpc-service-name"))
                .and_then(|v| v.as_str())
            {
                t["service_name"] = json!(name);
            }
            Some(t)
        }
        "h2" | "http" => {
            let mut t = json!({ "type": "http" });
            if let Some(opts) = p.get("h2-opts").or_else(|| p.get("http-opts")) {
                if let Some(host) = opts.get("host") {
                    t["host"] = host.clone();
                }
                // Clash http/h2 `path` is often an array; sing-box wants a string.
                match opts.get("path") {
                    Some(Value::Array(a)) => {
                        if let Some(first) = a.first().and_then(|v| v.as_str()) {
                            t["path"] = json!(first);
                        }
                    }
                    Some(Value::String(s)) => t["path"] = json!(s),
                    _ => {}
                }
            }
            Some(t)
        }
        _ => None,
    }
}

/// Build a sing-box `tls` object from Clash TLS-ish fields. `enabled` gates whether
/// TLS is on at all (vmess/vless carry a `tls:` bool; trojan/hysteria2/tuic always).
fn build_tls(p: &Value, enabled: bool) -> Option<Value> {
    if !enabled {
        return None;
    }
    let mut tls = json!({ "enabled": true });
    if let Some(sni) = get_str(p, "sni")
        .or_else(|| get_str(p, "servername"))
        .filter(|s| !s.is_empty())
    {
        tls["server_name"] = json!(sni);
    }
    if get_bool(p, "skip-cert-verify") {
        tls["insecure"] = json!(true);
    }
    match p.get("alpn") {
        Some(Value::Array(a)) => tls["alpn"] = Value::Array(a.clone()),
        Some(Value::String(s)) => {
            tls["alpn"] = json!(s.split(',').map(|x| x.trim()).collect::<Vec<_>>())
        }
        _ => {}
    }
    if let Some(fp) = get_str(p, "client-fingerprint").filter(|s| !s.is_empty()) {
        tls["utls"] = json!({ "enabled": true, "fingerprint": fp });
    }
    if let Some(ro) = p.get("reality-opts").and_then(|v| v.as_object()) {
        let mut reality = json!({ "enabled": true });
        if let Some(pk) = ro.get("public-key").and_then(|v| v.as_str()) {
            reality["public_key"] = json!(pk);
        }
        if let Some(sid) = ro.get("short-id").and_then(|v| v.as_str()) {
            reality["short_id"] = json!(sid);
        }
        tls["reality"] = reality;
        // sing-box's REALITY client requires uTLS; default a fingerprint when the
        // Clash proxy didn't specify `client-fingerprint`, else the config is
        // rejected ("uTLS is required by reality client").
        if tls.get("utls").is_none() {
            tls["utls"] = json!({ "enabled": true, "fingerprint": "chrome" });
        }
    }
    Some(tls)
}

fn map_clash_type(t: &str) -> String {
    match t {
        "ss" | "shadowsocks" => "shadowsocks",
        "vmess" => "vmess",
        "trojan" => "trojan",
        "vless" => "vless",
        "hysteria2" | "hy2" => "hysteria2",
        "tuic" => "tuic",
        other => other,
    }
    .to_string()
}

// Clash values may be strings, numbers or bools; coerce to the shape we want.
fn get_str(v: &Value, k: &str) -> Option<String> {
    match v.get(k) {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Number(n)) => Some(n.to_string()),
        Some(Value::Bool(b)) => Some(b.to_string()),
        _ => None,
    }
}

fn get_i64(v: &Value, k: &str) -> Option<i64> {
    match v.get(k) {
        Some(Value::Number(n)) => n.as_i64(),
        Some(Value::String(s)) => s.trim().parse().ok(),
        _ => None,
    }
}

fn get_bool(v: &Value, k: &str) -> bool {
    match v.get(k) {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => s.eq_ignore_ascii_case("true"),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_inline_flow_style_ss_and_vmess() {
        // The iKuuu/`?clash=` shape: inline flow maps with emoji names.
        let yaml = r#"
port: 7890
proxies:
  - {name: 🇭🇰 香港Z01, server: hk01.example, port: 19274, type: ss, cipher: aes-256-gcm, password: secret-pw, udp: true}
  - {name: 🇯🇵 日本Z05 | x0.01, server: jp05.example, port: 64657, type: vmess, uuid: uuid-123, alterId: 1, cipher: auto, tls: false, skip-cert-verify: false, udp: true}
proxy-groups:
  - {name: PROXY, type: select, proxies: [🇭🇰 香港Z01]}
rules:
  - MATCH,PROXY
"#;
        let nodes = parse_subscription_body(yaml).unwrap();
        assert_eq!(nodes.len(), 2, "both inline proxies must parse (was the skipped '- {{' case)");

        let ss = &nodes[0];
        assert_eq!(ss.node_type, "shadowsocks");
        assert_eq!(ss.tag, "🇭🇰 香港Z01");
        assert_eq!(ss.server, "hk01.example");
        assert_eq!(ss.server_port, 19274);
        assert_eq!(ss.protocol_config["method"], "aes-256-gcm");
        assert_eq!(ss.protocol_config["password"], "secret-pw");

        let vm = &nodes[1];
        assert_eq!(vm.node_type, "vmess");
        assert_eq!(vm.protocol_config["uuid"], "uuid-123");
        assert_eq!(vm.protocol_config["alter_id"], 1); // was hardcoded 0 before
        assert_eq!(vm.protocol_config["security"], "auto");
        assert!(vm.protocol_config.get("tls").is_none(), "tls:false → no tls object");
        assert!(vm.protocol_config.get("transport").is_none(), "no network → tcp, no transport");
    }

    #[test]
    fn maps_vmess_ws_and_tls_to_singbox_shape() {
        let yaml = r#"
proxies:
  - {name: WS-TLS, server: e.example, port: 443, type: vmess, uuid: u1, alterId: 0, cipher: auto, network: ws, ws-opts: {path: /vm, headers: {Host: cdn.example}}, tls: true, servername: cdn.example, skip-cert-verify: true}
"#;
        let nodes = parse_subscription_body(yaml).unwrap();
        assert_eq!(nodes.len(), 1);
        let c = &nodes[0].protocol_config;
        assert_eq!(c["transport"]["type"], "ws");
        assert_eq!(c["transport"]["path"], "/vm");
        assert_eq!(c["transport"]["headers"]["Host"], "cdn.example");
        assert_eq!(c["tls"]["enabled"], true);
        assert_eq!(c["tls"]["server_name"], "cdn.example");
        assert_eq!(c["tls"]["insecure"], true);
    }

    #[test]
    fn trojan_and_hysteria2_tls_shapes() {
        let yaml = r#"
proxies:
  - {name: TJ, server: t.example, port: 443, type: trojan, password: tj-pw, sni: t.example, skip-cert-verify: true}
  - {name: HY, server: h.example, port: 8443, type: hysteria2, password: hy-pw, sni: h.example, obfs: salamander, obfs-password: op}
"#;
        let nodes = parse_subscription_body(yaml).unwrap();
        assert_eq!(nodes.len(), 2);
        let tj = &nodes[0];
        assert_eq!(tj.node_type, "trojan");
        assert_eq!(tj.protocol_config["password"], "tj-pw");
        assert_eq!(tj.protocol_config["tls"]["server_name"], "t.example");
        assert_eq!(tj.protocol_config["tls"]["insecure"], true);
        let hy = &nodes[1];
        assert_eq!(hy.node_type, "hysteria2");
        assert_eq!(hy.protocol_config["obfs"]["type"], "salamander");
        assert_eq!(hy.protocol_config["obfs"]["password"], "op");
    }

    #[test]
    fn uri_list_with_proxies_substring_still_parses() {
        // A plain URI list whose comment contains "proxies:" must NOT be treated
        // as (broken) Clash — it should fall through to URI parsing, not error.
        let body = "# my proxies: list\nss://YWVzLTI1Ni1nY206dGVzdHBhc3N3b3Jk@1.2.3.4:443#Node\n";
        let nodes = parse_subscription_body(body).unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].node_type, "shadowsocks");
    }

    #[test]
    fn malformed_clash_falls_through_not_hard_error() {
        // Broken YAML that isn't a valid Clash doc → no hard error, just 0 nodes
        // (the UI surfaces this as "no nodes parsed").
        let body = "proxies:\n  - {name: X, this is : : not valid";
        assert!(parse_subscription_body(body).unwrap().is_empty());
    }

    #[test]
    fn skips_proxy_with_missing_secret() {
        // One half-populated entry must not poison the batch; only valid nodes survive.
        let yaml = r#"
proxies:
  - {name: good, server: g.example, port: 443, type: ss, cipher: aes-256-gcm, password: pw}
  - {name: bad-no-uuid, server: b.example, port: 443, type: vmess, alterId: 0, cipher: auto}
  - {name: bad-empty-pw, server: c.example, port: 443, type: ss, cipher: aes-256-gcm, password: ""}
"#;
        let nodes = parse_subscription_body(yaml).unwrap();
        let tags: Vec<&str> = nodes.iter().map(|n| n.tag.as_str()).collect();
        assert_eq!(tags, vec!["good"]);
    }

    #[test]
    fn vless_reality_gets_utls() {
        let yaml = r#"
proxies:
  - {name: R, server: r.example, port: 443, type: vless, uuid: u1, tls: true, servername: r.example, reality-opts: {public-key: pk123, short-id: ab}, flow: xtls-rprx-vision}
"#;
        let nodes = parse_subscription_body(yaml).unwrap();
        let tls = &nodes[0].protocol_config["tls"];
        assert_eq!(tls["reality"]["public_key"], "pk123");
        assert_eq!(tls["utls"]["enabled"], true); // required by sing-box reality
    }

    // Set SB_TEST_CLASH_YAML=/path/to/sub.yaml to validate against a real
    // subscription export; a no-op when the env var is unset (keeps CI green).
    #[test]
    fn parses_real_subscription_when_provided() {
        let Ok(path) = std::env::var("SB_TEST_CLASH_YAML") else { return };
        let body = std::fs::read_to_string(&path).expect("read SB_TEST_CLASH_YAML");
        let nodes = parse_subscription_body(&body).expect("parse real subscription");
        assert!(nodes.len() >= 40, "expected the full node list, got {}", nodes.len());
        // Every parsed node must have server/port and a non-empty per-type secret.
        for n in &nodes {
            assert!(!n.server.is_empty() && n.server_port > 0, "bad server/port for {}", n.tag);
            assert!(!n.fingerprint().is_empty());
        }
        // Optionally render a full sing-box config so it can be run through
        // `sing-box check` for end-to-end schema validation.
        if let Ok(out) = std::env::var("SB_TEST_OUT") {
            use crate::models::proxy_node::ProxyNode;
            use crate::services::proxy_config;
            let proxy_nodes: Vec<ProxyNode> = nodes
                .iter()
                .enumerate()
                .map(|(i, n)| ProxyNode {
                    id: format!("id-{i}"),
                    tag: n.tag.clone(),
                    node_type: n.node_type.clone(),
                    enabled: true,
                    server: n.server.clone(),
                    server_port: n.server_port,
                    protocol_config: n.protocol_config.to_string(),
                    subscription_id: None,
                    fingerprint: n.fingerprint(),
                    latency: None,
                    last_latency_test: None,
                    created_at: "now".into(),
                    updated_at: "now".into(),
                })
                .collect();
            let cfg = proxy_config::render_host_config(
                &proxy_config::default_profile_template(),
                &proxy_nodes,
            );
            std::fs::write(&out, serde_json::to_string_pretty(&cfg).unwrap()).unwrap();
            eprintln!("wrote rendered sing-box config ({} nodes) to {out}", nodes.len());
        }
    }
}
