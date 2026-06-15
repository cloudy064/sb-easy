//! Parse sing-box outbound JSON back into structured nodes — the inverse of
//! `proxy_config::generate_outbound`. Used to import an existing config (e.g. a
//! full-mode profile's `outbounds`, or a pasted sing-box config) into the
//! structured `proxy_nodes` model so the panel becomes the source of truth.
//!
//! Importing is purely additive: it populates the node list and never touches a
//! running config. The fields we extract mirror exactly what `generate_outbound`
//! reads, and `tls`/`transport` are preserved verbatim, so re-rendering a parsed
//! node reproduces the original outbound (verified by the round-trip tests).

use serde_json::{json, Value};

use crate::services::uri_parser::ParsedNode;

/// Outbound `type`s that map to a structured proxy node. Everything else
/// (selector/urltest groups, direct/block/dns/...) is skipped.
const PROXY_TYPES: &[&str] = &["shadowsocks", "vmess", "vless", "trojan", "hysteria2", "tuic"];

#[derive(Debug, Default)]
pub struct ImportParse {
    pub nodes: Vec<ParsedNode>,
    /// Proxy-type outbounds we recognised but could not parse (missing server/port),
    /// formatted as "tag (type)". Groups and built-ins are skipped silently.
    pub skipped: Vec<String>,
}

/// Extract proxy nodes from a sing-box config value. Accepts either an object
/// with an `outbounds` array, or a bare array of outbounds.
pub fn parse_config(config: &Value) -> ImportParse {
    let outbounds = if let Some(arr) = config.get("outbounds").and_then(|v| v.as_array()) {
        arr.as_slice()
    } else if let Some(arr) = config.as_array() {
        arr.as_slice()
    } else {
        return ImportParse::default();
    };

    let mut out = ImportParse::default();
    for ob in outbounds {
        let ty = ob.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if !PROXY_TYPES.contains(&ty) {
            continue; // group or built-in outbound — not a node
        }
        match parse_outbound(ob) {
            Some(n) => out.nodes.push(n),
            None => {
                let tag = ob.get("tag").and_then(|v| v.as_str()).unwrap_or("?");
                out.skipped.push(format!("{tag} ({ty})"));
            }
        }
    }
    out
}

fn port_of(ob: &Value) -> Option<i32> {
    match ob.get("server_port") {
        Some(Value::Number(n)) => n.as_i64().map(|x| x as i32),
        Some(Value::String(s)) => s.parse().ok(),
        _ => None,
    }
}

/// Parse one outbound. Returns `None` for unsupported types or when the required
/// server/port are missing.
fn parse_outbound(ob: &Value) -> Option<ParsedNode> {
    let ty = ob.get("type")?.as_str()?.to_string();
    let server = ob.get("server")?.as_str()?.to_string();
    let server_port = port_of(ob)?;
    let tag = ob
        .get("tag")
        .and_then(|v| v.as_str())
        .unwrap_or(&server)
        .to_string();

    let mut cfg = serde_json::Map::new();
    match ty.as_str() {
        "shadowsocks" => {
            cfg.insert("method".into(), ob.get("method").cloned().unwrap_or(Value::Null));
            cfg.insert("password".into(), ob.get("password").cloned().unwrap_or(Value::Null));
        }
        "vmess" => {
            cfg.insert("uuid".into(), ob.get("uuid").cloned().unwrap_or(Value::Null));
            cfg.insert("alter_id".into(), ob.get("alter_id").cloned().unwrap_or(json!(0)));
            cfg.insert("security".into(), ob.get("security").cloned().unwrap_or(json!("auto")));
        }
        "vless" => {
            cfg.insert("uuid".into(), ob.get("uuid").cloned().unwrap_or(Value::Null));
            cfg.insert("flow".into(), ob.get("flow").cloned().unwrap_or(json!("")));
            cfg.insert(
                "packet_encoding".into(),
                ob.get("packet_encoding").cloned().unwrap_or(json!("xudp")),
            );
        }
        "trojan" => {
            cfg.insert("password".into(), ob.get("password").cloned().unwrap_or(Value::Null));
        }
        "hysteria2" => {
            cfg.insert("password".into(), ob.get("password").cloned().unwrap_or(Value::Null));
            if let Some(o) = ob.get("obfs") {
                cfg.insert("obfs".into(), o.clone());
            }
        }
        "tuic" => {
            cfg.insert("uuid".into(), ob.get("uuid").cloned().unwrap_or(Value::Null));
            cfg.insert("password".into(), ob.get("password").cloned().unwrap_or(Value::Null));
            if let Some(v) = ob.get("congestion_control") {
                cfg.insert("congestion_control".into(), v.clone());
            }
            if let Some(v) = ob.get("udp_relay_mode") {
                cfg.insert("udp_relay_mode".into(), v.clone());
            }
        }
        _ => return None,
    }

    // Preserve TLS / transport verbatim (shadowsocks carries neither) so that
    // re-rendering via generate_outbound reproduces the original exactly.
    if ty != "shadowsocks" {
        if let Some(tls) = ob.get("tls") {
            cfg.insert("tls".into(), tls.clone());
        }
        if let Some(tr) = ob.get("transport") {
            cfg.insert("transport".into(), tr.clone());
        }
    }

    Some(ParsedNode {
        node_type: ty,
        tag,
        server,
        server_port,
        protocol_config: Value::Object(cfg),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::proxy_node::ProxyNode;
    use crate::services::proxy_config::generate_outbound;

    fn node_from(parsed: &ParsedNode) -> ProxyNode {
        ProxyNode {
            id: "x".into(),
            tag: parsed.tag.clone(),
            node_type: parsed.node_type.clone(),
            enabled: true,
            server: parsed.server.clone(),
            server_port: parsed.server_port,
            protocol_config: serde_json::to_string(&parsed.protocol_config).unwrap(),
            subscription_id: None,
            fingerprint: String::new(),
            latency: None,
            last_latency_test: None,
            created_at: String::new(),
            updated_at: String::new(),
        }
    }

    /// Parse an outbound then re-render it; the result must equal the original.
    fn assert_roundtrip(original: Value) {
        let parse = parse_config(&json!({ "outbounds": [original.clone()] }));
        assert_eq!(parse.nodes.len(), 1, "expected one node from {original}");
        let rendered = generate_outbound(&node_from(&parse.nodes[0]));
        assert_eq!(rendered, original, "round-trip mismatch");
    }

    #[test]
    fn roundtrip_shadowsocks() {
        assert_roundtrip(json!({
            "type": "shadowsocks", "tag": "SS HK", "server": "1.2.3.4",
            "server_port": 8388, "method": "aes-256-gcm", "password": "pw"
        }));
    }

    #[test]
    fn roundtrip_vless_with_tls_and_transport() {
        assert_roundtrip(json!({
            "type": "vless", "tag": "VLESS", "server": "a.example.com", "server_port": 443,
            "uuid": "11111111-1111-1111-1111-111111111111", "flow": "xtls-rprx-vision",
            "packet_encoding": "xudp",
            "tls": { "enabled": true, "server_name": "a.example.com",
                     "utls": { "enabled": true, "fingerprint": "chrome" } },
            "transport": { "type": "ws", "path": "/ray", "headers": { "Host": "a.example.com" } }
        }));
    }

    #[test]
    fn roundtrip_trojan_and_hysteria2_and_tuic() {
        assert_roundtrip(json!({
            "type": "trojan", "tag": "TJ", "server": "t.example.com", "server_port": 443,
            "password": "pw", "tls": { "enabled": true, "server_name": "t.example.com" }
        }));
        assert_roundtrip(json!({
            "type": "hysteria2", "tag": "HY2", "server": "h.example.com", "server_port": 443,
            "password": "pw", "tls": { "enabled": true, "server_name": "h.example.com" },
            "obfs": { "type": "salamander", "password": "x" }
        }));
        assert_roundtrip(json!({
            "type": "tuic", "tag": "TUIC", "server": "u.example.com", "server_port": 443,
            "uuid": "22222222-2222-2222-2222-222222222222", "password": "pw",
            "congestion_control": "bbr", "udp_relay_mode": "native",
            "tls": { "enabled": true, "server_name": "u.example.com", "alpn": ["h3"] }
        }));
    }

    #[test]
    fn groups_and_builtins_are_skipped() {
        let cfg = json!({ "outbounds": [
            { "type": "selector", "tag": "Proxy", "outbounds": ["a", "b"] },
            { "type": "urltest", "tag": "Auto", "outbounds": ["a"] },
            { "type": "direct", "tag": "direct" },
            { "type": "shadowsocks", "tag": "SS", "server": "1.1.1.1", "server_port": 443, "method": "aes-256-gcm", "password": "p" }
        ]});
        let parse = parse_config(&cfg);
        assert_eq!(parse.nodes.len(), 1);
        assert_eq!(parse.nodes[0].tag, "SS");
        assert!(parse.skipped.is_empty());
    }
}
