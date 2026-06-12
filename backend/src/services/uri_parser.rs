//! URI parser for proxy subscription formats.
//! Supports: ss://, vmess://, trojan://, vless://, hysteria2://, tuic://
//!
//! Each parser returns a normalized tuple: (node_type, server, port, tag, protocol_config_json)

use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

use crate::error::{AppError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedNode {
    pub node_type: String,
    pub tag: String,
    pub server: String,
    pub server_port: i32,
    pub protocol_config: serde_json::Value,
}

impl ParsedNode {
    /// Generate a deduplication fingerprint.
    pub fn fingerprint(&self) -> String {
        let raw = format!(
            "{}:{}:{}:{}",
            self.server,
            self.server_port,
            self.node_type,
            extract_key_material(&self.node_type, &self.protocol_config)
        );
        let mut hasher = Sha256::new();
        hasher.update(raw.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

fn extract_key_material(node_type: &str, config: &serde_json::Value) -> String {
    match node_type {
        "shadowsocks" => config["password"].as_str().unwrap_or("").to_string(),
        "vmess" | "vless" => config["uuid"].as_str().unwrap_or("").to_string(),
        "trojan" | "hysteria2" => config["password"].as_str().unwrap_or("").to_string(),
        "tuic" => format!(
            "{}:{}",
            config["uuid"].as_str().unwrap_or(""),
            config["password"].as_str().unwrap_or("")
        ),
        _ => String::new(),
    }
}

/// Parse a single proxy URI. Returns None if the scheme is not recognized.
pub fn parse_uri(uri: &str) -> Option<ParsedNode> {
    let uri = uri.trim();
    if uri.is_empty() {
        return None;
    }

    if uri.starts_with("ss://") {
        parse_ss(uri)
    } else if uri.starts_with("vmess://") {
        parse_vmess(uri)
    } else if uri.starts_with("trojan://") {
        parse_trojan(uri)
    } else if uri.starts_with("vless://") {
        parse_vless(uri)
    } else if uri.starts_with("hysteria2://") || uri.starts_with("hy2://") {
        parse_hysteria2(uri)
    } else if uri.starts_with("tuic://") {
        parse_tuic(uri)
    } else {
        None
    }
}

/// Parse Shadowsocks URI: ss://BASE64(method:password)@host:port#tag
/// Or legacy: ss://BASE64(method:password@host:port)#tag
fn parse_ss(uri: &str) -> Option<ParsedNode> {
    let uri = uri.trim_start_matches("ss://");
    let fragment = extract_fragment(uri);
    // The rest after removing fragment
    let body = uri.split('#').next()?;

    // Try SIP002 format first: userinfo@host:port
    if body.contains('@') {
        let userinfo_encoded = body.split('@').next()?;
        let host_port = body.split('@').nth(1)?;

        // Decode userinfo (base64 standard or url-safe)
        let userinfo = decode_base64_flexible(userinfo_encoded)?;
        let (method, password) = userinfo.split_once(':')?;

        // Parse host:port
        let (host, port) = parse_host_port(host_port)?;

        Some(ParsedNode {
            tag: fragment.map(|s| s.to_string()).unwrap_or_else(|| format!("{host}:{port}")),
            node_type: "shadowsocks".to_string(),
            server: host,
            server_port: port,
            protocol_config: serde_json::json!({
                "method": method,
                "password": password,
            }),
        })
    } else {
        // Legacy ss:// format: base64(method:password@host:port)#tag
        let decoded = decode_base64_flexible(body)?;
        let parts: Vec<&str> = decoded.splitn(2, '@').collect();
        if parts.len() != 2 {
            return None;
        }
        let (method, password) = parts[0].split_once(':')?;
        let (host, port) = parse_host_port(parts[1])?;

        Some(ParsedNode {
            tag: fragment.map(|s| s.to_string()).unwrap_or_else(|| format!("{host}:{port}")),
            node_type: "shadowsocks".to_string(),
            server: host,
            server_port: port,
            protocol_config: serde_json::json!({
                "method": method,
                "password": password,
            }),
        })
    }
}

/// Parse VMess URI: vmess://BASE64(json)
fn parse_vmess(uri: &str) -> Option<ParsedNode> {
    let body = uri.trim_start_matches("vmess://");
    let decoded = decode_base64_flexible(body)?;
    let json: serde_json::Value = serde_json::from_str(&decoded).ok()?;

    let server = json["add"].as_str().or(json["host"].as_str())?;
    let port = json["port"]
        .as_str()
        .or(json["port"].as_i64().map(|_| ""))
        .and_then(|s| s.parse::<i32>().ok())
        .or_else(|| json["port"].as_i64().map(|i| i as i32))?;
    let tag = json["ps"].as_str().unwrap_or(&json["name"].as_str().unwrap_or("vmess"));

    let mut config = serde_json::json!({
        "uuid": json["id"].as_str().unwrap_or(""),
        "alter_id": json["aid"].as_i64().unwrap_or(0),
        "security": json["scy"].as_str().unwrap_or("auto"),
    });

    // Transport
    let network = json["net"].as_str().unwrap_or("tcp");
    if network != "tcp" {
        let mut transport = serde_json::json!({ "type": network });
        if let Some(path) = json["path"].as_str() {
            transport["path"] = serde_json::json!(path);
        }
        if let Some(host) = json["host"].as_str() {
            transport["headers"] = serde_json::json!({ "Host": host });
        }
        config["transport"] = transport;
    }

    // TLS
    let tls = json["tls"].as_str().unwrap_or("");
    if tls == "tls" {
        let mut tls_config = serde_json::json!({ "enabled": true });
        if let Some(sni) = json["sni"].as_str() {
            tls_config["server_name"] = serde_json::json!(sni);
        }
        config["tls"] = tls_config;
    }

    Some(ParsedNode {
        node_type: "vmess".to_string(),
        tag: tag.to_string(),
        server: server.to_string(),
        server_port: port,
        protocol_config: config,
    })
}

/// Parse Trojan URI: trojan://password@host:port?security=tls&sni=...#tag
fn parse_trojan(uri: &str) -> Option<ParsedNode> {
    let parsed = Url::parse(uri).ok()?;
    let password = parsed.username();
    let host = parsed.host_str()?;
    let port = parsed.port().unwrap_or(443) as i32;
    let tag = parsed.fragment().unwrap_or("trojan").to_string();

    let mut config = serde_json::json!({
        "password": password,
    });

    let mut tls = serde_json::json!({ "enabled": true });
    for (k, v) in parsed.query_pairs() {
        match k.as_ref() {
            "sni" => { tls["server_name"] = serde_json::json!(v.as_ref()); }
            "alpn" => { tls["alpn"] = serde_json::json!(v.as_ref().split(',').collect::<Vec<_>>()); }
            "fp" | "fingerprint" => {
                tls["utls"] = serde_json::json!({
                    "enabled": true,
                    "fingerprint": v.as_ref()
                });
            }
            "allowInsecure" | "skip-cert-verify" if v.as_ref() == "1" => {
                tls["insecure"] = serde_json::json!(true);
            }
            _ => {}
        }
    }
    config["tls"] = tls;

    Some(ParsedNode {
        node_type: "trojan".to_string(),
        tag,
        server: host.to_string(),
        server_port: port,
        protocol_config: config,
    })
}

/// Parse VLESS URI: vless://uuid@host:port?encryption=none&type=ws&security=tls&...#tag
fn parse_vless(uri: &str) -> Option<ParsedNode> {
    let parsed = Url::parse(uri).ok()?;
    let uuid = parsed.username();
    let host = parsed.host_str()?;
    let port = parsed.port().unwrap_or(443) as i32;
    let tag = parsed.fragment().unwrap_or("vless").to_string();

    let mut config = serde_json::json!({
        "uuid": uuid,
        "flow": "",
        "packet_encoding": "xudp",
    });

    for (k, v) in parsed.query_pairs() {
        match k.as_ref() {
            "flow" => { config["flow"] = serde_json::json!(v.as_ref()); }
            "encryption" => {}, // always "none" in current spec
            "type" | "network" => {
                if v.as_ref() != "tcp" {
                    let mut transport = serde_json::json!({ "type": v.as_ref() });
                    config["transport"] = transport;
                }
            }
            "security" if v.as_ref() == "tls" || v.as_ref() == "reality" => {
                let mut tls = serde_json::json!({ "enabled": true });
                config["tls"] = tls;
            }
            "sni" => {
                if let Some(ref mut tls) = config.get_mut("tls") {
                    tls["server_name"] = serde_json::json!(v.as_ref());
                }
            }
            "path" => {
                if let Some(ref mut transport) = config.get_mut("transport") {
                    transport["path"] = serde_json::json!(v.as_ref());
                }
            }
            "host" => {
                if let Some(ref mut transport) = config.get_mut("transport") {
                    transport["headers"] = serde_json::json!({ "Host": v.as_ref() });
                }
            }
            _ => {}
        }
    }

    Some(ParsedNode {
        node_type: "vless".to_string(),
        tag,
        server: host.to_string(),
        server_port: port,
        protocol_config: config,
    })
}

/// Parse Hysteria2 URI: hysteria2://password@host:port?sni=...#tag
fn parse_hysteria2(uri: &str) -> Option<ParsedNode> {
    // Normalize hy2:// to hysteria2://
    let normalized = if uri.starts_with("hy2://") {
        uri.replacen("hy2://", "hysteria2://", 1)
    } else {
        uri.to_string()
    };
    let parsed = Url::parse(&normalized).ok()?;
    let password = parsed.username();
    let host = parsed.host_str()?;
    let port = parsed.port().unwrap_or(443) as i32;
    let tag = parsed.fragment().unwrap_or("hysteria2").to_string();

    let mut config = serde_json::json!({
        "password": password,
    });

    for (k, v) in parsed.query_pairs() {
        match k.as_ref() {
            "sni" => {
                let mut tls = serde_json::json!({ "enabled": true, "server_name": v.as_ref() });
                config["tls"] = tls;
            }
            "insecure" | "skip-cert-verify" if v.as_ref() == "1" => {
                if let Some(ref mut tls) = config.get_mut("tls") {
                    tls["insecure"] = serde_json::json!(true);
                }
            }
            "obfs" => {
                config["obfs"] = serde_json::json!({
                    "type": v.as_ref()
                });
            }
            "obfs-password" => {
                if let Some(ref mut obfs) = config.get_mut("obfs") {
                    obfs["password"] = serde_json::json!(v.as_ref());
                }
            }
            _ => {}
        }
    }

    Some(ParsedNode {
        node_type: "hysteria2".to_string(),
        tag,
        server: host.to_string(),
        server_port: port,
        protocol_config: config,
    })
}

/// Parse TUIC URI: tuic://uuid:password@host:port?sni=...#tag
fn parse_tuic(uri: &str) -> Option<ParsedNode> {
    let parsed = Url::parse(uri).ok()?;
    let userinfo = parsed.username();
    let (uuid, password) = userinfo.split_once(':')?;
    let host = parsed.host_str()?;
    let port = parsed.port().unwrap_or(443) as i32;
    let tag = parsed.fragment().unwrap_or("tuic").to_string();

    let mut config = serde_json::json!({
        "uuid": uuid,
        "password": password,
        "congestion_control": "bbr",
        "udp_relay_mode": "native",
        "heartbeat": "10s",
    });

    for (k, v) in parsed.query_pairs() {
        match k.as_ref() {
            "sni" => {
                let mut tls = serde_json::json!({ "enabled": true, "server_name": v.as_ref() });
                config["tls"] = tls;
            }
            "alpn" => {
                if let Some(ref mut tls) = config.get_mut("tls") {
                    tls["alpn"] = serde_json::json!(v.as_ref().split(',').collect::<Vec<_>>());
                }
            }
            "congestion_control" | "congestion" => {
                config["congestion_control"] = serde_json::json!(v.as_ref());
            }
            "insecure" | "skip-cert-verify" if v.as_ref() == "1" => {
                if let Some(ref mut tls) = config.get_mut("tls") {
                    tls["insecure"] = serde_json::json!(true);
                }
            }
            _ => {}
        }
    }

    Some(ParsedNode {
        node_type: "tuic".to_string(),
        tag,
        server: host.to_string(),
        server_port: port,
        protocol_config: config,
    })
}

// ── Helpers ──────────────────────────────────────────────

fn decode_base64_flexible(input: &str) -> Option<String> {
    // Try standard base64
    let cleaned = input.trim();
    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(cleaned) {
        return String::from_utf8(decoded).ok();
    }
    // Try URL-safe base64
    if let Ok(decoded) = base64::engine::general_purpose::URL_SAFE.decode(cleaned) {
        return String::from_utf8(decoded).ok();
    }
    // Try no-padding variants
    let padded = pad_base64(cleaned);
    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(&padded) {
        return String::from_utf8(decoded).ok();
    }
    None
}

fn pad_base64(input: &str) -> String {
    let len = input.len();
    let pad = (4 - (len % 4)) % 4;
    format!("{}{}", input, "=".repeat(pad))
}

fn extract_fragment(uri: &str) -> Option<&str> {
    uri.split('#').nth(1).map(|f| {
        // URL-decode the fragment
        let f = f.trim();
        // Simple percent-decoding
        f.split('%').next().unwrap_or(f)
    })
}

fn parse_host_port(input: &str) -> Option<(String, i32)> {
    if input.contains(':') {
        let (host, port_str) = input.rsplit_once(':')?;
        let port = port_str.parse::<i32>().ok()?;
        Some((host.to_string(), port))
    } else {
        // No port, use defaults
        Some((input.to_string(), 8388)) // shadowsocks default
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ss_sip002() {
        let uri = "ss://YWVzLTI1Ni1nY206dGVzdHBhc3N3b3Jk@server.example.com:443#TestNode";
        let result = parse_ss(uri).unwrap();
        assert_eq!(result.node_type, "shadowsocks");
        assert_eq!(result.server, "server.example.com");
        assert_eq!(result.server_port, 443);
        assert_eq!(result.tag, "TestNode");
    }

    #[test]
    fn test_parse_trojan() {
        let uri = "trojan://password123@trojan.example.com:443?security=tls&sni=sni.example.com#Trojan01";
        let result = parse_trojan(uri).unwrap();
        assert_eq!(result.node_type, "trojan");
        assert_eq!(result.server, "trojan.example.com");
        assert_eq!(result.server_port, 443);
        assert_eq!(result.tag, "Trojan01");
    }

    #[test]
    fn test_parse_hysteria2() {
        let uri = "hysteria2://letmein@hy2.example.com:8443?sni=hy2.example.com#HY2";
        let result = parse_hysteria2(uri).unwrap();
        assert_eq!(result.node_type, "hysteria2");
        assert_eq!(result.server, "hy2.example.com");
        assert_eq!(result.server_port, 8443);
    }

    #[test]
    fn test_parse_vless() {
        let uri = "vless://abc123def456@vless.example.com:443?encryption=none&security=tls&type=ws&path=/ws#VLESS-WS";
        let result = parse_vless(uri).unwrap();
        assert_eq!(result.node_type, "vless");
        assert_eq!(result.server, "vless.example.com");
        assert_eq!(result.tag, "VLESS-WS");
    }

    #[test]
    fn test_fingerprint_unique() {
        let node1 = ParsedNode {
            node_type: "shadowsocks".into(),
            tag: "Node1".into(),
            server: "server1.com".into(),
            server_port: 443,
            protocol_config: serde_json::json!({"method": "aes-256-gcm", "password": "pass1"}),
        };
        let node2 = ParsedNode {
            node_type: "shadowsocks".into(),
            tag: "Node2".into(),
            server: "server2.com".into(),
            server_port: 443,
            protocol_config: serde_json::json!({"method": "aes-256-gcm", "password": "pass2"}),
        };
        let node1_dup = ParsedNode {
            node_type: "shadowsocks".into(),
            tag: "Node1-copy".into(),
            server: "server1.com".into(),
            server_port: 443,
            protocol_config: serde_json::json!({"method": "aes-256-gcm", "password": "pass1"}),
        };

        assert_eq!(node1.fingerprint(), node1_dup.fingerprint());
        assert_ne!(node1.fingerprint(), node2.fingerprint());
    }
}
