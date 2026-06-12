//! Sing-box configuration generator.
//! Produces outbound JSON for each proxy node type,
//! and full config.json with inbounds, dns, route, outbounds.

use crate::models::proxy_node::ProxyNode;
use serde_json::{json, Value};

/// Generate a sing-box outbound JSON for a single proxy node.
pub fn generate_outbound(node: &ProxyNode) -> Value {
    let protocol_config: Value =
        serde_json::from_str(&node.protocol_config).unwrap_or(json!({}));

    let mut outbound = match node.node_type.as_str() {
        "shadowsocks" => json!({
            "type": "shadowsocks",
            "tag": node.tag,
            "server": node.server,
            "server_port": node.server_port,
            "method": protocol_config["method"],
            "password": protocol_config["password"],
        }),
        "vmess" => {
            let mut ob = json!({
                "type": "vmess",
                "tag": node.tag,
                "server": node.server,
                "server_port": node.server_port,
                "uuid": protocol_config["uuid"],
                "alter_id": protocol_config["alter_id"].as_i64().unwrap_or(0),
                "security": protocol_config["security"].as_str().unwrap_or("auto"),
            });
            if let Some(transport) = protocol_config.get("transport") {
                ob["transport"] = transport.clone();
            }
            if let Some(tls) = protocol_config.get("tls") {
                ob["tls"] = tls.clone();
            }
            ob
        }
        "trojan" => {
            let mut ob = json!({
                "type": "trojan",
                "tag": node.tag,
                "server": node.server,
                "server_port": node.server_port,
                "password": protocol_config["password"],
            });
            if let Some(tls) = protocol_config.get("tls") {
                ob["tls"] = tls.clone();
            }
            ob
        }
        "vless" => {
            let mut ob = json!({
                "type": "vless",
                "tag": node.tag,
                "server": node.server,
                "server_port": node.server_port,
                "uuid": protocol_config["uuid"],
                "flow": protocol_config.get("flow").and_then(|v| v.as_str()).unwrap_or(""),
                "packet_encoding": protocol_config.get("packet_encoding").and_then(|v| v.as_str()).unwrap_or("xudp"),
            });
            if let Some(transport) = protocol_config.get("transport") {
                ob["transport"] = transport.clone();
            }
            if let Some(tls) = protocol_config.get("tls") {
                ob["tls"] = tls.clone();
            }
            ob
        }
        "hysteria2" => {
            let mut ob = json!({
                "type": "hysteria2",
                "tag": node.tag,
                "server": node.server,
                "server_port": node.server_port,
                "password": protocol_config["password"],
            });
            if let Some(tls) = protocol_config.get("tls") {
                ob["tls"] = tls.clone();
            }
            if let Some(obfs) = protocol_config.get("obfs") {
                ob["obfs"] = obfs.clone();
            }
            ob
        }
        "tuic" => {
            let mut ob = json!({
                "type": "tuic",
                "tag": node.tag,
                "server": node.server,
                "server_port": node.server_port,
                "uuid": protocol_config["uuid"],
                "password": protocol_config["password"],
                "congestion_control": protocol_config.get("congestion_control").and_then(|v| v.as_str()).unwrap_or("bbr"),
                "udp_relay_mode": protocol_config.get("udp_relay_mode").and_then(|v| v.as_str()).unwrap_or("native"),
            });
            if let Some(tls) = protocol_config.get("tls") {
                ob["tls"] = tls.clone();
            }
            ob
        }
        _ => json!({ "type": "direct", "tag": node.tag }),
    };

    outbound
}

/// Generate just the outbounds array from all enabled nodes.
pub fn generate_outbounds_array(nodes: &[ProxyNode]) -> Vec<Value> {
    let mut outbounds: Vec<Value> = nodes
        .iter()
        .filter(|n| n.enabled)
        .map(generate_outbound)
        .collect();

    // Add urltest Auto selector
    let auto_tags: Vec<String> = nodes
        .iter()
        .filter(|n| n.enabled)
        .map(|n| n.tag.clone())
        .collect();

    if !auto_tags.is_empty() {
        outbounds.push(json!({
            "type": "urltest",
            "tag": "Auto",
            "outbounds": auto_tags,
            "url": "https://www.google.com/generate_204",
            "interval": "3m",
            "tolerance": 50,
            "idle_timeout": "10m"
        }));

        // Selector with Auto as default
        outbounds.push(json!({
            "type": "selector",
            "tag": "Proxy",
            "outbounds": ["Auto"],
            "default": "Auto"
        }));
    }

    outbounds
}

/// Generate a complete sing-box config.json.
pub fn generate_full_config(nodes: &[ProxyNode]) -> Value {
    json!({
        "log": {
            "level": "info",
            "timestamp": true
        },
        "dns": {
            "servers": [
                { "type": "udp", "tag": "cn-dns", "server": "223.5.5.5" },
                { "type": "udp", "tag": "backup", "server": "119.29.29.29" }
            ],
            "final": "cn-dns",
            "strategy": "prefer_ipv4",
            "independent_cache": true
        },
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "address": ["172.20.0.1/30"],
                "auto_route": true,
                "strict_route": true,
                "stack": "mixed",
                "exclude_interface": ["ztxrndgbge", "docker0", "br-f2e2b7e8627f", "br-58480c19fb3e", "wg0"]
            },
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "0.0.0.0",
                "listen_port": 7890
            }
        ],
        "outbounds": generate_outbounds_array(nodes),
        "route": {
            "rules": [
                { "action": "sniff" },
                { "action": "resolve", "strategy": "prefer_ipv4" },
                { "protocol": "dns", "action": "hijack-dns" },
                { "port": [22], "outbound": "direct", "network": "tcp" },
                { "ip_cidr": ["10.168.1.0/24"], "outbound": "direct" },
                { "ip_is_private": true, "outbound": "direct" }
            ],
            "final": "Proxy",
            "auto_detect_interface": true,
            "default_domain_resolver": {
                "server": "cn-dns"
            }
        }
    })
}
