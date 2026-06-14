//! Sing-box configuration generator.
//! Produces outbound JSON for each proxy node type,
//! and full config.json with inbounds, dns, route, outbounds.

use crate::models::proxy_node::ProxyNode;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Compute the ETag for a host's rendered config. Single source of truth shared
/// by the agent config endpoint and drift detection so both hash identically.
pub fn config_etag(host_id: &str, config_str: &str, seed: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(host_id.as_bytes());
    hasher.update(config_str.as_bytes());
    hasher.update(seed.as_bytes());
    format!("\"{:x}\"", hasher.finalize())
}

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

/// The built-in default profile template (sing-box config minus outbounds).
/// Mirrors `migrations/003_multi_host.sql`'s `default` profile and is used as a
/// fallback when a host has no profile assigned or the stored template is invalid.
pub fn default_profile_template() -> Value {
    json!({
        "log": { "level": "info", "timestamp": true },
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
            "default_domain_resolver": { "server": "cn-dns" }
        }
    })
}

/// Render a per-host sing-box config by injecting this host's assigned outbounds
/// into its profile template. The template carries log/dns/inbounds/route; the
/// outbounds array (proxies + Auto/Proxy selectors) is built from `nodes`.
///
/// If `nodes` is empty there is no `Proxy` selector, so any `route.final` that
/// points at `Proxy` is rewritten to `direct` to keep the config valid.
pub fn render_host_config(template: &Value, nodes: &[ProxyNode]) -> Value {
    let mut config = template.clone();
    let mut outbounds = generate_outbounds_array(nodes);
    let has_proxy = outbounds.iter().any(|o| o["tag"] == "Proxy");

    // Empty case only: no proxies → no Proxy selector. Add a direct outbound and
    // repoint route.final at it so the config stays valid. (When proxies exist
    // the output is byte-for-byte the same as the previous global config.)
    if !has_proxy {
        outbounds.push(json!({ "type": "direct", "tag": "direct" }));
    }

    let obj = config.as_object_mut().expect("profile template must be a JSON object");
    obj.insert("outbounds".into(), Value::Array(outbounds));

    if !has_proxy {
        if let Some(route) = obj.get_mut("route").and_then(|v| v.as_object_mut()) {
            if route.get("final").map(|f| f == "Proxy").unwrap_or(false) {
                route.insert("final".into(), Value::String("direct".into()));
            }
        }
    }

    config
}

/// Generate a complete sing-box config.json from the built-in default profile.
/// Retained for backward compatibility; prefer `render_host_config`.
pub fn generate_full_config(nodes: &[ProxyNode]) -> Value {
    render_host_config(&default_profile_template(), nodes)
}

/// Strip the scheme from a Clash API URL → "host:port" for external_controller.
pub fn controller_addr(api_url: &str) -> String {
    api_url
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .to_string()
}

/// Inject `experimental.clash_api` so the running sing-box exposes the control
/// API the panel talks to (live traffic/connections/logs, proxy switching).
pub fn inject_clash_api(config: &mut Value, controller: &str, secret: &str) {
    if controller.is_empty() {
        return;
    }
    let Some(obj) = config.as_object_mut() else { return };
    let exp = obj.entry("experimental").or_insert_with(|| json!({}));
    let Some(exp_obj) = exp.as_object_mut() else { return };
    let mut api = json!({ "external_controller": controller });
    if !secret.is_empty() {
        api["secret"] = json!(secret);
    }
    exp_obj.insert("clash_api".into(), api);
}
