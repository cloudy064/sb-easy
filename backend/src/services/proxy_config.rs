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

    // One "auto" group: sing-box delay-tests the members at startup and uses the
    // fastest. A long interval keeps it from continuously re-testing/switching —
    // effectively "pick the fastest once at start". No selector / manual switching.
    let auto_tags: Vec<String> = nodes
        .iter()
        .filter(|n| n.enabled)
        .map(|n| n.tag.clone())
        .collect();

    if !auto_tags.is_empty() {
        outbounds.push(json!({
            "type": "urltest",
            "tag": "auto",
            "outbounds": auto_tags,
            "url": "https://www.gstatic.com/generate_204",
            "interval": "24h"
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
            "final": "auto",
            "auto_detect_interface": true,
            "default_domain_resolver": { "server": "cn-dns" }
        }
    })
}

/// Render a per-host sing-box config by injecting this host's assigned outbounds
/// into its profile template. The template carries log/dns/inbounds/route; the
/// outbounds array (the proxy nodes + one `auto` urltest) is built from `nodes`.
///
/// `route.final` is normalised: legacy `Proxy`/`Auto` tags map to `auto`; and if
/// `nodes` is empty there is no `auto` group, so `final` falls back to `direct`.
pub fn render_host_config(template: &Value, nodes: &[ProxyNode]) -> Value {
    let mut config = template.clone();
    let mut outbounds = generate_outbounds_array(nodes);
    let has_auto = outbounds.iter().any(|o| o["tag"] == "auto");

    // No proxies → no `auto` group. Add a direct outbound so the config is valid.
    if !has_auto {
        outbounds.push(json!({ "type": "direct", "tag": "direct" }));
    }

    let obj = config.as_object_mut().expect("profile template must be a JSON object");
    obj.insert("outbounds".into(), Value::Array(outbounds));

    if let Some(route) = obj.get_mut("route").and_then(|v| v.as_object_mut()) {
        let cur = route.get("final").and_then(|v| v.as_str()).map(str::to_string);
        if let Some(f) = cur {
            let nf = if !has_auto {
                "direct"
            } else if f == "Proxy" || f == "Auto" {
                "auto"
            } else {
                &f
            };
            if nf != f {
                route.insert("final".into(), Value::String(nf.to_string()));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::proxy_node::ProxyNode;

    fn node(tag: &str, node_type: &str, cfg: serde_json::Value) -> ProxyNode {
        ProxyNode {
            id: format!("id-{tag}"),
            tag: tag.into(),
            node_type: node_type.into(),
            enabled: true,
            server: "1.2.3.4".into(),
            server_port: 443,
            protocol_config: cfg.to_string(),
            subscription_id: None,
            fingerprint: format!("fp-{tag}"),
            latency: None,
            last_latency_test: None,
            created_at: "now".into(),
            updated_at: "now".into(),
        }
    }

    #[test]
    fn outbound_has_type_and_tag() {
        let ss = generate_outbound(&node("hk", "shadowsocks", json!({"method":"aes-256-gcm","password":"p"})));
        assert_eq!(ss["type"], "shadowsocks");
        assert_eq!(ss["tag"], "hk");
        assert_eq!(ss["method"], "aes-256-gcm");
    }

    #[test]
    fn render_empty_falls_back_to_direct() {
        let cfg = render_host_config(&default_profile_template(), &[]);
        let tags: Vec<&str> = cfg["outbounds"].as_array().unwrap()
            .iter().filter_map(|o| o["tag"].as_str()).collect();
        assert!(tags.contains(&"direct"));
        assert!(!tags.contains(&"auto"));
        // final must not dangle on a missing auto group.
        assert_eq!(cfg["route"]["final"], "direct");
    }

    #[test]
    fn render_with_proxies_adds_auto() {
        let nodes = vec![node("hk", "shadowsocks", json!({"method":"aes-256-gcm","password":"p"}))];
        let cfg = render_host_config(&default_profile_template(), &nodes);
        let tags: Vec<&str> = cfg["outbounds"].as_array().unwrap()
            .iter().filter_map(|o| o["tag"].as_str()).collect();
        assert!(tags.contains(&"hk"));
        assert!(tags.contains(&"auto"));
        // simplified model: no selector / manual-switch group
        assert!(!tags.contains(&"Proxy"));
        assert_eq!(cfg["route"]["final"], "auto");
    }

    #[test]
    fn clash_api_injected_when_absent() {
        let mut cfg = json!({"log": {"level": "info"}});
        inject_clash_api(&mut cfg, "127.0.0.1:9090", "sec");
        assert_eq!(cfg["experimental"]["clash_api"]["external_controller"], "127.0.0.1:9090");
        assert_eq!(cfg["experimental"]["clash_api"]["secret"], "sec");
    }

    #[test]
    fn clash_api_not_clobbered_when_present() {
        let mut cfg = json!({"experimental": {"clash_api": {"external_controller": "0.0.0.0:9090", "secret": "mine"}}});
        inject_clash_api(&mut cfg, "127.0.0.1:9090", "other");
        // existing controller/secret preserved
        assert_eq!(cfg["experimental"]["clash_api"]["external_controller"], "0.0.0.0:9090");
        assert_eq!(cfg["experimental"]["clash_api"]["secret"], "mine");
    }

    #[test]
    fn controller_addr_strips_scheme() {
        assert_eq!(controller_addr("http://127.0.0.1:9090"), "127.0.0.1:9090");
        assert_eq!(controller_addr("https://10.0.0.1:9090/"), "10.0.0.1:9090");
        assert_eq!(controller_addr("127.0.0.1:9090"), "127.0.0.1:9090");
    }

    #[test]
    fn etag_is_deterministic_and_host_scoped() {
        let a = config_etag("self", "{\"x\":1}", "seed");
        let b = config_etag("self", "{\"x\":1}", "seed");
        let other_host = config_etag("edge", "{\"x\":1}", "seed");
        let other_body = config_etag("self", "{\"x\":2}", "seed");
        assert_eq!(a, b);
        assert_ne!(a, other_host);
        assert_ne!(a, other_body);
    }
}

/// Inject `experimental.clash_api` so the running sing-box exposes the control
/// API the panel talks to (live traffic/connections/logs, proxy switching).
/// No-op if the config already declares a clash_api (full-mode profiles keep
/// their own), so we never clobber a hand-tuned controller/secret.
pub fn inject_clash_api(config: &mut Value, controller: &str, secret: &str) {
    if controller.is_empty() {
        return;
    }
    if config.pointer("/experimental/clash_api").is_some() {
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

/// Strip the bundled Clash dashboard UI from a config's `clash_api`. The panel
/// *is* the dashboard, so the embedded UI is never used — and downloading it on
/// startup (often via a proxy that isn't up yet) blocks the controller from
/// binding for minutes. Removes `external_ui` and its download settings.
pub fn disable_clash_dashboard(config: &mut Value) {
    if let Some(api) = config
        .pointer_mut("/experimental/clash_api")
        .and_then(|v| v.as_object_mut())
    {
        api.remove("external_ui");
        api.remove("external_ui_download_url");
        api.remove("external_ui_download_detour");
    }
}
