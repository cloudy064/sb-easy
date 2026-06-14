-- =============================================
-- sb-easy migration 003
-- Multi-host central management:
--   config_profiles  — per-host inbound/route/dns template
--   hosts            — managed machines running agent / sing-box / WG member
--   host_outbounds   — which proxy_nodes (Proxies) a Host should dial
--   wireguard_peers.host_id — link a WG peer to a managed Host
-- Backward compatible: a single built-in `self` host + `default` profile
-- reproduce the previous global config behavior.
-- =============================================

-- Per-host configuration profile: everything in a sing-box config EXCEPT the
-- outbounds array (outbounds are injected per-host from host_outbounds at render
-- time). The `default` profile below encodes the previously hardcoded config.
CREATE TABLE IF NOT EXISTS config_profiles (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    template    TEXT NOT NULL DEFAULT '{}',
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Managed machines. `capabilities` JSON: runs_singbox/is_wg_member/is_wg_hub/is_self.
-- `is_self` host is managed in-process (no remote agent); its config is written
-- locally. Remote hosts authenticate the agent with per-host `agent_token`.
CREATE TABLE IF NOT EXISTS hosts (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    agent_token   TEXT NOT NULL DEFAULT '',
    capabilities  TEXT NOT NULL DEFAULT '{}',
    profile_id    TEXT REFERENCES config_profiles(id),
    wg_address    TEXT,
    wg_public_key TEXT,
    wg_endpoint   TEXT,
    clash_api     TEXT,
    clash_secret  TEXT NOT NULL DEFAULT '',
    last_seen     TEXT,
    singbox_state TEXT,
    enabled       INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Many-to-many: which Proxies (proxy_nodes) are assigned to a Host.
-- A Host with NO rows here falls back to "all enabled proxies" at render time,
-- which keeps the existing single-deployment working with zero configuration.
CREATE TABLE IF NOT EXISTS host_outbounds (
    host_id   TEXT NOT NULL,
    node_id   TEXT NOT NULL,
    PRIMARY KEY (host_id, node_id)
);
CREATE INDEX IF NOT EXISTS idx_host_outbounds_host ON host_outbounds(host_id);

-- Link a WG peer to a managed Host (NULL for ordinary end-user clients).
ALTER TABLE wireguard_peers ADD COLUMN host_id TEXT;

-- Seed the default profile (the previously hardcoded inbounds/route/dns/log).
INSERT OR IGNORE INTO config_profiles (id, name, template) VALUES (
    'default',
    'Default (tun + mixed)',
    '{"log":{"level":"info","timestamp":true},"dns":{"servers":[{"type":"udp","tag":"cn-dns","server":"223.5.5.5"},{"type":"udp","tag":"backup","server":"119.29.29.29"}],"final":"cn-dns","strategy":"prefer_ipv4","independent_cache":true},"inbounds":[{"type":"tun","tag":"tun-in","address":["172.20.0.1/30"],"auto_route":true,"strict_route":true,"stack":"mixed","exclude_interface":["ztxrndgbge","docker0","br-f2e2b7e8627f","br-58480c19fb3e","wg0"]},{"type":"mixed","tag":"mixed-in","listen":"0.0.0.0","listen_port":7890}],"route":{"rules":[{"action":"sniff"},{"action":"resolve","strategy":"prefer_ipv4"},{"protocol":"dns","action":"hijack-dns"},{"port":[22],"outbound":"direct","network":"tcp"},{"ip_cidr":["10.168.1.0/24"],"outbound":"direct"},{"ip_is_private":true,"outbound":"direct"}],"final":"Proxy","auto_detect_interface":true,"default_domain_resolver":{"server":"cn-dns"}}}'
);

-- Seed the built-in self host (this server). Managed in-process.
INSERT OR IGNORE INTO hosts (id, name, capabilities, profile_id, enabled) VALUES (
    'self',
    'This server',
    '{"runs_singbox":true,"is_wg_member":true,"is_wg_hub":true,"is_self":true}',
    'default',
    1
);
