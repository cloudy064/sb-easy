-- Android device enrollment and a mobile-safe managed profile.

CREATE TABLE IF NOT EXISTS agent_enrollments (
    id          TEXT PRIMARY KEY,
    host_id     TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    code_hash   TEXT NOT NULL UNIQUE,
    expires_at  TEXT NOT NULL,
    redeemed_at TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_agent_enrollments_host
    ON agent_enrollments(host_id, created_at DESC);

INSERT OR IGNORE INTO config_profiles
    (id, name, template, mode, rule_script, rule_script_enabled)
VALUES (
    'android-client',
    'Android Client',
    '{"log":{"level":"info","timestamp":true},"dns":{"servers":[{"type":"udp","tag":"bootstrap-dns","server":"1.1.1.1"}],"final":"bootstrap-dns","strategy":"prefer_ipv4","independent_cache":true},"inbounds":[{"type":"tun","tag":"tun-in","address":["172.19.0.1/30"],"auto_route":true,"strict_route":true,"stack":"mixed"}],"experimental":{"cache_file":{"enabled":true}},"route":{"rules":[{"action":"sniff"},{"protocol":"dns","action":"hijack-dns"},{"ip_is_private":true,"outbound":"direct"}],"final":"Proxy","auto_detect_interface":true,"default_domain_resolver":{"server":"bootstrap-dns"}}}',
    'managed',
    'function buildRules(context) {
  return context.currentRules;
}',
    1
);
