-- =============================================
-- sb-easy initial migration
-- Tables: users, wireguard_peers, proxy_nodes,
--         subscriptions, app_settings, one_time_links
-- =============================================

CREATE TABLE IF NOT EXISTS users (
    id              TEXT PRIMARY KEY,
    username        TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS wireguard_peers (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    private_key     TEXT NOT NULL,
    public_key      TEXT NOT NULL,
    preshared_key   TEXT,
    address         TEXT NOT NULL UNIQUE,
    dns             TEXT DEFAULT '10.59.32.1',
    enabled         INTEGER NOT NULL DEFAULT 1,
    persistent_keepalive INTEGER NOT NULL DEFAULT 25,
    allowed_ips     TEXT NOT NULL DEFAULT '0.0.0.0/0, ::/0',
    expire_at       TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now')),
    notes           TEXT
);

CREATE TABLE IF NOT EXISTS one_time_links (
    id              TEXT PRIMARY KEY,
    peer_id         TEXT NOT NULL,
    expires_at      TEXT NOT NULL,
    used            INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS proxy_nodes (
    id              TEXT PRIMARY KEY,
    tag             TEXT NOT NULL UNIQUE,
    node_type       TEXT NOT NULL,
    enabled         INTEGER NOT NULL DEFAULT 1,
    server          TEXT NOT NULL,
    server_port     INTEGER NOT NULL,
    protocol_config TEXT NOT NULL DEFAULT '{}',
    subscription_id TEXT,
    fingerprint     TEXT NOT NULL UNIQUE,
    latency         REAL,
    last_latency_test TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS subscriptions (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    url             TEXT NOT NULL,
    enabled         INTEGER NOT NULL DEFAULT 1,
    refresh_interval INTEGER NOT NULL DEFAULT 3600,
    last_fetched_at TEXT,
    last_fetch_result TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS app_settings (
    key             TEXT PRIMARY KEY,
    value           TEXT NOT NULL,
    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Seed default settings (values are overridden by env at runtime)
INSERT OR IGNORE INTO app_settings (key, value) VALUES
    ('wireguard_interface', '{"interface":"wg0","listen_port":51820,"address":"10.59.32.1/24","dns":"10.59.32.1","mtu":1420}'),
    ('singbox_connection', '{"api_url":"http://10.168.1.5:9090","secret":""}'),
    ('general', '{"app_name":"sb-easy","external_hostname":"39.108.98.208","one_time_link_expiry_minutes":5}');
