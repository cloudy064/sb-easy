-- Independent proxy identities; never reuse panel accounts or WireGuard peers.
-- Written only by authenticated runtime status reports, never host admin edits.
CREATE TABLE proxy_runtime_reports (
    host_id TEXT PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
    supported INTEGER NOT NULL DEFAULT 0,
    observed_at INTEGER NOT NULL
);
CREATE TABLE proxy_ingress_nodes (
    host_id TEXT PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
    enabled INTEGER NOT NULL DEFAULT 0,
    server TEXT NOT NULL,
    listen TEXT NOT NULL DEFAULT '0.0.0.0',
    listen_port INTEGER NOT NULL CHECK(listen_port BETWEEN 1 AND 65535),
    server_key TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE TABLE proxy_users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    deleted INTEGER NOT NULL DEFAULT 0,
    quota_bytes INTEGER NOT NULL DEFAULT 0 CHECK(quota_bytes >= 0),
    expires_at INTEGER NOT NULL DEFAULT 0,
    max_devices INTEGER NOT NULL DEFAULT 3 CHECK(max_devices BETWEEN 1 AND 32),
    epoch INTEGER NOT NULL DEFAULT 1,
    not_before INTEGER NOT NULL DEFAULT 0,
    claim_hash TEXT UNIQUE,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE TABLE proxy_user_nodes (
    user_id TEXT NOT NULL REFERENCES proxy_users(id),
    host_id TEXT NOT NULL REFERENCES proxy_ingress_nodes(host_id) ON DELETE CASCADE,
    PRIMARY KEY(user_id,host_id)
);
CREATE TABLE proxy_devices (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES proxy_users(id),
    name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    password TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at INTEGER NOT NULL DEFAULT 0 CHECK(expires_at >= 0),
    created_at INTEGER NOT NULL,
    revoked_at INTEGER
);
CREATE INDEX proxy_devices_user ON proxy_devices(user_id,enabled);
CREATE TABLE proxy_leases (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES proxy_users(id),
    host_id TEXT NOT NULL,
    boot_id TEXT NOT NULL,
    epoch INTEGER NOT NULL,
    grant_bytes INTEGER NOT NULL CHECK(grant_bytes >= 0),
    used_bytes INTEGER NOT NULL DEFAULT 0 CHECK(used_bytes BETWEEN 0 AND grant_bytes),
    expires_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE(user_id,host_id,boot_id,epoch)
);
CREATE INDEX proxy_leases_budget ON proxy_leases(user_id,epoch);
CREATE TABLE proxy_lease_sessions (
    host_id TEXT NOT NULL,
    boot_id TEXT NOT NULL,
    request_seq INTEGER NOT NULL,
    request_hash TEXT NOT NULL,
    response TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY(host_id,boot_id)
);
