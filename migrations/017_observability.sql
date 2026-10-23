-- Receipt-time minute buckets; no connections, domains, URLs or credentials.
CREATE TABLE observability_settings (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    retention_days INTEGER NOT NULL DEFAULT 30,
    offline_seconds INTEGER NOT NULL DEFAULT 180,
    drift_seconds INTEGER NOT NULL DEFAULT 300,
    node_latency_ms INTEGER NOT NULL DEFAULT 5000,
    metrics_token_hash TEXT
);
INSERT INTO observability_settings(id) VALUES(1);
CREATE TABLE observability_hosts (
    host_id TEXT PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
    sampled_at INTEGER NOT NULL DEFAULT 0,
    up_counter INTEGER NOT NULL DEFAULT 0,
    down_counter INTEGER NOT NULL DEFAULT 0,
    observed_up INTEGER NOT NULL DEFAULT 0,
    observed_down INTEGER NOT NULL DEFAULT 0,
    counter_resets INTEGER NOT NULL DEFAULT 0,
    status_at INTEGER NOT NULL DEFAULT 0,
    target_etag TEXT NOT NULL DEFAULT '',
    target_since INTEGER NOT NULL DEFAULT 0,
    applied_etag TEXT NOT NULL DEFAULT '',
    applied_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE observability_samples (
    host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    bucket INTEGER NOT NULL,
    samples INTEGER NOT NULL,
    up_average REAL NOT NULL,
    down_average REAL NOT NULL,
    connections_max INTEGER NOT NULL,
    up_bytes INTEGER NOT NULL,
    down_bytes INTEGER NOT NULL,
    counter_resets INTEGER NOT NULL,
    PRIMARY KEY(host_id,bucket)
);
CREATE INDEX observability_samples_age ON observability_samples(bucket);
CREATE TABLE observability_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    host_id TEXT REFERENCES hosts(id) ON DELETE CASCADE,
    opened_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    resolved_at INTEGER,
    acknowledged_at INTEGER,
    acknowledged_by TEXT REFERENCES users(id) ON DELETE SET NULL
);
CREATE UNIQUE INDEX observability_alert_active ON observability_alerts(kind,resource_id) WHERE resolved_at IS NULL;
CREATE INDEX observability_alert_age ON observability_alerts(updated_at);
