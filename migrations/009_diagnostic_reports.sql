-- User-triggered, redacted diagnostic bundles from managed devices.
CREATE TABLE IF NOT EXISTS diagnostic_reports (
    id          TEXT PRIMARY KEY,
    host_id     TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    reason      TEXT NOT NULL DEFAULT 'manual',
    app_version TEXT NOT NULL DEFAULT '',
    core_version TEXT NOT NULL DEFAULT '',
    payload     TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_diagnostic_reports_host_created
    ON diagnostic_reports(host_id, created_at DESC);
