-- =============================================
-- sb-easy migration 002
-- Adds: WG per-peer quota, user roles, audit log
-- =============================================

-- Per-peer traffic quota in bytes (0 = unlimited).
ALTER TABLE wireguard_peers ADD COLUMN quota_bytes INTEGER NOT NULL DEFAULT 0;

-- User role for RBAC: 'admin' (full) or 'viewer' (read-only).
ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'admin';

-- Audit log of mutating actions.
CREATE TABLE IF NOT EXISTS audit_log (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      TEXT NOT NULL DEFAULT (datetime('now')),
    actor   TEXT NOT NULL,
    action  TEXT NOT NULL,
    target  TEXT,
    detail  TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts DESC);
