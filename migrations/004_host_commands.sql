-- =============================================
-- sb-easy migration 004
-- Downlink command queue for managed hosts.
-- The panel enqueues commands; the agent pulls pending ones on its poll cycle,
-- executes them, and acks the result. No long-lived connection.
-- =============================================

CREATE TABLE IF NOT EXISTS host_commands (
    id          TEXT PRIMARY KEY,
    host_id     TEXT NOT NULL,
    command     TEXT NOT NULL,            -- reload | restart
    status      TEXT NOT NULL DEFAULT 'pending', -- pending | done | failed
    result      TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    acked_at    TEXT
);
CREATE INDEX IF NOT EXISTS idx_host_commands_pending ON host_commands(host_id, status);
