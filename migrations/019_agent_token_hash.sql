-- Phase 1 of agent token hashing: store SHA-256(agent_token) beside the legacy
-- plaintext column. The server backfills existing rows at startup (SQLite has no
-- built-in SHA-256) and looks tokens up by hash first, plaintext second.
ALTER TABLE hosts ADD COLUMN agent_token_hash TEXT NOT NULL DEFAULT '';
CREATE INDEX hosts_agent_token_hash ON hosts(agent_token_hash) WHERE agent_token_hash != '';
