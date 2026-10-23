ALTER TABLE subscriptions ADD COLUMN usage TEXT NOT NULL DEFAULT '{}';
ALTER TABLE subscriptions ADD COLUMN last_attempt_at TEXT;
ALTER TABLE subscriptions ADD COLUMN last_error TEXT;
ALTER TABLE subscriptions ADD COLUMN next_refresh_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE subscriptions ADD COLUMN failure_count INTEGER NOT NULL DEFAULT 0;

-- Remember the provider's last name so a refresh preserves a user's rename.
ALTER TABLE proxy_nodes ADD COLUMN source_tag TEXT;
UPDATE proxy_nodes SET source_tag = tag WHERE subscription_id IS NOT NULL;
