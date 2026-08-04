-- Profile-scoped deterministic QuickJS route rule generation.
-- Disabled and empty by default, so existing profiles remain unchanged.
ALTER TABLE config_profiles
    ADD COLUMN rule_script TEXT NOT NULL DEFAULT '';

ALTER TABLE config_profiles
    ADD COLUMN rule_script_enabled INTEGER NOT NULL DEFAULT 0;
