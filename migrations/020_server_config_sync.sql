-- One shared source clock, assigned on the server. Device patch deletion is
-- represented by {} with a newer version, never by deleting its version row.
CREATE TABLE config_sync_clock (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    version INTEGER NOT NULL CHECK(version > 0)
);
INSERT INTO config_sync_clock VALUES(1, CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER));

CREATE TABLE device_config_sync (
    host_id TEXT PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
    patch_version INTEGER NOT NULL DEFAULT 0 CHECK(patch_version >= 0),
    patch TEXT NOT NULL DEFAULT '{}',
    agent_settings TEXT NOT NULL DEFAULT '{}',
    agent_settings_initialized INTEGER NOT NULL DEFAULT 0 CHECK(agent_settings_initialized IN (0,1)),
    base_fingerprint TEXT NOT NULL DEFAULT '',
    base_seen_version INTEGER NOT NULL DEFAULT 0
);

CREATE TRIGGER config_sync_profiles_insert AFTER INSERT ON config_profiles BEGIN
    UPDATE config_sync_clock SET version = MAX(version + 1, CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER));
END;
CREATE TRIGGER config_sync_profiles_update AFTER UPDATE ON config_profiles
WHEN OLD.name IS NOT NEW.name OR OLD.template IS NOT NEW.template OR OLD.mode IS NOT NEW.mode
  OR OLD.rule_script IS NOT NEW.rule_script OR OLD.rule_script_enabled IS NOT NEW.rule_script_enabled BEGIN
    UPDATE config_sync_clock SET version = MAX(version + 1, CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER));
END;
CREATE TRIGGER config_sync_profiles_delete AFTER DELETE ON config_profiles BEGIN
    UPDATE config_sync_clock SET version = MAX(version + 1, CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER));
END;
CREATE TRIGGER config_sync_nodes_insert AFTER INSERT ON proxy_nodes BEGIN
    UPDATE config_sync_clock SET version = MAX(version + 1, CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER));
END;
CREATE TRIGGER config_sync_nodes_update AFTER UPDATE OF tag,node_type,enabled,server,server_port,protocol_config ON proxy_nodes
WHEN OLD.tag IS NOT NEW.tag OR OLD.node_type IS NOT NEW.node_type OR OLD.enabled IS NOT NEW.enabled
  OR OLD.server IS NOT NEW.server OR OLD.server_port IS NOT NEW.server_port OR OLD.protocol_config IS NOT NEW.protocol_config BEGIN
    UPDATE config_sync_clock SET version = MAX(version + 1, CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER));
END;
CREATE TRIGGER config_sync_nodes_delete AFTER DELETE ON proxy_nodes BEGIN
    UPDATE config_sync_clock SET version = MAX(version + 1, CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER));
END;
CREATE TRIGGER config_sync_hosts_update AFTER UPDATE OF name,capabilities,profile_id,wg_address,wg_public_key,wg_endpoint,clash_api,clash_secret,tailscale ON hosts
WHEN OLD.name IS NOT NEW.name OR OLD.capabilities IS NOT NEW.capabilities OR OLD.profile_id IS NOT NEW.profile_id
  OR OLD.wg_address IS NOT NEW.wg_address OR OLD.wg_public_key IS NOT NEW.wg_public_key OR OLD.wg_endpoint IS NOT NEW.wg_endpoint
  OR OLD.clash_api IS NOT NEW.clash_api OR OLD.clash_secret IS NOT NEW.clash_secret
  OR OLD.tailscale IS NOT NEW.tailscale BEGIN
    UPDATE config_sync_clock SET version = MAX(version + 1, CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER));
END;
CREATE TRIGGER config_sync_outbounds_insert AFTER INSERT ON host_outbounds BEGIN
    UPDATE config_sync_clock SET version = MAX(version + 1, CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER));
END;
CREATE TRIGGER config_sync_outbounds_delete AFTER DELETE ON host_outbounds BEGIN
    UPDATE config_sync_clock SET version = MAX(version + 1, CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER));
END;
