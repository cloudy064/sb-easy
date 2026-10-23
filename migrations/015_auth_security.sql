-- Stateful sessions, encrypted TOTP, one-use OIDC flows and scoped device access.
CREATE TABLE auth_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    method TEXT NOT NULL,
    client_label TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    revoked_at INTEGER
);
CREATE INDEX idx_auth_sessions_user ON auth_sessions(user_id, created_at DESC);
CREATE INDEX idx_auth_sessions_expiry ON auth_sessions(expires_at);
CREATE TABLE auth_mfa (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    secret_enc TEXT,
    pending_enc TEXT,
    pending_until INTEGER NOT NULL DEFAULT 0,
    last_step INTEGER NOT NULL DEFAULT -1,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE auth_recovery_codes (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    used_at INTEGER,
    PRIMARY KEY(user_id, code_hash)
);
CREATE TABLE auth_login_challenges (
    challenge_hash TEXT PRIMARY KEY,
    binding_hash TEXT,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    method TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE TABLE auth_oidc_config (
    id INTEGER PRIMARY KEY CHECK(id=1),
    enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0,1)),
    issuer TEXT NOT NULL,
    client_id TEXT NOT NULL,
    secret_enc TEXT,
    redirect_uri TEXT NOT NULL,
    discovery TEXT NOT NULL
);
CREATE TABLE auth_oidc_flows (
    state_hash TEXT PRIMARY KEY,
    binding_hash TEXT NOT NULL,
    verifier_enc TEXT NOT NULL,
    nonce TEXT NOT NULL,
    issuer TEXT NOT NULL,
    client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE TABLE auth_oidc_links (
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY(issuer,subject)
);
CREATE INDEX idx_auth_oidc_user ON auth_oidc_links(user_id);
CREATE TABLE auth_device_groups (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE
);
CREATE TABLE auth_device_group_hosts (
    group_id TEXT NOT NULL REFERENCES auth_device_groups(id) ON DELETE CASCADE,
    host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    PRIMARY KEY(group_id,host_id)
);
CREATE TABLE auth_user_scope (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    scope TEXT NOT NULL CHECK(scope IN ('all','groups'))
);
INSERT INTO auth_user_scope(user_id,scope) SELECT id,'all' FROM users;
CREATE TABLE auth_device_grants (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id TEXT NOT NULL REFERENCES auth_device_groups(id) ON DELETE CASCADE,
    permission TEXT NOT NULL CHECK(permission IN ('view','operate')),
    PRIMARY KEY(user_id,group_id)
);
