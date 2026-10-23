-- Only client-encrypted preference archives are stored here. Never store a
-- passphrase, enrollment credential or per-device runtime configuration.
CREATE TABLE auth_preferences (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    slot TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(revision > 0),
    updated_at INTEGER NOT NULL,
    envelope TEXT, -- NULL is a deletion tombstone; revisions never reset
    PRIMARY KEY(user_id, slot)
);
