-- Private rollback records; never included in public app settings or responses.
CREATE TABLE wireguard_imports (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    status TEXT NOT NULL DEFAULT 'applied',
    before_snapshot TEXT NOT NULL,
    after_snapshot TEXT NOT NULL,
    inserted_ids TEXT NOT NULL
);
