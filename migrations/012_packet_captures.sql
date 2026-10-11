-- Content-addressed raw captures; device deletion also removes its captures.
CREATE TABLE packet_captures (
    host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    digest TEXT NOT NULL,
    payload BLOB NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (host_id, digest)
);
CREATE INDEX idx_packet_captures_created ON packet_captures(host_id, created_at DESC);
