-- KELS Registry peer allowlist schema
BEGIN;

CREATE TABLE IF NOT EXISTS peer (
    said CHAR(44) PRIMARY KEY,
    prefix CHAR(44) NOT NULL,
    previous CHAR(44),
    version BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    peer_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    active BOOLEAN NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_peer_prefix ON peer(prefix);
CREATE INDEX IF NOT EXISTS idx_peer_version ON peer(prefix, version DESC);
CREATE INDEX IF NOT EXISTS idx_peer_active ON peer(peer_id) WHERE active = true;
CREATE UNIQUE INDEX IF NOT EXISTS idx_peer_prefix_version_unique ON peer(prefix, version);
CREATE UNIQUE INDEX IF NOT EXISTS idx_peer_node_version_unique ON peer(node_id, version);

COMMIT;
