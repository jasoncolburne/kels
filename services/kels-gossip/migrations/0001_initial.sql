-- KELS Gossip initial schema for PostgreSQL

-- Peer cache table for registry fallback
CREATE TABLE IF NOT EXISTS kels_gossip_peers (
    said CHAR(44) PRIMARY KEY,
    prefix CHAR(44) NOT NULL,
    previous CHAR(44),
    version BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    node_id VARCHAR(255) NOT NULL,
    gossip_multiaddr TEXT NOT NULL,
    active BOOLEAN NOT NULL DEFAULT true
);

-- Unique constraint on (node_id, version) as requested
CREATE UNIQUE INDEX IF NOT EXISTS kels_gossip_peers_node_id_version_idx ON kels_gossip_peers(node_id, version);
-- Index for querying active peers
CREATE INDEX IF NOT EXISTS kels_gossip_peers_active_idx ON kels_gossip_peers(active);
-- Index for looking up latest version by node_id
CREATE INDEX IF NOT EXISTS kels_gossip_peers_node_id_idx ON kels_gossip_peers(node_id);
