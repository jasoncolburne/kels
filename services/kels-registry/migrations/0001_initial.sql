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
    active BOOLEAN NOT NULL,
    -- Peer scope: 'core' (replicated across federation) or 'regional' (local only)
    scope VARCHAR(16) NOT NULL,
    -- HTTP URL for the KELS service
    kels_url TEXT NOT NULL,
    -- libp2p multiaddr for gossip connections
    gossip_multiaddr TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_peer_prefix ON peer(prefix);
CREATE INDEX IF NOT EXISTS idx_peer_version ON peer(prefix, version DESC);
CREATE INDEX IF NOT EXISTS idx_peer_active ON peer(peer_id) WHERE active = true;
CREATE UNIQUE INDEX IF NOT EXISTS idx_peer_prefix_version_unique ON peer(prefix, version);
CREATE UNIQUE INDEX IF NOT EXISTS idx_peer_node_version_unique ON peer(node_id, version);
-- Index for querying by scope
CREATE INDEX IF NOT EXISTS idx_peer_scope ON peer(scope) WHERE active = true;

-- Raft consensus state for federation (content-addressed, chained)
-- Each registry maintains its own Raft state keyed by node_id

-- Raft vote state (chained by prefix, queryable by node_id)
CREATE TABLE IF NOT EXISTS raft_vote (
    said CHAR(44) PRIMARY KEY,
    prefix CHAR(44) NOT NULL,
    previous CHAR(44),
    version BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    node_id BIGINT NOT NULL,
    term BIGINT NOT NULL,
    voted_for BIGINT,
    committed BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_raft_vote_prefix ON raft_vote(prefix);
CREATE INDEX IF NOT EXISTS idx_raft_vote_node_id ON raft_vote(node_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_raft_vote_prefix_version ON raft_vote(prefix, version);
CREATE UNIQUE INDEX IF NOT EXISTS idx_raft_vote_node_version ON raft_vote(node_id, version);

-- Raft log entries (chained by prefix, queryable by node_id)
CREATE TABLE IF NOT EXISTS raft_log (
    said CHAR(44) PRIMARY KEY,
    prefix CHAR(44) NOT NULL,
    previous CHAR(44),
    version BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    node_id BIGINT NOT NULL,
    log_index BIGINT NOT NULL,
    term BIGINT NOT NULL,
    -- Node ID of the leader that proposed this entry (for advanced LeaderId)
    leader_node_id BIGINT NOT NULL,
    payload_type TEXT NOT NULL,
    payload_data TEXT
);

CREATE INDEX IF NOT EXISTS idx_raft_log_prefix ON raft_log(prefix);
CREATE INDEX IF NOT EXISTS idx_raft_log_node_id ON raft_log(node_id);
CREATE INDEX IF NOT EXISTS idx_raft_log_node_index ON raft_log(node_id, log_index);
CREATE UNIQUE INDEX IF NOT EXISTS idx_raft_log_prefix_version ON raft_log(prefix, version);
CREATE UNIQUE INDEX IF NOT EXISTS idx_raft_log_node_version ON raft_log(node_id, version);

-- Raft state metadata (chained by prefix, queryable by node_id)
CREATE TABLE IF NOT EXISTS raft_state (
    said CHAR(44) PRIMARY KEY,
    prefix CHAR(44) NOT NULL,
    previous CHAR(44),
    version BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    node_id BIGINT NOT NULL,
    last_purged_index BIGINT,
    last_purged_term BIGINT,
    -- Node ID of leader for last purged entry (for advanced LeaderId)
    last_purged_node_id BIGINT,
    committed_index BIGINT,
    committed_term BIGINT,
    -- Node ID of leader for committed entry (for advanced LeaderId)
    committed_node_id BIGINT
);

CREATE INDEX IF NOT EXISTS idx_raft_state_prefix ON raft_state(prefix);
CREATE INDEX IF NOT EXISTS idx_raft_state_node_id ON raft_state(node_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_raft_state_prefix_version ON raft_state(prefix, version);
CREATE UNIQUE INDEX IF NOT EXISTS idx_raft_state_node_version ON raft_state(node_id, version);

-- Raft log audit records (for truncate/purge operations)
CREATE TABLE IF NOT EXISTS raft_log_audit (
    said CHAR(44) PRIMARY KEY,
    node_id BIGINT NOT NULL,
    operation TEXT NOT NULL,
    entries_json TEXT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_raft_log_audit_node_id ON raft_log_audit(node_id);
CREATE INDEX IF NOT EXISTS idx_raft_log_audit_recorded_at ON raft_log_audit(recorded_at);

COMMIT;
