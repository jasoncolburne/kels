-- KELS Registry schema
BEGIN;

-- Raft consensus state for federation (content-addressed, chained)
-- Each registry maintains its own Raft state keyed by node_id

-- Raft vote state (chained by prefix, queryable by node_id)
CREATE TABLE IF NOT EXISTS raft_vote (
    said TEXT PRIMARY KEY,
    prefix TEXT NOT NULL,
    previous TEXT,
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
    said TEXT PRIMARY KEY,
    prefix TEXT NOT NULL,
    previous TEXT,
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
    said TEXT PRIMARY KEY,
    prefix TEXT NOT NULL,
    previous TEXT,
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
    said TEXT PRIMARY KEY,
    node_id BIGINT NOT NULL,
    operation TEXT NOT NULL,
    entries_json TEXT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_raft_log_audit_node_id ON raft_log_audit(node_id);
CREATE INDEX IF NOT EXISTS idx_raft_log_audit_recorded_at ON raft_log_audit(recorded_at);

-- Member KELs: stores key events for federation members (replicated via Raft)
-- Same schema as kels_key_events but in the registry database
CREATE TABLE IF NOT EXISTS member_key_events (
    said TEXT PRIMARY KEY,
    prefix TEXT NOT NULL,
    previous TEXT,
    serial BIGINT NOT NULL,
    public_key TEXT,
    rotation_hash TEXT,
    recovery_key TEXT,
    recovery_hash TEXT,
    kind TEXT NOT NULL,
    anchor TEXT,
    delegating_prefix TEXT
);

CREATE INDEX IF NOT EXISTS idx_member_key_events_prefix ON member_key_events(prefix);
CREATE INDEX IF NOT EXISTS idx_member_key_events_prefix_serial ON member_key_events(prefix, serial);
CREATE INDEX IF NOT EXISTS idx_member_key_events_prefix_previous ON member_key_events(prefix, previous);

CREATE TABLE IF NOT EXISTS member_key_event_signatures (
    said TEXT PRIMARY KEY,
    event_said TEXT NOT NULL,
    label TEXT NOT NULL,
    signature TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_member_key_event_sigs_event_said ON member_key_event_signatures(event_said);

-- Recovery audit records for member KELs
CREATE TABLE IF NOT EXISTS member_recovery (
    said TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL,
    kel_prefix TEXT NOT NULL,
    recovery_serial BIGINT NOT NULL,
    diverged_at BIGINT NOT NULL,
    rec_previous TEXT NOT NULL,
    owner_first_serial BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_member_recovery_kel_prefix ON member_recovery(kel_prefix);

-- Archive tables for member KELs
CREATE TABLE IF NOT EXISTS member_archived_events (LIKE member_key_events INCLUDING ALL);
CREATE TABLE IF NOT EXISTS member_archived_event_signatures (LIKE member_key_event_signatures INCLUDING ALL);

COMMIT;
