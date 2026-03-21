-- Identity Service Initial Schema
-- HSM key bindings, authority mappings, and local KEL copy

-- HSM key bindings - maps KEL state to HSM key handles
CREATE TABLE IF NOT EXISTS identity_hsm_key_bindings (
    said TEXT PRIMARY KEY,
    prefix TEXT NOT NULL,
    previous TEXT,
    version BIGINT NOT NULL,
    kel_prefix TEXT NOT NULL,
    current_key_handle TEXT NOT NULL,
    next_key_handle TEXT NOT NULL,
    recovery_key_handle TEXT NOT NULL,
    signing_generation BIGINT NOT NULL,
    recovery_generation BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_hsm_bindings_prefix ON identity_hsm_key_bindings(prefix);
CREATE INDEX IF NOT EXISTS idx_hsm_bindings_kel_prefix ON identity_hsm_key_bindings(kel_prefix);
CREATE UNIQUE INDEX IF NOT EXISTS idx_hsm_bindings_prefix_version ON identity_hsm_key_bindings(prefix, version);

-- Authority mapping - maps name to KEL prefix
CREATE TABLE IF NOT EXISTS identity_authority (
    said TEXT PRIMARY KEY,
    prefix TEXT NOT NULL,
    previous TEXT,
    version BIGINT NOT NULL,
    name TEXT NOT NULL,
    kel_prefix TEXT NOT NULL,
    last_said TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_authority_prefix ON identity_authority(prefix);
CREATE INDEX IF NOT EXISTS idx_authority_name ON identity_authority(name);
CREATE UNIQUE INDEX IF NOT EXISTS idx_authority_prefix_version ON identity_authority(prefix, version);

-- Key events - local copy of the authority's KEL
CREATE TABLE IF NOT EXISTS identity_key_events (
    said TEXT PRIMARY KEY,
    prefix TEXT NOT NULL,
    previous TEXT,
    serial BIGINT NOT NULL,
    public_key TEXT,
    rotation_hash TEXT,
    kind TEXT NOT NULL,
    anchor TEXT,
    delegating_prefix TEXT,
    recovery_key TEXT,
    recovery_hash TEXT
);

CREATE INDEX IF NOT EXISTS idx_key_events_prefix ON identity_key_events(prefix);
CREATE INDEX IF NOT EXISTS idx_key_events_prefix_serial ON identity_key_events(prefix, serial);
CREATE INDEX IF NOT EXISTS idx_key_events_prefix_previous ON identity_key_events(prefix, previous);

-- Signatures for key events
CREATE TABLE IF NOT EXISTS identity_key_event_signatures (
    said TEXT PRIMARY KEY,
    event_said TEXT NOT NULL,
    label TEXT NOT NULL,
    signature TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_identity_key_event_signatures_event_said ON identity_key_event_signatures(event_said);
CREATE UNIQUE INDEX IF NOT EXISTS idx_identity_key_event_signatures_event_label ON identity_key_event_signatures(event_said, label);
