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
    event_said TEXT NOT NULL REFERENCES identity_key_events(said) ON DELETE CASCADE,
    label TEXT NOT NULL,
    signature TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_identity_key_event_signatures_event_said ON identity_key_event_signatures(event_said);
CREATE UNIQUE INDEX IF NOT EXISTS idx_identity_key_event_signatures_event_label ON identity_key_event_signatures(event_said, label);

-- Recovery audit records for identity KEL
CREATE TABLE IF NOT EXISTS identity_recovery (
    said TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL,
    kel_prefix TEXT NOT NULL,
    recovery_serial BIGINT NOT NULL,
    diverged_at BIGINT NOT NULL,
    rec_previous TEXT NOT NULL,
    owner_first_serial BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_identity_recovery_kel_prefix ON identity_recovery(kel_prefix);

-- Archive tables for identity KEL
CREATE TABLE IF NOT EXISTS identity_archived_events (LIKE identity_key_events INCLUDING ALL);
CREATE TABLE IF NOT EXISTS identity_archived_event_signatures (LIKE identity_key_event_signatures INCLUDING ALL);
ALTER TABLE identity_archived_event_signatures
    ADD CONSTRAINT fk_archived_sigs_event FOREIGN KEY (event_said)
    REFERENCES identity_archived_events(said) ON DELETE CASCADE;

CREATE TABLE IF NOT EXISTS identity_recovery_events (
    said TEXT PRIMARY KEY,
    recovery_said TEXT NOT NULL REFERENCES identity_recovery(said) ON DELETE CASCADE,
    event_said TEXT NOT NULL REFERENCES identity_archived_events(said) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS identity_recovery_events_recovery_idx ON identity_recovery_events(recovery_said);
