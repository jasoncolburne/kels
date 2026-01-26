-- Identity Service Initial Schema
-- HSM key bindings, authority mappings, and local KEL copy

-- HSM key bindings - maps KEL state to HSM key handles
CREATE TABLE IF NOT EXISTS identity_hsm_key_bindings (
    said CHAR(44) PRIMARY KEY,
    prefix CHAR(44) NOT NULL,
    previous CHAR(44),
    version BIGINT NOT NULL,
    kel_prefix CHAR(44) NOT NULL,
    current_key_handle TEXT NOT NULL,
    next_key_handle TEXT NOT NULL,
    recovery_key_handle TEXT NOT NULL,
    next_label_generation BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_hsm_bindings_prefix ON identity_hsm_key_bindings(prefix);
CREATE INDEX IF NOT EXISTS idx_hsm_bindings_kel_prefix ON identity_hsm_key_bindings(kel_prefix);
CREATE UNIQUE INDEX IF NOT EXISTS idx_hsm_bindings_prefix_version ON identity_hsm_key_bindings(prefix, version);

-- Authority mapping - maps name to KEL prefix
CREATE TABLE IF NOT EXISTS identity_authority (
    said CHAR(44) PRIMARY KEY,
    prefix CHAR(44) NOT NULL,
    previous CHAR(44),
    version BIGINT NOT NULL,
    name TEXT NOT NULL,
    kel_prefix CHAR(44) NOT NULL,
    last_said CHAR(44) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_authority_prefix ON identity_authority(prefix);
CREATE INDEX IF NOT EXISTS idx_authority_name ON identity_authority(name);
CREATE UNIQUE INDEX IF NOT EXISTS idx_authority_prefix_version ON identity_authority(prefix, version);

-- Key events - local copy of the authority's KEL
CREATE TABLE IF NOT EXISTS identity_key_events (
    said CHAR(44) PRIMARY KEY,
    prefix CHAR(44) NOT NULL,
    previous CHAR(44),
    version BIGINT NOT NULL,
    public_key CHAR(48),
    rotation_hash CHAR(44),
    kind VARCHAR(16) NOT NULL,
    anchor CHAR(44),
    delegating_prefix CHAR(44),
    recovery_key CHAR(48),
    recovery_hash CHAR(44),
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_key_events_prefix ON identity_key_events(prefix);
CREATE UNIQUE INDEX IF NOT EXISTS idx_key_events_prefix_version ON identity_key_events(prefix, version);

-- Signatures for key events
CREATE TABLE IF NOT EXISTS identity_key_event_signatures (
    said CHAR(44) PRIMARY KEY,
    event_said CHAR(44) NOT NULL,
    public_key CHAR(48) NOT NULL,
    signature CHAR(88) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_identity_key_event_signatures_event_said ON identity_key_event_signatures(event_said);
CREATE UNIQUE INDEX IF NOT EXISTS idx_identity_key_event_signatures_event_pk ON identity_key_event_signatures(event_said, public_key);
