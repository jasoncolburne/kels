-- KELS Gossip schema
BEGIN;

-- Registry KELs: local copy of registry key events for anchoring verification
-- Synced and verified from registries, then queried locally for anchoring checks
CREATE TABLE IF NOT EXISTS registry_key_events (
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

CREATE INDEX IF NOT EXISTS idx_registry_key_events_prefix ON registry_key_events(prefix);
CREATE INDEX IF NOT EXISTS idx_registry_key_events_prefix_serial ON registry_key_events(prefix, serial);
CREATE INDEX IF NOT EXISTS idx_registry_key_events_prefix_previous ON registry_key_events(prefix, previous);

CREATE TABLE IF NOT EXISTS registry_key_event_signatures (
    said TEXT PRIMARY KEY,
    event_said TEXT NOT NULL REFERENCES registry_key_events(said) ON DELETE CASCADE,
    label TEXT NOT NULL,
    signature TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_registry_key_event_sigs_event_said ON registry_key_event_signatures(event_said);

-- Recovery audit records for registry KELs (local copy)
CREATE TABLE IF NOT EXISTS registry_recovery (
    said TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL,
    kel_prefix TEXT NOT NULL,
    recovery_serial BIGINT NOT NULL,
    diverged_at BIGINT NOT NULL,
    rec_previous TEXT NOT NULL,
    owner_first_serial BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_registry_recovery_kel_prefix ON registry_recovery(kel_prefix);

-- Archive tables for registry KELs
CREATE TABLE IF NOT EXISTS registry_archived_events (LIKE registry_key_events INCLUDING ALL);
CREATE TABLE IF NOT EXISTS registry_archived_event_signatures (LIKE registry_key_event_signatures INCLUDING ALL);
ALTER TABLE registry_archived_event_signatures
    ADD CONSTRAINT fk_archived_sigs_event FOREIGN KEY (event_said)
    REFERENCES registry_archived_events(said) ON DELETE CASCADE;

COMMIT;
