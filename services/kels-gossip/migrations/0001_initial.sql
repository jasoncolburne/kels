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
    event_said TEXT NOT NULL,
    label TEXT NOT NULL,
    signature TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_registry_key_event_sigs_event_said ON registry_key_event_signatures(event_said);

COMMIT;
