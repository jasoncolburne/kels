-- KELS Gossip schema
BEGIN;

-- Registry KELs: local copy of registry key events for anchoring verification
-- Synced and verified from registries, then queried locally for anchoring checks
CREATE TABLE IF NOT EXISTS registry_key_events (
    said CHAR(44) PRIMARY KEY,
    prefix CHAR(44) NOT NULL,
    previous CHAR(44),
    serial BIGINT NOT NULL,
    public_key TEXT,
    rotation_hash CHAR(44),
    recovery_key TEXT,
    recovery_hash CHAR(44),
    kind TEXT NOT NULL,
    anchor CHAR(44),
    delegating_prefix CHAR(44),
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_registry_key_events_prefix ON registry_key_events(prefix);
CREATE UNIQUE INDEX IF NOT EXISTS idx_registry_key_events_prefix_serial ON registry_key_events(prefix, serial);

CREATE TABLE IF NOT EXISTS registry_key_event_signatures (
    said CHAR(44) PRIMARY KEY,
    event_said CHAR(44) NOT NULL,
    public_key TEXT NOT NULL,
    signature TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_registry_key_event_sigs_event_said ON registry_key_event_signatures(event_said);

COMMIT;
