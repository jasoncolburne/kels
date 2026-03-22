-- KELS initial schema for PostgreSQL
BEGIN;

-- Key events table
CREATE TABLE IF NOT EXISTS kels_key_events (
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

CREATE INDEX IF NOT EXISTS kels_key_events_prefix_idx ON kels_key_events(prefix);
CREATE INDEX IF NOT EXISTS kels_key_events_prefix_serial_idx ON kels_key_events(prefix, serial);
CREATE INDEX IF NOT EXISTS kels_key_events_prefix_previous_idx ON kels_key_events(prefix, previous);

-- Signatures table
CREATE TABLE IF NOT EXISTS kels_key_event_signatures (
    said TEXT PRIMARY KEY,
    event_said TEXT NOT NULL,
    label TEXT NOT NULL,
    signature TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS kels_key_event_signatures_event_said_idx ON kels_key_event_signatures(event_said);
CREATE UNIQUE INDEX IF NOT EXISTS kels_key_event_signatures_event_said_label_idx ON kels_key_event_signatures(event_said, label);

-- Recovery tracking: chained records for async adversary archival.
-- Each state transition creates a new version; records are never deleted.
CREATE TABLE IF NOT EXISTS kels_recovery (
    said TEXT PRIMARY KEY,
    prefix TEXT NOT NULL,
    previous TEXT,
    version BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    kel_prefix TEXT NOT NULL,
    recovery_serial BIGINT NOT NULL,
    diverged_at BIGINT NOT NULL,
    rec_previous TEXT NOT NULL,
    owner_first_serial BIGINT NOT NULL,
    state TEXT NOT NULL,
    cursor_serial BIGINT NOT NULL,
    adversary_tip_said TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_kels_recovery_prefix_version ON kels_recovery(prefix, version);
CREATE UNIQUE INDEX IF NOT EXISTS idx_kels_recovery_kel_prefix_version ON kels_recovery(kel_prefix, version);
CREATE INDEX IF NOT EXISTS idx_kels_recovery_kel_prefix ON kels_recovery(kel_prefix);

-- Archive tables: mirror the live tables for adversary events moved during recovery.
-- Full picture is reconstructable by joining live + archived tables on prefix,
-- with kels_recovery providing provenance.
CREATE TABLE IF NOT EXISTS kels_archived_events (LIKE kels_key_events INCLUDING ALL);
CREATE TABLE IF NOT EXISTS kels_archived_event_signatures (LIKE kels_key_event_signatures INCLUDING ALL);

COMMIT;
