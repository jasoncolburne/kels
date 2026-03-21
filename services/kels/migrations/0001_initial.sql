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

-- Audit records table
CREATE TABLE IF NOT EXISTS kels_audit_records (
    said TEXT PRIMARY KEY,
    kel_prefix TEXT NOT NULL,
    kind TEXT NOT NULL,
    data_json TEXT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS kels_audit_records_kel_prefix_idx ON kels_audit_records(kel_prefix);
CREATE INDEX IF NOT EXISTS kels_audit_records_kind_idx ON kels_audit_records(kind);

COMMIT;
