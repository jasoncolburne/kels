-- KELS initial schema for PostgreSQL
BEGIN;

-- Key events table
CREATE TABLE IF NOT EXISTS kels_key_events (
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
    delegating_prefix CHAR(44)
);

CREATE INDEX IF NOT EXISTS kels_key_events_prefix_idx ON kels_key_events(prefix);
CREATE INDEX IF NOT EXISTS kels_key_events_prefix_serial_idx ON kels_key_events(prefix, serial);
CREATE INDEX IF NOT EXISTS kels_key_events_prefix_previous_idx ON kels_key_events(prefix, previous);

-- Signatures table
CREATE TABLE IF NOT EXISTS kels_key_event_signatures (
    said CHAR(44) PRIMARY KEY,
    event_said CHAR(44) NOT NULL,
    label TEXT NOT NULL,
    signature TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS kels_key_event_signatures_event_said_idx ON kels_key_event_signatures(event_said);
CREATE UNIQUE INDEX IF NOT EXISTS kels_key_event_signatures_event_said_label_idx ON kels_key_event_signatures(event_said, label);

-- Audit records table
CREATE TABLE IF NOT EXISTS kels_audit_records (
    said CHAR(44) PRIMARY KEY,
    kel_prefix CHAR(44) NOT NULL,
    kind TEXT NOT NULL,
    data_json TEXT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS kels_audit_records_kel_prefix_idx ON kels_audit_records(kel_prefix);
CREATE INDEX IF NOT EXISTS kels_audit_records_kind_idx ON kels_audit_records(kind);

COMMIT;
