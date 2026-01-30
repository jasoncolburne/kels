-- KELS initial schema for PostgreSQL
BEGIN;

-- Key events table
CREATE TABLE IF NOT EXISTS kels_key_events (
    said CHAR(44) PRIMARY KEY,
    prefix CHAR(44) NOT NULL,
    previous CHAR(44),
    public_key CHAR(48),
    rotation_hash CHAR(44),
    recovery_key CHAR(48),
    recovery_hash CHAR(44),
    kind VARCHAR(32) NOT NULL,
    anchor CHAR(44),
    delegating_prefix CHAR(44)
);

CREATE INDEX IF NOT EXISTS kels_key_events_prefix_idx ON kels_key_events(prefix);

-- Signatures table
CREATE TABLE IF NOT EXISTS kels_key_event_signatures (
    said CHAR(44) PRIMARY KEY,
    event_said CHAR(44) NOT NULL,
    public_key CHAR(48) NOT NULL,
    signature CHAR(88) NOT NULL
);

CREATE INDEX IF NOT EXISTS kels_key_event_signatures_event_said_idx ON kels_key_event_signatures(event_said);
CREATE UNIQUE INDEX IF NOT EXISTS kels_key_event_signatures_event_said_pk_idx ON kels_key_event_signatures(event_said, public_key);

-- Audit records table
CREATE TABLE IF NOT EXISTS kels_audit_records (
    said CHAR(44) PRIMARY KEY,
    kel_prefix CHAR(44) NOT NULL,
    kind VARCHAR(32) NOT NULL,
    data_json TEXT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS kels_audit_records_kel_prefix_idx ON kels_audit_records(kel_prefix);
CREATE INDEX IF NOT EXISTS kels_audit_records_kind_idx ON kels_audit_records(kind);

COMMIT;
