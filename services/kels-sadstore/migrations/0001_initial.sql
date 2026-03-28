-- KELS SADStore initial schema for PostgreSQL
BEGIN;

-- SAD chain records table
CREATE TABLE IF NOT EXISTS sad_records (
    said TEXT PRIMARY KEY,
    prefix TEXT NOT NULL,
    previous TEXT,
    version BIGINT NOT NULL,
    kel_prefix TEXT NOT NULL,
    kind TEXT NOT NULL,
    content_said TEXT
);

CREATE INDEX IF NOT EXISTS sad_records_prefix_idx ON sad_records(prefix);
CREATE UNIQUE INDEX IF NOT EXISTS sad_records_prefix_version_idx ON sad_records(prefix, version);

-- SAD record signatures (1:1 with sad_records, separate to keep SAID table clean)
CREATE TABLE IF NOT EXISTS sad_record_signatures (
    said TEXT PRIMARY KEY,
    record_said TEXT NOT NULL,
    signature TEXT NOT NULL,
    establishment_serial BIGINT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS sad_record_signatures_record_said_idx ON sad_record_signatures(record_said);

COMMIT;
