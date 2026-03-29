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
CREATE INDEX IF NOT EXISTS sad_records_prefix_version_idx ON sad_records(prefix, version);

-- SAD record signatures (1:1 with sad_records, separate to keep SAID table clean)
CREATE TABLE IF NOT EXISTS sad_record_signatures (
    said TEXT PRIMARY KEY,
    record_said TEXT NOT NULL REFERENCES sad_records(said) ON DELETE CASCADE,
    signature TEXT NOT NULL,
    establishment_serial BIGINT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS sad_record_signatures_record_said_idx ON sad_record_signatures(record_said);

-- SAD object index (tracks which SAIDs exist in MinIO for bootstrap/anti-entropy)
CREATE TABLE IF NOT EXISTS sad_objects (
    said TEXT PRIMARY KEY,
    sad_said TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS sad_objects_sad_said_idx ON sad_objects(sad_said);

-- Archive tables: pure copies of records/signatures for repaired chains
CREATE TABLE IF NOT EXISTS sad_record_archives (LIKE sad_records INCLUDING ALL);
CREATE TABLE IF NOT EXISTS sad_record_archive_signatures (LIKE sad_record_signatures INCLUDING ALL);
ALTER TABLE sad_record_archive_signatures
    ADD CONSTRAINT fk_archived_sigs_record FOREIGN KEY (record_said)
    REFERENCES sad_record_archives(said) ON DELETE CASCADE;

-- Chain repair tracking: each repair is a first-class entity
CREATE TABLE IF NOT EXISTS sad_chain_repairs (
    said TEXT PRIMARY KEY,
    record_prefix TEXT NOT NULL,
    diverged_at_version BIGINT NOT NULL,
    repaired_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS sad_chain_repairs_prefix_idx ON sad_chain_repairs(record_prefix);

-- Links a repair to the archived records it displaced
CREATE TABLE IF NOT EXISTS sad_chain_repair_records (
    said TEXT PRIMARY KEY,
    repair_said TEXT NOT NULL REFERENCES sad_chain_repairs(said) ON DELETE CASCADE,
    record_said TEXT NOT NULL REFERENCES sad_record_archives(said) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS sad_chain_repair_records_repair_idx ON sad_chain_repair_records(repair_said);

COMMIT;
