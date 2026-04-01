-- KELS SADStore initial schema for PostgreSQL
BEGIN;

-- SAD chain pointers table
CREATE TABLE IF NOT EXISTS sad_pointers (
    said TEXT PRIMARY KEY,
    prefix TEXT NOT NULL,
    previous TEXT,
    version BIGINT NOT NULL,
    kel_prefix TEXT NOT NULL,
    kind TEXT NOT NULL,
    content_said TEXT
);

CREATE INDEX IF NOT EXISTS sad_pointers_prefix_idx ON sad_pointers(prefix);
CREATE INDEX IF NOT EXISTS sad_pointers_prefix_version_idx ON sad_pointers(prefix, version);

-- SAD pointer signatures (1:1 with sad_pointers, separate to keep SAID table clean)
CREATE TABLE IF NOT EXISTS sad_pointer_signatures (
    said TEXT PRIMARY KEY,
    pointer_said TEXT NOT NULL REFERENCES sad_pointers(said) ON DELETE CASCADE,
    signature TEXT NOT NULL,
    establishment_serial BIGINT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS sad_pointer_signatures_pointer_said_idx ON sad_pointer_signatures(pointer_said);

-- SAD object index (tracks which SAIDs exist in MinIO for bootstrap/anti-entropy)
CREATE TABLE IF NOT EXISTS sad_objects (
    said TEXT PRIMARY KEY,
    sad_said TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS sad_objects_sad_said_idx ON sad_objects(sad_said);

-- Archive tables: pure copies of pointers/signatures for repaired chains
CREATE TABLE IF NOT EXISTS sad_pointer_archives (LIKE sad_pointers INCLUDING ALL);
CREATE TABLE IF NOT EXISTS sad_pointer_archive_signatures (LIKE sad_pointer_signatures INCLUDING ALL);
ALTER TABLE sad_pointer_archive_signatures
    ADD CONSTRAINT fk_archived_sigs_pointer FOREIGN KEY (pointer_said)
    REFERENCES sad_pointer_archives(said) ON DELETE CASCADE;

-- Chain repair tracking: each repair is a first-class entity
CREATE TABLE IF NOT EXISTS sad_pointer_repairs (
    said TEXT PRIMARY KEY,
    pointer_prefix TEXT NOT NULL,
    diverged_at_version BIGINT NOT NULL,
    repaired_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS sad_pointer_repairs_prefix_idx ON sad_pointer_repairs(pointer_prefix);

-- Links a repair to the archived pointers it displaced
CREATE TABLE IF NOT EXISTS sad_pointer_repair_records (
    said TEXT PRIMARY KEY,
    repair_said TEXT NOT NULL REFERENCES sad_pointer_repairs(said) ON DELETE CASCADE,
    pointer_said TEXT NOT NULL REFERENCES sad_pointer_archives(said) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS sad_pointer_repair_records_repair_idx ON sad_pointer_repair_records(repair_said);

COMMIT;
