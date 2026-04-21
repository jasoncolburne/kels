-- KELS SADStore initial schema for PostgreSQL
BEGIN;

-- SAD chain pointers table
CREATE TABLE IF NOT EXISTS sad_pointers (
    said TEXT PRIMARY KEY,
    prefix TEXT NOT NULL,
    previous TEXT,
    version BIGINT NOT NULL,
    topic TEXT NOT NULL,
    content TEXT,
    custody TEXT,                    -- SAID of custody SAD
    write_policy TEXT,               -- required on Icp, optional on Evl, forbidden on Est/Upd/Rpr
    kind TEXT NOT NULL,              -- record kind (kels/sad/v1/pointer/{icp,upd,est,evl,rpr})
    checkpoint_policy TEXT           -- SAID of checkpoint policy (higher threshold than write_policy)
);

CREATE INDEX IF NOT EXISTS sad_pointers_prefix_idx ON sad_pointers(prefix);

-- SAD object index (tracks which SAIDs exist in MinIO for bootstrap/anti-entropy)
CREATE TABLE IF NOT EXISTS sad_objects (
    said TEXT PRIMARY KEY,
    sad_said TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    custody TEXT                     -- SAID of custody SAD (nullable, absent = no custody)
);

CREATE UNIQUE INDEX IF NOT EXISTS sad_objects_sad_said_idx ON sad_objects(sad_said);
CREATE INDEX IF NOT EXISTS sad_objects_custody_idx ON sad_objects(custody);

-- Cached custody SADs for fetch-time hot path (one row per distinct custody config)
CREATE TABLE IF NOT EXISTS custodies (
    said TEXT PRIMARY KEY,
    write_policy TEXT,
    read_policy TEXT,
    ttl BIGINT,
    once BOOLEAN,
    nodes TEXT                       -- SAID of NodeSet SAD
);

-- Cached policy SADs for evaluation without MinIO round-trips
CREATE TABLE IF NOT EXISTS policies (
    said TEXT PRIMARY KEY,
    expression TEXT NOT NULL,
    poison TEXT,
    immune BOOLEAN
);

-- Archive tables: copies of pointers for repaired chains
CREATE TABLE IF NOT EXISTS sad_pointer_archives (LIKE sad_pointers INCLUDING ALL);

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
