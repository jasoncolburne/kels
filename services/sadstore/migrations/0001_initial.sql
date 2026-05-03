-- KELS SADStore initial schema for PostgreSQL
BEGIN;

-- SAD Event Log events table.
--
-- Round 12: SE chains are identity-rooted (bound to an IEL via `identity` at
-- Icp; subsequent events bind via `identity_event` to a specific IEL event
-- whose policy authorizes them). Pre-round-12 `write_policy` /
-- `governance_policy` columns are gone — those policy values now live on
-- the IEL and are resolved on demand. See `docs/design/sel/events.md`.
CREATE TABLE IF NOT EXISTS sad_events (
    said TEXT PRIMARY KEY,
    prefix TEXT NOT NULL,
    previous TEXT,
    version BIGINT NOT NULL,
    topic TEXT NOT NULL,
    content TEXT,
    custody TEXT,                    -- SAID of custody SAD
    -- Event kind: one of kels/sad/v1/events/{icp,upd,sea,rpr,cnt,dec}
    kind TEXT NOT NULL,
    -- IEL prefix the chain is bound to. Non-NULL only on Icp; NULL on every
    -- other kind. Participates in chain prefix derivation alongside `topic`.
    identity TEXT,
    -- SAID of the IEL event whose policy authorizes this SE event. NULL on
    -- Icp (permissionless inception); NOT NULL on every v1+ kind.
    identity_event TEXT
);

CREATE INDEX IF NOT EXISTS sad_events_prefix_idx ON sad_events(prefix);

-- SAD object index (tracks which SAIDs exist in the object store for bootstrap/anti-entropy)
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

-- Cached policy SADs for evaluation without the object store round-trips
CREATE TABLE IF NOT EXISTS policies (
    said TEXT PRIMARY KEY,
    expression TEXT NOT NULL,
    poison TEXT,
    immune BOOLEAN
);

-- Archive tables: copies of events displaced by SEL repair
CREATE TABLE IF NOT EXISTS sad_event_archives (LIKE sad_events INCLUDING ALL);

-- SEL repair tracking: each repair is a first-class entity
CREATE TABLE IF NOT EXISTS sad_event_repairs (
    said TEXT PRIMARY KEY,
    event_prefix TEXT NOT NULL,
    diverged_at_version BIGINT NOT NULL,
    repaired_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS sad_event_repairs_prefix_idx ON sad_event_repairs(event_prefix);

-- Links a repair to the archived events it displaced
CREATE TABLE IF NOT EXISTS sel_repair_events (
    said TEXT PRIMARY KEY,
    repair_said TEXT NOT NULL REFERENCES sad_event_repairs(said) ON DELETE CASCADE,
    event_said TEXT NOT NULL REFERENCES sad_event_archives(said) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS sel_repair_events_repair_idx ON sel_repair_events(repair_said);

-- Identity Event Log (IEL) events. Mirrors `sad_events` shape but trims
-- fields IEL doesn't carry (no `content` / `custody` / `write_policy`) and
-- keeps `auth_policy` / `governance_policy` as NOT NULL (every IEL event
-- always declares both — see `docs/design/iel/events.md §Per-Kind Field Rules`).
--
-- No archive table: IEL has no `Rpr` kind. Divergence is preserved in-place
-- and resolved by `Cnt`. See `docs/design/iel/event-log.md §Divergence and
-- Contest-Only Resolution`.
CREATE TABLE IF NOT EXISTS iel_events (
    said TEXT PRIMARY KEY,
    prefix TEXT NOT NULL,
    previous TEXT,
    version BIGINT NOT NULL,
    topic TEXT NOT NULL,
    kind TEXT NOT NULL,              -- kels/iel/v1/events/{icp,evl,cnt,dec}
    auth_policy TEXT NOT NULL,       -- declared at Icp; preserved or evolved at Evl; preserved at Cnt/Dec
    governance_policy TEXT NOT NULL  -- same shape
);

CREATE INDEX IF NOT EXISTS iel_events_prefix_idx ON iel_events(prefix);

COMMIT;
