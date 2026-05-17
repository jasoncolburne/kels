-- Identity Service Initial Schema
-- HSM key bindings, authority mappings, and local KEL copy

-- HSM key bindings - maps KEL state to HSM key handles
CREATE TABLE IF NOT EXISTS identity_hsm_key_bindings (
    said TEXT PRIMARY KEY,
    prefix TEXT NOT NULL,
    previous TEXT,
    version BIGINT NOT NULL,
    kel_prefix TEXT NOT NULL,
    current_key_handle TEXT NOT NULL,
    next_key_handle TEXT NOT NULL,
    recovery_key_handle TEXT NOT NULL,
    signing_generation BIGINT NOT NULL,
    recovery_generation BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_hsm_bindings_prefix ON identity_hsm_key_bindings(prefix);
CREATE INDEX IF NOT EXISTS idx_hsm_bindings_kel_prefix ON identity_hsm_key_bindings(kel_prefix);
CREATE UNIQUE INDEX IF NOT EXISTS idx_hsm_bindings_prefix_version ON identity_hsm_key_bindings(prefix, version);

-- Authority mapping - maps name to KEL prefix
CREATE TABLE IF NOT EXISTS identity_authority (
    said TEXT PRIMARY KEY,
    prefix TEXT NOT NULL,
    previous TEXT,
    version BIGINT NOT NULL,
    name TEXT NOT NULL,
    kel_prefix TEXT NOT NULL,
    last_said TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_authority_prefix ON identity_authority(prefix);
CREATE INDEX IF NOT EXISTS idx_authority_name ON identity_authority(name);
CREATE UNIQUE INDEX IF NOT EXISTS idx_authority_prefix_version ON identity_authority(prefix, version);

-- Key events - local copy of the authority's KEL
CREATE TABLE IF NOT EXISTS identity_key_events (
    said TEXT PRIMARY KEY,
    prefix TEXT NOT NULL,
    previous TEXT,
    serial BIGINT NOT NULL,
    public_key TEXT,
    rotation_hash TEXT,
    kind TEXT NOT NULL,
    anchor TEXT,
    delegating_prefix TEXT,
    recovery_key TEXT,
    recovery_hash TEXT
);

CREATE INDEX IF NOT EXISTS idx_key_events_prefix ON identity_key_events(prefix);
CREATE INDEX IF NOT EXISTS idx_key_events_prefix_serial ON identity_key_events(prefix, serial);
CREATE INDEX IF NOT EXISTS idx_key_events_prefix_previous ON identity_key_events(prefix, previous);

-- Signatures for key events
CREATE TABLE IF NOT EXISTS identity_key_event_signatures (
    said TEXT PRIMARY KEY,
    event_said TEXT NOT NULL REFERENCES identity_key_events(said) ON DELETE CASCADE,
    label TEXT NOT NULL,
    signature TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_identity_key_event_signatures_event_said ON identity_key_event_signatures(event_said);
CREATE UNIQUE INDEX IF NOT EXISTS idx_identity_key_event_signatures_event_label ON identity_key_event_signatures(event_said, label);

-- Recovery audit records for identity KEL
CREATE TABLE IF NOT EXISTS identity_recovery (
    said TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL,
    kel_prefix TEXT NOT NULL,
    recovery_serial BIGINT NOT NULL,
    diverged_at BIGINT NOT NULL,
    rec_previous TEXT NOT NULL,
    owner_first_serial BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_identity_recovery_kel_prefix ON identity_recovery(kel_prefix);

-- Archive tables for identity KEL
CREATE TABLE IF NOT EXISTS identity_archived_events (LIKE identity_key_events INCLUDING ALL);
CREATE TABLE IF NOT EXISTS identity_archived_event_signatures (LIKE identity_key_event_signatures INCLUDING ALL);
ALTER TABLE identity_archived_event_signatures
    ADD CONSTRAINT fk_archived_sigs_event FOREIGN KEY (event_said)
    REFERENCES identity_archived_events(said) ON DELETE CASCADE;

CREATE TABLE IF NOT EXISTS identity_recovery_events (
    said TEXT PRIMARY KEY,
    recovery_said TEXT NOT NULL REFERENCES identity_recovery(said) ON DELETE CASCADE,
    event_said TEXT NOT NULL REFERENCES identity_archived_events(said) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS identity_recovery_events_recovery_idx ON identity_recovery_events(recovery_said);

-- Identity Event Log (IEL) events — local copy of the node's own IEL.
--
-- The identity service is the source of truth for the node's own KEL, IEL,
-- and address SEL; the kels and sadstore services hold infrastructure-
-- distributed copies. The schema mirrors `sadstore.iel_events` so events
-- round-trip without re-serialization (same column shape => same SAID).
--
-- No archive table: IEL has no `Rpr` kind, and the node never diverges its
-- own chain (it is the sole signer). Divergence/contest handling lives in
-- sadstore; here the identity service produces events and pushes them out.
CREATE TABLE IF NOT EXISTS identity_iel_events (
    said TEXT PRIMARY KEY,
    prefix TEXT NOT NULL,
    previous TEXT,
    version BIGINT NOT NULL,
    topic TEXT NOT NULL,
    kind TEXT NOT NULL,              -- kels/iel/v1/events/{icp,evl,cnt,dec}
    auth_policy TEXT NOT NULL,       -- declared at Icp; preserved or evolved at Evl (at least one of auth/governance MUST evolve per Evl); preserved at Cnt/Dec
    governance_policy TEXT NOT NULL  -- same shape
);

CREATE INDEX IF NOT EXISTS identity_iel_events_prefix_idx ON identity_iel_events(prefix);

-- SAD Event Log (SEL) events — local copy of the node's own per-peer SELs
-- (`peer/services` and `peer/gossip` at the deterministic prefixes derived
-- from the peer identity + topic; see `lib/kels/src/types/federation/peer_publication.rs`).
--
-- Column shape mirrors sadstore's SEL table (which sadstore confusingly calls
-- `sad_events`); identity uses the precise `identity_sel_events` name so the
-- IEL/SEL parity is visible in the schema.
--
-- Identity owns and signs its address SEL; the infrastructure copy lives in
-- sadstore and is gossip-replicated.
--
-- No archive: identity-owned SELs are single-author and don't diverge or
-- repair locally; if a divergence ever appears in the infrastructure copy it
-- is observed there, not here.
CREATE TABLE IF NOT EXISTS identity_sel_events (
    said TEXT PRIMARY KEY,
    prefix TEXT NOT NULL,
    previous TEXT,
    version BIGINT NOT NULL,
    topic TEXT NOT NULL,
    content TEXT,
    kind TEXT NOT NULL,              -- kels/sad/v1/events/{icp,upd,sea,rpr,cnt,dec}
    identity TEXT,                   -- non-NULL only on Icp; participates in chain prefix derivation alongside `topic`
    identity_event TEXT              -- NULL on Icp; NOT NULL on every v1+ kind (SAID of authorizing IEL event)
);

CREATE INDEX IF NOT EXISTS identity_sel_events_prefix_idx ON identity_sel_events(prefix);

-- SAD object cache — layer 0 of identity's CascadingSadStore
-- [RepositorySadStore, RemoteSadStore]. Holds SAD bodies the node authored,
-- plus any remote bodies cached on a previous fetch.
--
-- `said` is the entry's own SAID (derived from `(object_said, object)` via
-- the SelfAddressed derive). `object_said` is the contained SAD's own SAID
-- — what consumers look up by — and is unique. Identical objects produce
-- identical SAIDs at both levels, so `ON CONFLICT DO NOTHING` on `said` is
-- idempotent.
CREATE TABLE IF NOT EXISTS identity_sad_objects (
    said TEXT PRIMARY KEY,
    object_said TEXT NOT NULL,
    object JSONB NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS identity_sad_objects_object_said_idx
    ON identity_sad_objects(object_said);
