-- Identity Event Log (IEL) schema. Mirrors `sad_events` shape but trims
-- fields IEL doesn't carry (no `content` / `custody` / `write_policy`) and
-- keeps `auth_policy` / `governance_policy` as NOT NULL (every IEL event
-- always declares both — see `docs/design/iel/events.md §Per-Kind Field Rules`).
--
-- No archive table: IEL has no `Rpr` kind. Divergence is preserved in-place
-- and resolved by `Cnt`. See `docs/design/iel/event-log.md §Divergence and
-- Contest-Only Resolution`.
BEGIN;

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
