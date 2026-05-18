# SelEventBuilder

**Canonical name:** `SelEventBuilder`

Constructs structurally-valid SEL events (`Icp`, `Est`, `Upd`, `Sea`, `Rpr`, `Cnt`, `Dec`), wiring `previous`, `serial`, `identity` (on `Icp`), `ielEvent` (on every v1+ kind), and `content`. The `content` field is itself a SAD constructed via [`SadObjectBuilder`](sad-object-builder.md). Repair construction derives the boundary uniformly (`boundary = surviving_tip.serial`) per the SEL repair-workflow.

**Consumers:** CLI; per-peer address-SEL publishers; credential-issuance flows; any caller producing SEL events.

**Dependencies:** [`../../data/event-logs/sel/events.md`](../../data/event-logs/sel/events.md), [`../../data/event-logs/sel/event-log.md`](../../data/event-logs/sel/event-log.md), [`../../data/event-logs/sel/repair-workflow.md`](../../data/event-logs/sel/repair-workflow.md), [`sad-object-builder.md`](sad-object-builder.md) for SAD-content construction.

**Impl-vs-doctrine gap (north star):** the code currently calls this builder `SadEventBuilder` (`lib/kels/src/sad_builder.rs`). The doctrine-canonical name is `SelEventBuilder` — this builder constructs **SEL events**, not generic SAD objects. The "SAD object" construction role belongs to [`SadObjectBuilder`](sad-object-builder.md), which is a distinct, new abstraction. Code follow-up: rename `SadEventBuilder` → `SelEventBuilder`.

Stub. Detailed content lands iteratively.
