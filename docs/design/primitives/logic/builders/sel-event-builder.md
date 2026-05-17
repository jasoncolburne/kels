# SelEventBuilder

**Canonical name:** `SelEventBuilder`

Constructs structurally-valid SEL events (`Icp`, `Est`, `Upd`, `Sea`, `Rpr`, `Cnt`, `Dec`), wiring `previous`, `serial`, `identity` (on `Icp`), `ielEvent` (on every v1+ kind), and `content`. Used by [`SadEventBuilder`](sad-event-builder.md) and by callers producing SEL events directly. Repair construction derives the boundary uniformly (`boundary = surviving_tip.serial`) per the SEL repair-workflow.

**Consumers:** SAD event builder; CLI; per-peer address-SEL publishers; credential-issuance flows.

**Dependencies:** [`../../data/event-logs/sel/events.md`](../../data/event-logs/sel/events.md), [`../../data/event-logs/sel/event-log.md`](../../data/event-logs/sel/event-log.md), [`../../data/event-logs/sel/repair-workflow.md`](../../data/event-logs/sel/repair-workflow.md).

Stub. Detailed content lands iteratively.
