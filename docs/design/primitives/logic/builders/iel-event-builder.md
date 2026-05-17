# IelEventBuilder

**Canonical name:** `IelEventBuilder`

Constructs structurally-valid IEL events (`Icp`, `Evl`, `Sea`, `Cnt`, `Dec`), wiring `previous`, `serial`, and policy field discipline (`authPolicy` / `governancePolicy` per kind). Used by [`SadEventBuilder`](sad-event-builder.md) and by callers producing IEL events directly.

**Consumers:** SAD event builder; CLI; identity-bootstrap flows (federation IEL).

**Dependencies:** [`../../data/event-logs/iel/events.md`](../../data/event-logs/iel/events.md), [`../../data/event-logs/iel/event-log.md`](../../data/event-logs/iel/event-log.md).

Stub. Detailed content lands iteratively.
