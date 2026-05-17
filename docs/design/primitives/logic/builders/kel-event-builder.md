# KelEventBuilder

**Canonical name:** `KelEventBuilder`

Constructs structurally-valid KEL events (`Icp`, `Dip`, `Ixn`, `Rot`, `Ror`, `Rec`, `Cnt`, `Dec`), wiring `previous`, `serial`, forward-key commitments (`rotationHash`, `recoveryHash`), and dual signatures on the recovery-revealing kinds. Used by [`SadEventBuilder`](sad-event-builder.md) and by callers that need to produce KEL events directly.

**Consumers:** SAD event builder; CLI; identity service; recovery and ROR ceremonies.

**Dependencies:** [`../../data/event-logs/kel/events.md`](../../data/event-logs/kel/events.md), [`../../data/event-logs/kel/event-log.md`](../../data/event-logs/kel/event-log.md), [`../../data/event-logs/kel/recovery-workflow.md`](../../data/event-logs/kel/recovery-workflow.md).

Stub. Detailed content lands iteratively.
