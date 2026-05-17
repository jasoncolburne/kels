# SadEventBuilder

**Canonical name:** `SadEventBuilder`

The composition root for SAD-bearing event construction across KEL/IEL/SEL. Produces canonically-shaped events (correct field set per kind, parent linkage, derived `said`/`prefix`, and any required pre-commitments) without exposing the per-primitive event-kind shape to the caller. Drives [`KelEventBuilder`](kel-event-builder.md), [`IelEventBuilder`](iel-event-builder.md), and [`SelEventBuilder`](sel-event-builder.md).

**Consumers:** higher-level operator workflows (CLI builders, gossip-driven recovery/repair flows, federation enrollment).

**Dependencies:** chain primitives (KEL/IEL/SEL event-log docs under [`../../data/event-logs/`](../../data/event-logs/)); cesr types for cryptographic material.

Stub. Detailed content lands iteratively as the builder surface settles.
