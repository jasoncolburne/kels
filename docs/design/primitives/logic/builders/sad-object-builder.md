# SadObjectBuilder

**Canonical name:** `SadObjectBuilder`

Convenience constructor for SAD objects — content + optional authority / replication wrapper fields + computed `said`. Abstracts the cross-cutting wrapper concerns (`ownerIelEvent`, `readPolicy`, `availability`) so callers don't repeat the boilerplate for every SAD-bearing surface (credentials, policy SADs, exchange envelopes, SEL `content`, etc.).

The wrapper shape per [../../../infrastructure/sadstore.md §Custody](../../../infrastructure/sadstore.md#custody-per-sad-object-authority) and §Availability:

- `ownerIelEvent: Option<Digest256>` — IEL **event** SAID. Write attestation; pins the writer's identity + tracked `authPolicy` at write time. Dereferencable for both point-in-time and identity-current verification. `None` for unsigned / anonymous writes.
- `readPolicy: Option<Digest256>` — policy SAID. Read enforcement at fetch time via `evaluate_signed_policy` against a verified prefix set. Composable (`identity(X)`, `threshold`, etc.). `None` for publicly readable content.
- `availability: Option<Availability>` — nested struct `{ nodes: Option<Digest256>, ttl: Option<u64>, once: Option<bool> }`. Replication + lifecycle. Sibling of custody, not part of it.

Convenience signature (sketch):

```rust
SadObjectBuilder::build(
    content: T,
    owner_iel_event: Option<Digest256>,
    read_policy: Option<Digest256>,
    availability: Option<Availability>,
) -> SadObject<T>
```

The builder computes the SAID over the canonical serialization (content + populated wrapper fields, with `said` blanked) and returns the assembled SAD object.

**Consumers:** credentials (`issuerIelEvent` / `subjectIelEvent` carried as SAD wrapper fields); exchange envelopes; policy SADs; any application-layer SAD-bearing surface; SEL `content` (the SEL event's `content` field is itself a SAD whose wrapper this builder produces).

**Dependencies:** [`../../data/sad/sad.md`](../../data/sad/sad.md) for the SAD shape, [`../../data/sad/said.md`](../../data/sad/said.md) for SAID computation, [`../../data/sad/custody.md`](../../data/sad/custody.md) for `ownerIelEvent` / `readPolicy` semantics, [`../../../infrastructure/sadstore.md`](../../../infrastructure/sadstore.md) for storage-side enforcement of the wrapper fields.

**Not to be confused with:** the per-primitive **event** builders ([`kel-event-builder.md`](kel-event-builder.md), [`iel-event-builder.md`](iel-event-builder.md), [`sel-event-builder.md`](sel-event-builder.md)), which produce chain events with `previous` / `serial` / chain-specific fields. SAD objects have no `previous` / `serial` — those are event-layer concepts.

**Impl-vs-doctrine gap (north star):** the code currently has `SadEventBuilder` (`lib/kels/src/sad_builder.rs`) that actually constructs SEL events. The doctrine-canonical naming is `SelEventBuilder` for that role and a new `SadObjectBuilder` for the SAD-wrapper construction described here. Code follow-up: rename `SadEventBuilder` → `SelEventBuilder`; add `SadObjectBuilder` as a new abstraction.

Stub. Content fills out as the SAD-builder surface settles.
