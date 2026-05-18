# Custody

**Canonical name:** custody — per-SAD-object authority declarations attached to the SAD wrapper.

Custody declares who can write a SAD (`custody.write`) and who can read it (`custody.read`). Both are IEL-rooted references — `custody.write` is an IEL event SAID (one-time anchored write attestation; satisfied at write time, frozen at the bound event); `custody.read` is an IEL prefix (identity-current; resolved through the IEL's current `authPolicy` at read time).

Custody is **decoupled from availability** (replication + lifecycle; a sibling top-level field on the SAD wrapper). A SAD can be widely-replicated but custody-gated; an unreplicated SAD with permissive custody is publicly readable to anyone who has the SAID.

**Consumers:** [SadStore family](../../logic/stores/sad-store.md) (custody check at write + read), [SADStore service](../../../infrastructure/sadstore.md) (HTTP-level enforcement), [../../../features/creds.md](../../../features/creds.md) (credential custody).

**Dependencies:** [identity-rooting.md](identity-rooting.md), [../event-logs/iel/events.md](../event-logs/iel/events.md), [../../logic/verifiers/anchored-policy-checker.md](../../logic/verifiers/anchored-policy-checker.md).

Stub pending #173 design closure. The full custody surface (frozen-mode vs identity-current semantics, custody on chain events, write-time vs read-time enforcement, custody-derived effective SAIDs) lives in active design discussion at issue #173; this doc will consolidate the design-level statement once that closes.
