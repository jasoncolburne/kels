# Custody

**Canonical name:** custody — the logical grouping of two flat top-level fields on the SAD wrapper that declare per-SAD-object authority.

Custody declares who can write a SAD (`ownerIelEvent`) and who can read it (`readPolicy`). The two fields sit as independent top-level optional fields on the SAD wrapper:

- `ownerIelEvent` is an IEL **event** SAID — a one-time anchored write attestation. It pins the writer's identity and tracked `authPolicy` at write time; a verifier can ask either "was the writer authorized under the `authPolicy` at *this event*?" (point-in-time lookup) or "is the writer's identity still authorized at the *current* tip?" (dereference → IEL prefix → walk to tip → resolve current `authPolicy`). Both modes derive from one SAID. `None` for anonymous writes.
- `readPolicy` is a **policy SAID** — composable across identities via the policy DSL (`identity(X)`, `threshold`, etc.). At read time the policy is fetched and evaluated via `evaluate_signed_policy` against the verified prefix set from a `SignedRequest`. `None` for publicly readable content.

The asymmetry between the two fields is intentional: writes are single-identity-bound (one writer at one moment); reads are composable (any DSL expression).

Custody is **decoupled from availability** (replication + lifecycle; a sibling top-level field on the SAD wrapper). A SAD can be widely-replicated but custody-gated; an unreplicated SAD with permissive custody is publicly readable to anyone who has the SAID.

**Consumers:** [SadStore family](../../logic/stores/sad-store.md) (custody check at write + read), [SADStore service](../../../infrastructure/sadstore.md) (HTTP-level enforcement), [../../../features/creds.md](../../../features/creds.md) (credential custody).

**Dependencies:** [identity-rooting.md](identity-rooting.md), [../event-logs/iel/events.md](../event-logs/iel/events.md), [../../logic/verifiers/anchored-policy-checker.md](../../logic/verifiers/anchored-policy-checker.md).

Stub pending #173 design closure. The full custody surface (frozen-mode vs identity-current semantics, custody on chain events, write-time vs read-time enforcement, custody-derived effective SAIDs) lives in active design discussion at issue #173; this doc will consolidate the design-level statement once that closes.
