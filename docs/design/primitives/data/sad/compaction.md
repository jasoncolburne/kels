# SAD Compaction / Expansion

**Canonical name:** SAD compaction — the structural transform between a fully-resolved SAD and a "compacted" representation that replaces sub-SADs with their SAIDs.

A SAD with nested SADs can be transmitted in compacted form (sub-SADs replaced by their SAIDs) and expanded by re-fetching the referenced SADs from a [SadStore](../../logic/stores/sad-store.md). The SAID-of-the-SAID rule means compaction is reversible: the compacted SAID equals the expanded SAID.

**Consumers:** credentials (compacted disclosure), policy SADs (compacted policy serialization), exchange envelopes.

**Dependencies:** [sad.md](sad.md), [said.md](said.md), [../../logic/stores/sad-store.md](../../logic/stores/sad-store.md).

Stub pending #101 design closure. The full compaction algorithm (which fields can be compacted, sort order, partial-compaction shapes, schema-aware compaction) lives in active design discussion at issue #101; this doc will consolidate the design-level statement once that closes.
