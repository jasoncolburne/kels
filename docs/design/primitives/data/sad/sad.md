# SAD — Self-Addressed Data

**Canonical shape:** the SAD object — content + canonical serialization + `said` field. The SAID-bearing primitive that underpins SEL events, credentials, policies, exchange envelopes, and every other content-addressed surface in KELS.

A SAD is a serializable record whose own SAID (`said` field) is computed by blanking `said` (and `prefix` where derived together), serializing canonically, and hashing — see [said.md](said.md) for the algorithm.

**Consumers:** every content-bearing primitive — SEL `content`, credentials, policy SADs, exchange envelopes, custody-tagged objects.

**Dependencies:** [said.md](said.md) (SAID computation), the [SadStore family](../../logic/stores/sad-store.md) for persistence, [SadObjectBuilder](../../logic/builders/sad-object-builder.md) for wrapping content as a SAD object.

Stub. The full SAD shape (canonical serialization rules, JCS, field-blanking semantics) is documented in the verifiable-storage crate at `../verifiable-storage-rs`; this doc will consolidate the design-level account as it firms up.
