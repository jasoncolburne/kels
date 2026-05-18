# SAID — Self-Addressing Identifier

**Canonical name:** SAID (44-char Base64 CESR-encoded Blake3-256 hash).

Content-addressable identifier for any SAD. Computed by blanking the `said` field (and `prefix` for prefix-derived SADs) in the canonical serialization, hashing with Blake3-256, then CESR-encoding the digest.

The "blank-then-hash" rule lets the SAID be embedded inside its own SAD without circularity: every consumer recomputes the SAID by re-blanking and re-hashing the same bytes.

**Consumers:** every reference to a SAD across the corpus — `previous` pointers, `ielEvent` bindings, `identity` references, policy SAIDs, anchor SAIDs.

**Dependencies:** [sad.md](sad.md) for the SAD shape this SAID computes against. CESR encoding via `cesr` crate.

Stub. SAID-vs-prefix derivation distinctions (KEL prefix uses a different blanking pattern; see [../event-logs/kel/events.md](../event-logs/kel/events.md)) and the canonical-serialization rules (JCS) live in implementing crates; this doc consolidates the design-level statement as it firms up.
