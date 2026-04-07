# Branch Audit: KELS-84_typed-cesr-fields (Round 7) — 2026-04-07

Scope: 149 files changed (~7300 lines), 16k-line Rust diff. Full typed-CESR conversion across all services, libraries, clients, and tests. Focus: new issues across core library, gossip sync, credentials, and SAD verification.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 1        |
| Low      | 0    | 1        |

All 22 findings from rounds 1–6 are resolved. 2 new findings identified and resolved. Finding 3 (composite cache keys) was dropped after review — the heterogeneous key format is correct for matching Redis pub/sub payloads.

---

## Medium Priority

### ~~1. Verbose UFCS syntax in credential edge schema comparison~~ — RESOLVED

**File:** `lib/creds/src/verification.rs:238`

~~The edge schema SAID comparison uses fully-qualified `AsRef::<str>::as_ref(&edge_schema.said)` when `edge_schema.said.as_ref()` would work identically (since `cesr::Digest` only implements `AsRef<str>`).~~

**Resolution:** Replaced with `edge_schema.said.as_ref()`.

---

## Low Priority

### ~~2. `StaleEntry::source` and stale entry functions use `String` instead of `cesr::Digest`~~ — RESOLVED

**File:** `services/gossip/src/sync.rs:968-1030`

~~`StaleEntry::source` was `String`, and `record_stale_entry`, `requeue_stale_entry`, and `encode_stale_value` all accepted `&str` parameters for digest values. The `drain_due_stale_entries` return type was `HashMap<String, StaleEntry>`, requiring callers to parse prefix strings via `from_qb64` inside task closures.~~

**Resolution:** Changed `StaleEntry::source` to `cesr::Digest`. Updated `encode_stale_value`, `record_stale_entry`, and `requeue_stale_entry` to accept `&cesr::Digest`. `drain_due_stale_entries` now returns `HashMap<cesr::Digest, StaleEntry>` with CESR parsing at the Redis boundary. Removed redundant `from_qb64` calls from both KEL and SAD anti-entropy task closures. `record_stale_prefix` and `record_sad_stale_prefix` no longer need `.as_ref()` when calling `record_stale_entry`.

---

## Positive Observations

- **Complete CESR field conversion.** Zero remaining `pub said: String`, `pub prefix: String`, `pub signature: String`, or similar fields across the entire codebase. Every cryptographic identifier is now a typed CESR value (`cesr::Digest`, `cesr::VerificationKey`, `cesr::Signature`).

- **Correct boundary discipline.** CESR parsing (`from_qb64`) happens exclusively at system boundaries (HTTP handlers, CLI args, FFI, Redis decode) with proper error propagation. Internal code operates on typed values throughout — the "parse once at the edge" pattern is consistently applied.

- **Wire format preserved.** Since `cesr::Digest` serializes as QB64 via serde, the JSON wire format is completely unchanged. No migration or compatibility concerns.

- **Signing consistency.** All signing and verification sites uniformly use `.qb64().as_bytes()` — no mixed representations.

- **Gossip sync error handling improved.** Former silent `.ok()` swallowing of `from_qb64` errors in gossip sync has been replaced with explicit `match` expressions that log warnings on parse failures, while KEL-related instances that can't fail with typed inputs were eliminated entirely.

- **Import ordering clean.** All touched files follow the three-group convention (std/tokio/tracing → external crates → local/workspace) with proper blank-line separation.
