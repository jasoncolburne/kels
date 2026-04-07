# Branch Audit: KELS-84_typed-cesr-fields (Round 3) — 2026-04-07

Branch replaces `String` fields with typed CESR types (`cesr::Digest`, `cesr::PublicKey`, `cesr::Signature`, `cesr::EncapsulationKey`, `cesr::KemCiphertext`, `cesr::Nonce`) throughout the codebase. 116 files changed, ~3325 insertions, ~2473 deletions. Focus: new findings not covered in rounds 1-2, correctness of conversion patterns, residual issues.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 0        |
| Low      | 0    | 3        |

All 11 findings from rounds 1-2 are resolved. All 3 findings from round 3 are resolved.

---

## Low Priority

### ~~1. Inline `use cesr::Matter` in production code violates import style~~ — RESOLVED

**Files:** `services/registry/src/handlers.rs`, `services/registry/src/federation/sync.rs`, `services/kels/src/handlers.rs`, `services/identity/src/handlers.rs`, `services/gossip/src/sync.rs`, `services/gossip/src/lib.rs`, `clients/bench/src/main.rs`, `clients/cli/src/commands/dev.rs`, `clients/cli/src/commands/exchange.rs`, `clients/cli/src/commands/kel.rs`, `clients/cli/src/helpers.rs`, `lib/kels/src/merge.rs`, `lib/kels/src/repository.rs`, `lib/kels/src/client/kels.rs`, `lib/kels/src/client/registry.rs`, `lib/kels/src/store/sad.rs`, `lib/ffi/src/lib.rs`

~~~30 instances of `use cesr::Matter` inside function bodies in non-test, non-feature-gated code. CLAUDE.md states: "Never import inline within function bodies, unless inside a feature-gated block."~~

**Resolution:** All inline `use cesr::Matter` in production code moved to file-level imports. Remaining inline uses are in `#[cfg(test)]` blocks (acceptable) and `lib/derive/src/lib.rs` `quote!{}` blocks (required for proc macro code generation).

### ~~2. Unused `_prefix` parameter in merge.rs methods~~ — RESOLVED

**File:** `lib/kels/src/merge.rs` — `handle_full_path`, `handle_divergent_submission`, `handle_overlap_submission`

~~All three methods accepted `_prefix: &str` but never used it — they call `self.prefix_digest()` internally instead.~~

**Resolution:** Removed the `_prefix` parameter from all three methods and updated all call sites.

### ~~3. `SignedKeyEvent::Hash` allocates via `qb64()` for signature sorting~~ — RESOLVED

**File:** `lib/kels/src/types/kel/event.rs:611-622`

~~The `Hash` implementation sorted signatures by `s.qb64()`, allocating a new `String` per signature per hash call.~~

**Resolution:** Replaced `sort_unstable_by_key(|s| s.qb64())` with `sort_unstable()` since `cesr::Signature` derives `Ord`.

---

## Positive Observations

- **Complete type conversion.** All CESR-representable fields across the entire codebase are now typed — structs, trait interfaces, function signatures, return types, and test data. The scope of this refactor is impressive with zero correctness regressions (all prior findings resolved).

- **Type-enforced signature validation.** The removal of manual `Signature::from_qb64` validation in `merge.rs` (line ~550) is correct — typed `cesr::Signature` fields guarantee valid CESR format at deserialization time, making the runtime check redundant. This is a good example of leveraging the type system to eliminate defensive code.

- **Benchmark client rewrite.** Replacing the `KelsClient`-based benchmark with raw `hyper` HTTP eliminates client-side verification overhead, producing more accurate throughput measurements. The pre-computed `bytes_per_request` approach is cleaner than accumulating per-request byte counts.

- **Cache hot-path optimization.** The new `get_full_serialized_str(&str)` method on `ServerKelCache` avoids parsing raw prefix strings into `cesr::Digest` on every cached request — the fast path stays string-based while the typed path is used everywhere else. Good performance/correctness trade-off.

- **`Box<MailMessage>` in `MailAnnouncement::Message`.** Boxing the large `MailMessage` (now ~7 `cesr::Digest` fields) inside the enum variant reduces the overall enum size since `Removal` only holds one `cesr::Digest`. Serde handles `Box<T>` transparently, so wire format is unchanged.

- **`compute_rotation_hash` now takes `&VerificationKey` directly.** Previously callers had to call `.qb64()` before passing to this function; now the function accepts the typed key and calls `.qb64()` internally. This eliminates a class of bugs where callers might hash the wrong representation.
