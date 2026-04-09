# Branch Audit: KELS-84_typed-cesr-fields (Round 4) — 2026-04-07

Branch replaces `String` fields with typed CESR types (`cesr::Digest`, `cesr::PublicKey`, `cesr::Signature`, `cesr::EncapsulationKey`, `cesr::KemCiphertext`, `cesr::Nonce`) throughout the codebase. 117 files changed, ~3320 insertions, ~2477 deletions. Focus: new findings not covered in rounds 1-3, residual inconsistencies across the conversion.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 0        |
| Low      | 0    | 2        |

All 14 findings from rounds 1-3 are resolved. All 2 findings from round 4 are resolved.

---

## Low Priority

### ~~1. Inline `use http_body_util::BodyExt` in bench client~~ — RESOLVED

**File:** `clients/bench/src/main.rs:273`

~~`use http_body_util::BodyExt;` is inside the `run_worker()` function body, which is not in a `#[cfg(test)]` or `#[cfg(feature = "...")]` block. CLAUDE.md states: "Never import inline within function bodies, unless inside a feature-gated block." This import was introduced in this branch as part of the bench rewrite.~~

**Resolution:** Moved `use http_body_util::BodyExt;` to file-level imports in the external crates group.

### ~~2. `to_string()` instead of `qb64()` for signature verification in sadstore~~ — RESOLVED

**File:** `services/sadstore/src/handlers.rs:591`

~~The signature verification uses `r.pointer.said.to_string().as_bytes()`, while every other signing/verification site in the codebase uses `.qb64().as_bytes()` (e.g., `verification.rs:108`, `verification.rs:813`, `builder.rs:672`, `essr.rs:118`, `repair_tests.rs:122`). Functionally identical since `Display` for `Digest` writes the qb64 field, but inconsistent with the established pattern. If the `Display` impl ever diverged from `qb64()`, this would silently break signature verification.~~

**Resolution:** Changed to `r.pointer.said.qb64().as_bytes()` to match the rest of the codebase.

---

## Positive Observations

- **Complete type conversion across 117 files with zero correctness regressions.** All 14 findings from rounds 1-3 (inline imports, unused parameters, allocation in Hash, and all String→Digest/PublicKey/Signature conversions in traits, caches, federation config, edges, schemas, merge vectors) are resolved. The branch is remarkably clean for this scope.

- **Consistent signing pattern.** With the one exception noted above, all signing/verification sites uniformly use `said.qb64().as_bytes()` — builder (inception, rotation, interaction, decommission, contest, recovery), ESSR envelope, SAD chain verifier, KEL verifier, and all test helpers. This makes the signing contract clear and auditable.

- **Cache hot-path design.** The `get_full_serialized_str(&str)` / `store(&cesr::Digest, ...)` split in the KEL cache is intentional and correct — both paths key on the same qb64 string (via `as_ref()` or direct string). The hot path avoids a `from_qb64` parse per request while maintaining correctness. Good performance/safety trade-off.

- **Boundary parsing discipline.** CESR parsing (`from_qb64`) happens consistently at HTTP handler and CLI argument boundaries with proper `.context()` / `ApiError::bad_request()` wrapping. Internal code works entirely with typed values. This validates-once-at-the-edge pattern eliminates redundant parsing and makes invalid states unrepresentable.

- **Benchmark rewrite quality.** The switch from `KelsClient`-based benchmarking to raw `hyper` HTTP eliminates client-side verification overhead. The `run_worker` function drains response bodies frame-by-frame without large allocations, which is the correct approach for throughput measurement.

- **Clean allowlist simplification.** The gossip allowlist went from algorithm-based filtering (which had a chicken-and-egg race condition) to a simple `HashMap<cesr::Digest, AllowlistEntry>` with hardcoded ML-KEM-1024 for transport. Simpler code, better security.
