# Branch Audit: KELS-126_sad-event-builder (Round 1) — 2026-04-24

Initial audit of the SadEventBuilder branch: +1542/−163 across 21 files. New `SadEventBuilder` in `lib/kels`, `SelVerifier::resume`, `KelsError::EvaluationRequired`, `SadEventVerification → SelVerification` rename, `exchange.rs` rewrite, happy-path test-fixture migration, full-stack integration test harness in `services/sadstore/tests/sad_builder_tests.rs`, and a `compact_children` ordering fix. Audited by the same session that wrote the branch — this is a self-audit.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 4        |
| Low      | 0    | 6        |

Resolved breakdown: M1, M2, M3, L5, L7, L9 fixed in code/docs/tests; M4, L6, L8, L10 deferred with explicit resolution notes (intentional non-action).

---

## Medium Priority

### ~~1. `flush()` partial-success creates a silent local↔server divergence~~ — RESOLVED

**File:** `lib/kels/src/sad_builder.rs:352-374`

~~If (A) succeeds and (B) or (C) fails, the events are **on the server** but `pending_events` is retained and `sad_verification` is stale. The caller sees a post-flush builder that looks identical to a pre-flush builder: pending is non-empty, verification is old. A retry re-sends (idempotent server-side by SAID), re-persists (overwrite OK), re-absorbs. That works, but it's implicit — the `flush` docstring says "On failure, leaves `pending_events` intact so the caller can reason about already-anchored SAIDs," which misleads callers into thinking "failure" means "didn't submit."~~

**Resolution:** `flush()` docstring rewritten to enumerate the three internal phases, name the submit-succeeded-but-absorb-failed case explicitly, and state the contract: every phase is idempotent (server dedupes by SAID, store overwrites under same key, absorb re-verifies from server state) and callers should always retry on error rather than discarding pending. No code change — the behavior was already safe; the docstring just made it clear.

### ~~2. `incept` and `incept_deterministic` accept a `governance_policy` with no rejection test for the overlap case~~ — RESOLVED

**File:** `lib/kels/src/sad_builder.rs:180-242`

~~Both inception variants take `governance_policy: Digest256` (required). The difference is where governance_policy lands — on v0 (`incept`) or on v1 Est (`incept_deterministic`). Nothing in the builder prevents the caller from mixing them up: if a library user calls `incept(topic, wp, gp)` expecting a deterministic prefix, they'll get a v0-with-governance Icp whose prefix includes `gp` and does NOT match `compute_sad_event_prefix(wp, topic)`.~~

**Resolution:** Added regression-guard unit test `incept_prefix_diverges_from_compute_sad_event_prefix` in the `sad_builder` test module. It asserts `incept(topic, wp, gp).pending[0].prefix != compute_sad_event_prefix(wp, topic)` AND `incept_deterministic(topic, wp, gp, None).pending[0].prefix == compute_sad_event_prefix(wp, topic)` — both halves of the contract pinned in one place. The rename suggestion is left for a future API pass; not done here.

### ~~3. `events_since_evaluation` silently ignores an invariant violation~~ — RESOLVED

**File:** `lib/kels/src/sad_builder.rs:148-163`

~~If a corrupted or externally-mutated `pending_events` contains, say, an `Icp` at position 2, the counter silently resets to 0 — exactly the situation the bound check is guarding against. The builder's own API paths can't produce this (each stager pushes the right kind in the right order), but the field is `pub(crate)`-accessible inside the module and the invariant is load-bearing for the 63-event bound.~~

**Resolution:** Took option (a) — extended the `events_since_evaluation` docstring to call out that correctness depends on `pending_events` being append-only and only mutated through the stager methods (which enforce the kind ordering the simulation assumes: Icp only at position 0, Est only immediately after Icp, etc.). No `debug_assert!` — the invariant is module-private and held by the API surface; runtime checks would be guarding against an in-module bug rather than an external misuse.

### 4. Shared-harness env-var writes are process-global and cross-binary safety depends on `cargo test` running test files as separate processes

**File:** `services/sadstore/tests/sad_builder_tests.rs:182-193`

```rust
unsafe {
    std::env::set_var("MINIO_ENDPOINT", &minio_endpoint);
    std::env::set_var("MINIO_REGION", "us-east-1");
    ...
}
```

`cargo test` does spawn each `tests/*.rs` file as a separate binary (safe), but this relies on an implementation detail. If someone merges `sad_builder_tests.rs` into `integration_tests.rs` (same binary), the two harnesses would race to set the same MinIO env vars and the second initializer would corrupt the first's state. `integration_tests.rs` uses `OnceCell` + its own MinIO, so it doesn't currently hit this, but there's no mechanism preventing a future contributor from doing so.

**Suggested fix:** Add a comment at the top of each harness explaining the one-harness-per-binary constraint, and consider a `#[cfg(test)]` panic if a second `SharedHarness::new` is called in the same process. Low urgency — it's a footgun rather than an active bug.

**Resolution:** Deferred. The in-block `SAFETY:` comment already states the no-concurrent-env-reads reasoning. A cross-binary collision requires someone to actively merge two `tests/*.rs` files that both call `SharedHarness::new` — which nobody is doing today. Revisit when a second full-stack harness appears or someone tries to consolidate the two test files.

---

## Low Priority

### ~~5. Typo: "inepted"~~ — RESOLVED

**File:** `lib/kels/src/sad_builder.rs:176`

~~Should be `incepted`.~~

**Resolution:** s/inepted/incepted/.

### 6. `setup_kel_and_policy` returns a bare 4-tuple

**File:** `services/sadstore/tests/sad_builder_tests.rs:267-298`

```rust
) -> (
    Digest256,
    KeyEventBuilder<SoftwareKeyProvider>,
    Policy,
    SadStoreClient,
)
```

Callers must remember the positional order. Three of the four current callers destructure into `(_prefix, _kel_builder, policy, sad_client)` because they don't need the first two. A named-field struct would make intent clearer and reduce the `_`-prefixed placeholders.

**Suggested fix:** Replace the tuple with a `struct TestKelFixture { prefix, kel_builder, policy, sad_client }`.

**Resolution:** Deferred. Four callers, positional destructuring reads fine. Revisit if the test file grows enough to make the tuple obscure.

### ~~7. `build_checker_inputs` docstring is stale~~ — RESOLVED

**File:** `services/sadstore/tests/sad_builder_tests.rs:301-312`

~~The docstring says "closure that builds the checker," but the function returns `(HttpKelSource, InMemoryPolicyResolver)` — no closure.~~

**Resolution:** Rewrote the docstring to describe what the function actually returns (the two borrowed-from handles) and how the caller composes the checker. Function name kept as-is; only the doc comment changed.

### 8. `build_checker_inputs` is used once

**File:** `services/sadstore/tests/sad_builder_tests.rs:304, 428`

Used only in `flush_submits_and_absorbs`. `flush_failure_preserves_pending` (:493-496) and `exchange.rs:126-128, 230-232` all inline the same `HttpKelSource::new` + `InMemoryPolicyResolver::new` pair. Worth either consolidating all callers onto the helper or inlining it.

**Suggested fix:** Low priority — if keeping the helper, use it from `flush_failure_preserves_pending` too for consistency.

**Resolution:** Deferred. Inlining everywhere or unifying both callers on the helper is churn without a correctness benefit. Revisit when the test surface grows or a third caller appears that wants the shape.

### ~~9. `pending_events`, `last_event`, `last_said`, `prefix`, `version` accessors lack docstrings~~ — RESOLVED

**File:** `lib/kels/src/sad_builder.rs:89-117`

~~Accessors are `pub` and will appear in rustdoc for external callers, but have no docs.~~

**Resolution:** Added one-line docstrings on `pending_events`, `sad_verification`, `last_event`, `last_said`, `prefix`, and `version`. Each names the pending-first-then-verified precedence rule where relevant.

### 10. Env-var set in tests uses `unsafe` without a `// SAFETY:` comment explaining the thread-safety reasoning

**File:** `services/sadstore/tests/sad_builder_tests.rs:185-193`

```rust
// Shared env vars for both services (sadstore reads MinIO creds;
// KELS reads test-endpoints + nonce window). SAFETY: called before
// the server threads are spawned, so no concurrent env reads yet.
unsafe {
    std::env::set_var(...);
    ...
}
```

The comment above the `unsafe` block does state the safety reasoning, but the convention in the rest of the codebase (e.g., `services/kels/tests/integration_tests.rs:152-156`) uses the same inline comment style. Consistent — fine as-is, just noting that a stricter convention would use `// SAFETY:` as the immediate line prefix so lints that check for SAFETY comments pick it up.

**Suggested fix:** No change needed; noted for future standardization if the project adopts a stricter lint.

**Resolution:** Skipped per the finding itself. Existing convention matches the rest of the codebase.

---

## Positive Observations

- **The `compact_children` fix is exactly right and carries the "why" forward.** The block comment at `services/sadstore/src/compaction.rs:79-86` explains the swap_remove-based-scramble failure mode that motivated the `get_mut` switch. That's the kind of non-obvious invariant that's painful to re-discover, and the comment will save the next person who touches compaction from re-deriving it.

- **The `SadEventVerification → SelVerification` rename was followed through end-to-end.** Code, design docs, `.terminology-forbidden` (so the lint catches regressions), and docstrings that referenced the old name were all updated in one pass (`verification.rs:290` docstring comment cross-reference). The `feedback_global_replace_care.md` pattern was honored — no stragglers.

- **`SelVerifier::resume` mirror of `KelVerifier::resume` is minimal and honest about its limits.** Docstring at `lib/kels/src/types/sad/verification.rs:478-489` explicitly states that divergent chains aren't resumable and that callers over such chains must re-verify from inception. The fact that `SelVerification` only carries the tie-break winner is the real constraint, and the doc surfaces it rather than pretending otherwise.

- **`events_since_evaluation` simulation exactly mirrors the verifier's state transitions.** `lib/kels/src/sad_builder.rs:148-163` maps 1:1 to the verifier's `Icp→0, Est→1, Upd→+1, Evl/Rpr→0` semantics. The counter won't drift from the server's because it's the same logic — and the unit test `update_errors_at_63_event_bound` verifies the end-to-end guard fires exactly once at the boundary and resets correctly after `evaluate()`.

- **The happy-path/verifier-integrity fixture split is principled and commented.** Each affected test module gets a leading comment (`verification.rs:525-531`, `sync.rs:389-391`, `identity_chain.rs:117-120`) explaining that rejection fixtures stay hand-built because the builder refuses the shapes those tests exercise. A future reader won't have to re-derive the policy.

- **`flush()`'s caller-owns-anchoring contract is visibly reflected in `exchange.rs`.** The CLI rewrite (`exchange.rs:151-158, 255-258`) shows exactly the "stage → interact → ... → flush" shape the builder was designed to compose into. The builder stays protocol-agnostic; the CLI stays in charge of its KEL. No leaky abstraction.

- **Integration harness failure modes fail loudly.** `services/sadstore/tests/sad_builder_tests.rs:244-246` — the readiness loop panics after 100 tries with an explicit `"service not ready at {}"` message rather than silently timing out. The `#[dtor]` container cleanup at `:40-53` guarantees test containers are torn down even on panic paths, preventing docker resource leaks between test runs.
