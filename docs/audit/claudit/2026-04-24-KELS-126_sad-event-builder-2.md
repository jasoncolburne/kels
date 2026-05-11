# Branch Audit: KELS-126_sad-event-builder (Round 2) — 2026-04-24

Second-pass audit of the SadEventBuilder branch after /clear, reading every changed source file top-to-bottom. Focus on findings the first round missed — `with_dependencies` silent behaviors, `SelVerifier::resume` edge cases, `publish_pending`/`flush` asymmetry, the new `post_sad_object` SAID-match gate, and the `services/kels` dev-dep addition.

Cumulative across rounds: 10 resolved (Round 1) + 7 (this round's M1, M2, M3, L4, L5, L6, L7 all fixed). 0 of Round 1's findings re-surfaced; this round added 7 findings, all 7 now resolved. 17 total resolved across both rounds, zero open.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 3        |
| Low      | 0    | 4        |

---

## Medium Priority

### ~~1. `SelVerifier::resume` followed by an immediate `finish()` errors when the winning branch carried `governance_policy = None`~~ — RESOLVED

**File:** `lib/kels/src/types/sad/verification.rs:490-520, 427-436`

~~`resume` rehydrates exactly one branch with `governance_policy: verification.governance_policy().copied()`. If the token came from a divergent chain where the R6 Est-arm gate kept the tie-break winner's `governance_policy = None` (the scenario pinned by `test_divergent_est_soft_fail_does_not_poison_other_branch` at :946-1024), that single branch is reinstated with `governance_policy = None`. An immediate `finish()` on the resumed verifier — with no new `verify_page` calls — fires the chain-wide guard at `:427-436`.~~

**Resolution:** Went with option (a) — the type-system signal. `SelVerification` now carries `diverged_at_version: Option<u64>` (mirrors `KelVerification::diverged_at_serial`), populated by `SelVerifier::flush_generation` at first fork. `SelVerifier::resume` checks the token and returns a new `KelsError::CannotResumeDivergentChain` variant instead of silently rehydrating a single branch. The docstring on `resume` now names the precondition rather than burying it. Tests pinned: `test_diverged_at_version_none_on_linear_chain`, `test_diverged_at_version_set_at_first_fork`, `test_diverged_at_version_set_once` (set-once invariant across continuing generations), `test_resume_refuses_divergent_token`, and `absorb_pending_errors_on_divergent_cached_verification` (integration-level guard in `sad_builder.rs`).

### ~~2. `with_dependencies(sel_prefix=Some(X))` silently forgets `X` when the chain isn't found, allowing a later `incept()` to produce a different prefix~~ — RESOLVED

**File:** `lib/kels/src/sad_builder.rs:62-85, 196-258`

~~When `verify_sad_events` returns `KelsError::NotFound`, `with_dependencies` swallows it and leaves `sad_verification = None`. A subsequent `incept(topic, wp, gp)` or `incept_deterministic(topic, wp, gp, content)` computes a *new* prefix from `(topic, wp)` with no check that it matches `X`. The caller walks away thinking they initialized a chain at `X`; they actually initialized one somewhere else.~~

**Resolution:** Moved the check into the verifier rather than building a bespoke comparison in the builder. `SelVerifier::prefix` became `Option<Digest256>` — `new` and `resume` accept `Option<&Digest256>`. When `None`, the verifier latches to the inception event's prefix at v0; when `Some`, `verify_event` enforces `event.prefix == expected` and surfaces a mismatch as `KelsError::VerificationFailed("SAD event {} prefix {} doesn't match SEL prefix {}")`. `SadEventBuilder` caches `requested_prefix: Option<Digest256>` from the `sel_prefix` argument to `with_dependencies` (both hydration success and `NotFound` paths) and passes it to the verifier at `absorb_pending` time. Regression pinned by `requested_prefix_mismatch_rejected_at_absorb` in `sad_builder.rs` — a caller expecting X who ignites an inception that derives Y gets a structural error at flush instead of silent state drift. Callsite sweep: `SelVerifier::new`/`resume` callers in `verification.rs`, `sync.rs`, `identity_chain.rs`, `handlers.rs`, and `sad_builder.rs` updated to wrap existing `&prefix` args in `Some(...)`.

### ~~3. `post_sad_object` SAID-match gate makes inline-nested-SAD submission unreachable; `compact_sad` is now defensive-only~~ — RESOLVED

**File:** `services/sadstore/src/handlers.rs:434-457`

~~The added check compares the client-provided SAID (captured post-parse but pre-compaction) against the SAID derived on the fully-compacted form.~~

**Resolution:** First, the original audit was wrong about the gate — there is no SAID-mismatch gate on this branch (Round 1 author and I both misread a rename diff as a logic addition). What *is* real is the underlying ambiguity: when a client posts an expanded-form SAD, the server compacts and stores under a different (canonical) SAID than the client computed locally, leaving the client with no way to locate what was stored. Fixed by making the response authoritative rather than reasoning client-side. New `PostSadObjectResponse { said: Digest256 }` type in `lib/kels/src/types/sad/request.rs`. Server returns `Json(PostSadObjectResponse { said: canonical_said })` on both 200 ("exists" early-return) and 201 ("stored") paths. Client `SadStoreClient::post_sad_object` parses the response and returns `body.said` — return type stays `Result<Digest256, KelsError>` but the value is now server-authoritative. Pre-flight `verify_said` self-check stays so tampered payloads fail fast. Pinned by integration test `post_sad_object_returns_canonical_said_for_expanded_form` (parent with inline nested child; asserts returned SAID ≠ client-computed AND `get_sad_object(returned)` succeeds AND the client-computed SAID does NOT exist server-side). All-scalar SADs (publish_pending events, exchange.rs payloads) are behavior-preserving — the canonical SAID equals the client-computed value when nothing compacts.

---

## Low Priority

### ~~4. `with_dependencies` accepts a `checker` even when hydration is skipped; the checker is then silently discarded~~ — RESOLVED

**File:** `lib/kels/src/sad_builder.rs:62-85`

~~If either `sad_client` or `sel_prefix` is `None`, the match arm at `:77` returns early and the `checker` parameter is never used. The builder doesn't store it.~~

**Resolution:** Made obsolete by storing the checker as `Arc<dyn PolicyChecker + Send + Sync>` on the builder. Constructors (`new` and `with_prefix`) take it once at construction; `flush` and `absorb_pending` no longer accept the parameter and use `self.checker` instead. `with_dependencies` was renamed to `with_prefix` since the only thing it adds beyond `new` is the hydration prefix — the rest of the deps are symmetric across both constructors. The "silently discarded" failure mode no longer exists: the checker is held in builder state for the lifetime of the builder, and `flush` errors with `KelsError::OfflineMode("flush requires a PolicyChecker")` if pending events exist but `checker` was not supplied. Ripple effects: `SelVerifier` dropped its `'a` lifetime parameter (`SelVerifier<'a>` → `SelVerifier`), `verify_sad_events` (sync.rs) and `SadStoreClient::verify_sad_events` now take `Arc<dyn PolicyChecker + Send + Sync>`, and `AnchoredPolicyChecker` was refactored to own its `kel_source` and `resolver` via `Arc` (was borrowed `'a` references) so it satisfies the `'static` bound. `PolicyResolver` trait now declares `Send + Sync` (was `Sync` only). All callsites swept: verification.rs tests, identity_chain.rs tests, sad_builder.rs tests, sad_builder_tests.rs (integration), exchange.rs CLI commands, sadstore handlers.rs.

### ~~5. `publish_pending` does not write to the local `sad_store`; only `flush` does~~ — RESOLVED

**File:** `lib/kels/src/sad_builder.rs:349-359, 401-407`

~~`flush` writes each pending event to `sad_store` via `store.store(&event.said, &value)` before absorbing. `publish_pending` posts to the server's SAD object store but never mirrors into the local `sad_store`.~~

**Resolution:** Documented as intentional in `publish_pending`'s docstring — the local `sad_store` is a cache for *verified* SEL entries, populated by `flush` after `submit_sad_events` succeeds and `absorb_pending` accepts. `publish_pending` posts to the remote SAD object store for multi-party review pre-verification; those bytes shouldn't enter the local verified cache because they haven't been verified yet. Pre-flush events live in `pending_events` only.

### ~~6. `governance_policy()` accessor on `SadEventBuilder` returns a proposed value from pending events with no authorization context~~ — RESOLVED

**File:** `lib/kels/src/sad_builder.rs:131-141`

~~The accessor walks `pending_events` in reverse and returns the first `Some(gp)`.~~

**Resolution:** Documented the local-view-vs-server-accepted distinction across every state-exposing accessor on `SadEventBuilder` — `pending_events` (local-only), `sad_verification` (authoritative), and the mixed accessors (`last_event`, `last_said`, `prefix`, `version`, `governance_policy`, `is_established`, `events_since_evaluation`, `needs_evaluation`) each carry a `**Local view.**` note pointing consumers needing trustworthy state at `sad_verification()`. A block comment at the top of the accessor section explains the merge semantic and why it's the right default for the builder's internal users (e.g., `is_established` letting a just-staged `Est` count for the next staging call). The accessors aren't renamed — internal users want the pending-precedence semantic; the docstring is the right disambiguation cost.

### ~~7. `sadstore` now has a dev-dep on the full `services/kels` crate, pulling the entire KELS service build graph into sadstore's test builds~~ — RESOLVED

**File:** `services/sadstore/Cargo.toml:70-73`, `services/sadstore/Dockerfile:17-23`, `services/sadstore/garden.yml:15`

~~`cargo test` on sadstore now compiles the kels service (plus its transitive deps: axum, sqlx, redis, registry clients, etc.).~~

**Resolution:** Documented in `services/sadstore/Cargo.toml` immediately above the `kels = { path = "../../services/kels" }` line — explains why the dependency exists (full-stack integration tests need a live KELS service for `AnchoredPolicyChecker` to walk a real KEL), notes that this inverts the usual "services don't depend on services" rule but only at dev-deps, and points at the principled fix (extract a `kels-test-harness` crate) without acting on it. The extraction stays deferred until the test-build cost actually materializes — speculative refactoring otherwise.

---

## Positive Observations

- **Round 1's self-audit discipline paid off.** Round 1 audited the same code and produced 10 findings with resolutions; Round 2 reads the same surface with fresh context and finds 7 *different* issues, none overlapping. That's the argument for post-`/clear` re-audits as a regular step — the cached context of "I just wrote this" biases the first pass toward the known failure modes of the implementer.

- **The SAID-match gate in `post_sad_object` is defensible hardening even though it has follow-on consequences.** Fail-loud on ambiguous-shape submissions is the right default; the prior behavior of "silently store under a different SAID than the client computed" was a latent footgun. The medium finding above is about surfacing the consequence, not about reversing the decision.

- **`SelVerifier::resume` wire-up matches the `KelVerifier::resume` pattern faithfully.** Single-branch rehydration, chain-wide `establishment_version` and `policy_satisfied` carried forward, `saw_any_events = true` to skip the empty-chain check on finish. The edge case in finding 1 is inherent to the token format (single tie-break winner, per design), not a slip in the port.

- **`incept_deterministic`'s atomic either-both-or-neither staging (`sad_builder.rs:224-257`) is the right shape.** `v1.validate_structure()` runs before either push, so a structural failure on v1 leaves `pending_events` empty rather than half-populated. A subsequent `incept_deterministic` call after a failure is still valid (no fresh-builder check failure from a stray v0).

- **The `build_chain` rewrite in `repair_tests.rs:146-165` is a strict upgrade.** Old fixture constructed v0 + 62 bare Upd events (no governance_policy declared) — a shape the current verifier rejects. New fixture goes through `SadEventBuilder::incept_deterministic` + `update`, producing chains that look like what real callers produce. Repository-layer tests now exercise realistic chain layouts; if the verifier's shape rules tighten further, these tests exercise the correct shape.

- **`flush`'s sequencing (`sad_builder.rs:389-411`) preserves the "local store never ahead of verified" invariant correctly.** Order is: submit → local-store → absorb. A failure in any phase leaves pending intact and the docstring (post-Round-1) is explicit about the retry contract being idempotent end-to-end.

- **The `services/kels` dev-dep inversion was made with eyes open.** The `Cargo.toml` comment (`:70-72`) calls out the library-target quirk (crate named `kels`, library `kels_service`), and the Dockerfile comment (`:17-20`) names why the copy is required. Both save a future reader from archaeology.
