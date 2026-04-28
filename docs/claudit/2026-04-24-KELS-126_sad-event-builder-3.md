# Branch Audit: KELS-126_sad-event-builder (Round 3) — 2026-04-24

Third-pass audit of the SadEventBuilder branch after `/clear`. Read every changed source file plus the prior two round documents to avoid re-finding resolved issues. Cumulative across rounds before this one: 17 resolved, 0 open. This round adds 4 new findings (1 medium, 3 low), all 4 now resolved.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 1        |
| Low      | 0    | 3        |

---

## Medium Priority

### ~~1. `flush()` validates `checker` after `submit_sad_events` and `sad_store.store` already wrote — pending events get stranded on side-effect-then-error~~ — RESOLVED

**File:** `lib/kels/src/sad_builder.rs:389-411` (and `:435-447` in `absorb_pending`)

~~`flush()` runs three phases in order: server submit, local store write-through, then `absorb_pending`. The `checker` requirement is only enforced inside `absorb_pending`. A builder constructed via `SadEventBuilder::new(Some(client), Some(store), None)` — checker omitted — that stages events and calls `flush()` will successfully submit events to the server (they are now persisted server-side), successfully write each event to the local cache, then error from `absorb_pending` with `KelsError::OfflineMode("flush requires a PolicyChecker")`. The caller now holds a builder with `pending_events` still populated and `sad_verification = None` — exactly the shape they had before flush. Retry from this builder will hit the same error (no setter for `checker`). This is a fail-fast violation: the `checker` is needed for phase 3, the validation should run before phase 1.~~

**Resolution:** Added an explicit `self.checker.is_none()` check at the top of `flush()`, immediately after the `sad_client` validation and before any side effects. Returns `KelsError::OfflineMode("flush requires a PolicyChecker")` with the same string the in-`absorb_pending` check uses, so callers see a single consistent error message regardless of which guard fires. The defensive check inside `absorb_pending` stays as-is — `absorb_pending` is reachable from tests directly, so keeping the real error there is correct rather than promoting it to an `expect`.

---

## Low Priority

### ~~2. `build_chain`'s `kind: &str` parameter is actually used as the chain topic, not a `SadEventKind`~~ — RESOLVED

**File:** `services/sadstore/tests/repair_tests.rs:146-160` (and callers at `:230, 251, 330, 340, 344, 376, 383, 435, 446`)

~~The parameter is forwarded as the first argument to `incept_deterministic`, whose signature is `incept_deterministic(topic: &str, ...)`. Callers pass topic-shaped strings. The name `kind` collides with `SadEventKind`, the distinct type that names whether an event is Icp/Upd/Est/Evl/Rpr.~~

**Resolution:** Renamed the `kind: &str` parameter to `topic: &str` in both `build_chain` (`:146`) and `build_replacement` (`:168`), updated the body assignment in `build_replacement` to read `topic: topic.to_string()`, and renamed every per-test `let kind = "kels/v1/..."` binding to `let topic = ...` along with its call-site references. The remaining `kind` identifiers in the file (`kind:` field on `SadEvent` literals, `event.kind = ...`, the docstring `"first event uses Rpr kind"`) all genuinely refer to `SadEventKind` and are correct — verified by grepping after the rename.

### ~~3. `incept` and `incept_deterministic` don't `validate_structure()` on the staged v0 — only v1 (in the deterministic path) is checked~~ — RESOLVED

**File:** `lib/kels/src/sad_builder.rs:191-208, 220-258`

~~Both inception paths call `SadEvent::create(...)` to construct the v0 Icp event and push it onto `pending_events` without invoking `validate_structure()`. `compute_sad_event_prefix` (in `event.rs`) runs `validate_structure()` on its v0, and the v1+ stagers all run it. Today benign because `SadEvent::create` produces structurally valid Icp for the parameters this code passes, but a future tightening of Icp's structural contract would slip through unstaged here.~~

**Resolution:** Added `event.validate_structure().map_err(KelsError::InvalidKeyEvent)?` after `SadEvent::create(...)` in `incept` (single-shot v0) and after the v0 construction in `incept_deterministic` (before the v0→v1 mutate). Both incept paths now catch any Icp structural rule violation before pushing into `pending_events`, matching the pattern the v1+ stagers (`update`/`evaluate`/`repair`) already follow and the validation that `compute_sad_event_prefix` runs. The atomic-staging contract on `incept_deterministic` is preserved: v0 validation happens before any push, v1 validation continues to happen before either push.

### ~~4. `flush()`'s "Persist before absorbing" comment is misleading — local store is updated before *verification*, not before *server-acceptance*~~ — RESOLVED

**File:** `lib/kels/src/sad_builder.rs:402`

~~The "Persist before absorbing so local store never falls behind verified state" comment misleads: events have already been submitted to and accepted by the server at this point (phase 1 succeeded). The local store write happens before `absorb_pending`, which is the *local* re-verification step. The actual invariant is "local store may temporarily contain server-accepted events that haven't yet been folded into the local `SelVerification`."~~

**Resolution:** Rewrote the inline comment to spell out the ordering rationale: events are already server-accepted by phase 1, so writing to the cache before absorbing is safe; an absorb failure leaves the cache holding events that any subsequent `with_prefix()` will re-verify via the server. The new comment names server-acceptance as the source of truth and explicitly addresses the "what if absorb fails after we wrote" question a reader will ask.

---

## Positive Observations

- **The `requested_prefix` mismatch path is pinned by a focused unit test that doesn't need a server.** `requested_prefix_mismatch_rejected_at_absorb` (`lib/kels/src/sad_builder.rs:780-820`) constructs a builder with `sad_client = None` so hydration is skipped, latches an `expected_prefix` derived from one wp, then incepts deterministically with a different wp, and asserts the verifier's prefix-mismatch error fires at `absorb_pending`. The test has zero IO and exercises the same code path the real flush would hit — exactly the kind of regression guard that pays off when the verifier's prefix check is touched.

- **`absorb_pending_errors_on_divergent_cached_verification` exercises the resume-refusal contract from the builder side.** `lib/kels/src/sad_builder.rs:836-902` hand-builds a divergent chain (deliberately bypassing the builder's single-actor staging), seeds the resulting `SelVerification` directly into a fresh builder's `sad_verification` field, and calls `absorb_pending` to confirm `KelsError::CannotResumeDivergentChain` propagates through the builder layer. This complements the verifier-level `test_resume_refuses_divergent_token` and proves the error doesn't get swallowed at the boundary.

- **The Local-view-vs-authoritative documentation on accessors is sustained, not just a one-off.** Every state-exposing accessor in `sad_builder.rs:103-187` carries a `**Local view.**` or `**Authoritative.**` block, and the section-leading block comment at `:91-101` explains the merge semantic and *why* pending-precedence is correct for internal users. A future reader who lands on `is_established()` without scrolling up still sees the warning. The Round-2 finding M6 fix is the right shape — the accessors are not renamed (which would churn callers without solving the core misunderstanding), the docstrings carry the disambiguation cost.

- **Defense-in-depth on `policy_satisfied` is consistent across all four state-advance vectors on the Evl/Rpr arm and the Est arm.** `verification.rs:301-374` gates `tracked_write_policy`, branch `governance_policy`, `last_governance_version`, and `establishment_version` on the same `write_policy_satisfied` flag. The companion tests (`test_evl_evolution_rejected_does_not_advance_tracked_policy`, `test_evl_rejected_wp_does_not_advance_governance_policy`, `test_est_rejected_wp_does_not_establish_governance_policy`, `test_divergent_est_soft_fail_does_not_poison_other_branch`) pin the gate from four angles, including the chain-wide/per-branch asymmetry on `establishment_version`. This is exactly the right shape — the gate is uniform, the tests cover the corners, and the Round-1 R5/R6 incident has explicit comments tying the code to the audit.

- **`update_errors_at_63_event_bound` exercises the boundary precisely.** `lib/kels/src/sad_builder.rs:704-721` — 63 successive updates, then assert `events_since_evaluation == MAX_NON_EVALUATION_EVENTS && needs_evaluation()`, then assert the 64th update returns `EvaluationRequired`, then evaluate-then-update succeeds. The test pins both halves of the bound (fires at exactly 63, resets after evaluate) in one place. If the constant changes in the future, this test catches a one-off in either direction.

- **`post_sad_object_returns_canonical_said_for_expanded_form` is the right shape for an integration test.** `services/sadstore/tests/sad_builder_tests.rs:338-391` — builds an expanded-form parent with an inline nested child, asserts the returned SAID differs from the client-computed value (so the test is genuinely exercising compaction, not a no-op all-scalar case), asserts the canonical SAID locates the stored object, and asserts the client-computed SAID does NOT locate anything. All three assertions are necessary; missing any one weakens the regression. The Round-2 M3 audit-finding's full life cycle (problem identified, gate added, follow-on consequence found, fixed via response shape, regression test pinned) is visible in this single test.
