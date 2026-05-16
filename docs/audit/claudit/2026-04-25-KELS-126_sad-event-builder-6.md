# Branch Audit: KELS-126_sad-event-builder (Round 6) — 2026-04-25

Sixth-pass audit of the SadEventBuilder branch after `/clear`. Read every changed source file plus the prior five round documents to avoid re-finding resolved issues. Cumulative across rounds: 34 resolved (10 R1 + 7 R2 + 4 R3 + 4 R4 + 4 R5 + 5 R6), 0 open. This round added 4 audit findings (1 medium, 3 low) plus 1 medium discovered during implementation, all 5 now resolved.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 2        |
| Low      | 0    | 3        |

---

## Medium Priority

### ~~1. `flush()` cannot complete a repair from a builder whose `sad_verification` is divergent — `absorb_pending` errors after the server has already accepted the repair~~ — RESOLVED

**File:** `lib/kels/src/sad_builder.rs:474-528` (flush), `:569-593` (absorb_pending), `:395-405` (repair stager docstring), `lib/kels/src/types/sad/verification.rs:526-565` (`SelVerifier::resume`)

The Round-4 model gates normal stagers on divergence (`update` / `evaluate` refuse with `KelsError::SelDivergent`) but allows `repair` as the explicit owner-initiated recovery path. The `repair_allowed_on_divergent_chain` test (`sad_builder.rs:1067-1081`) pins this. But the *flush* of that staged repair has no working path: `absorb_pending` resumes from the cached divergent token, and `SelVerifier::resume` refuses divergent tokens (`verification.rs:530-532`, with `test_resume_refuses_divergent_token` and `absorb_pending_errors_on_divergent_cached_verification` both pinning the refusal).

Concrete sequence:

1. Owner has a builder with `sad_verification = Some(divergent_token_at_v6)` (e.g., from a previous flush whose `set_diverged_at_version` stamped after a concurrent fork was reported).
2. Owner stages `Rpr` at v7 via `b.repair(content)` — passes (the stager bypasses `require_non_divergent` intentionally).
3. Owner calls `flush()`. Phase 1: `submit_sad_events` → server takes the `is_repair` path (`handlers.rs:1339-1445`), truncates v7+, inserts the Rpr, runs `verify_existing_chain` → success. Server response: `applied: true, diverged_at: None` (the repair path doesn't go through `save_batch`'s `DivergenceCreated` outcome, and the chain is now linear).
4. Phase 2: `sad_store.store(...)` writes the Rpr to local cache. Success.
5. Phase 3: `absorb_pending` — `self.sad_verification.is_some()` (the cached divergent token), so `SelVerifier::resume(v, ...)?` returns `Err(KelsError::CannotResumeDivergentChain)`. `flush` returns this error.

State after: `pending_events` still has `[Rpr]` (cleared inside `absorb_pending` only on success), `sad_verification` is still the cached divergent token, server-side chain is linear and repaired.

Retry semantics: `flush` again → submit dedups (`applied: false`, `diverged_at: None` because `first_divergent_version` returns `None` post-repair) → store loop is idempotent → `absorb_pending` → same `SelVerifier::resume` failure. The builder is structurally stuck. Each retry burns a server round-trip and an IP rate-limit token without making progress.

The Round 4 M1 retry-recovery model only worked because the failure mode there was transient (a checker fetch error). `CannotResumeDivergentChain` is a structural property of the cached token, not a transient — the recovery story doesn't apply.

The `repair` docstring (`sad_builder.rs:391-405`) acknowledges divergent chains are different — "For actually-divergent chains, repair requires branch-tip information the verification token does not carry — callers in that case must construct the repair event out of band." But "out of band" is ambiguous: the builder's `repair` happily stages the event, the failure surfaces only at flush time, and the error doesn't tell the caller what to do. The flush docstring (`:474+`) advises "Always retry on error rather than discarding pending" — which is wrong for this specific case.

The asymmetry across the divergent-state staging surface tells the same story:
- `update` / `evaluate`: **explicit refusal** at staging with `SelDivergent { at }` — caller knows immediately.
- `repair`: stages successfully, flush fails with `CannotResumeDivergentChain` (a verifier-internal error code that doesn't name the divergent-builder problem) — caller has to read source to understand.

Three workable fixes, in increasing order of investment:

- **(a)** `repair` refuses divergent tokens too; document that divergent-chain repairs are out-of-builder. Callers handle them via `SadStoreClient::submit_sad_events` directly, then reconstruct the builder via `with_prefix` to re-hydrate from the repaired chain. The builder's contract becomes "linear chains only"; divergent recovery is a deliberate manual flow. Tests `repair_allowed_on_divergent_chain` and the staging-side surface change shape — `repair` would now error like the others.

- **(b)** Special-case `absorb_pending` for divergent + Rpr: when `sad_verification.diverged_at_version().is_some()` and pending contains a repair, drop the cached `sad_verification`, fall through to a fresh `SelVerifier::new(self.requested_prefix.as_ref(), checker)`, and re-verify the Rpr against `requested_prefix` only (no carried branch state). The Rpr-as-only-event would need to be valid against the empty-branches case — it isn't today (`flush_generation` requires `branches.is_empty() ⇒ inception`). So this option needs deeper changes to the verifier.

- **(c)** `flush` re-hydrates from the server after a successful submit when the response indicates the repair landed (server returns `applied: true` and the staged batch contained an Rpr). The local re-hydration is a fresh `verify_sad_events` round-trip. Cost: one extra GET on the repair path. Benefit: builder converges to the post-repair server state cleanly; absorb_pending isn't called at all in this branch. The set_diverged_at_version stamp becomes moot for the repair case.

Option **(a)** is the cleanest contract — it matches the docstring's "out of band" guidance — but it's a small staging-API change. Option **(c)** preserves the in-builder repair flow at the cost of a server round-trip. Either closes the bug; option (b) is a trap.

A regression test for any of these would be a full-stack flush-from-divergent test in `sad_builder_tests.rs` that mirrors `submit_dedup_returns_current_divergence_signal`'s setup (HTTP-level fork) but follows up with the owner staging a repair and flushing through the builder. Today no test exercises this path — `repair_allowed_on_divergent_chain` stops at staging.

**Suggested fix:** Take option (a). The change is small (`repair` adds `self.require_non_divergent()?;` like its siblings, the docstring stops claiming partial divergent support, and the "callers in that case must construct the repair event out of band" sentence is reified into a refusal at the staging boundary). Add an `add_repair_refused_on_divergent_chain` test that pins the new contract. The end-to-end recovery flow becomes: detect `KelsError::SelDivergent` from a stager, drop the builder, call `SadStoreClient::submit_sad_events` with a hand-built Rpr, then `SadEventBuilder::with_prefix(...)` to re-hydrate.

**Resolution (round-6 implementation):** Took the bigger fix — KEL-parity rework instead of the audit's option (a) refusal. `SelVerification` now carries `branches: Vec<SadBranchTip>` (`lib/kels/src/types/sad/event.rs:366-426`), the new `pub struct SadBranchTip` (`event.rs:340-365`) is the unified per-branch type used in both the verifier's runtime HashMap and the verification token, and `SelVerifier::resume` accepts divergent tokens by rebuilding the HashMap from `verification.branches()` (`lib/kels/src/types/sad/verification.rs:471-512`). Existing accessors (`current_event`, `write_policy`, `governance_policy`, `events_since_evaluation`, `last_governance_version`) keep their signatures and now compute the tie-break winner on demand via a private `winning_branch()` helper (`event.rs:443-457`); `branches()` is the new public accessor for callers needing the full per-branch picture. `KelsError::CannotResumeDivergentChain` is removed (`error.rs`); the FFI mapping had no entry. `SadEventBuilder::repair` extends the owner's branch tip via the new `owner_branch_tip()` helper (`lib/kels/src/sad_builder.rs:580-599`), mirroring `KeyEventBuilder::get_owner_tail` — for non-divergent chains it's identical to `current_tip`, for divergent it picks `branches().first()` deterministically. Tests dropped: `test_resume_refuses_divergent_token` and `absorb_pending_errors_on_divergent_cached_verification` (reversed contract). Tests added: `resume_rehydrates_divergent_token` and `resume_then_extend_preserves_other_branch` in `verification.rs`, `absorb_pending_succeeds_on_divergent_cached_verification` in `sad_builder.rs`, plus the load-bearing full-stack test `flush_repair_on_divergent_chain_succeeds` in `services/sadstore/tests/sad_builder_tests.rs`. The full-stack test pins flush-no-deadlock, `applied: true`, pending cleared, and idempotent retry — divergence resolution proper requires a Rpr at the divergence version (out-of-builder, see `repair_tests.rs::build_replacement`), which is documented in the test's preamble. `make` clean. **Contract decided:** in-builder repair flow now works on divergent chains; the high-level `repair` stager extends the owner's branch tip rather than truncating the divergence, and divergence-resolving repairs (truncating archives) remain an out-of-builder construction.

---

## Low Priority

### ~~2. `is_repair` declared at outer scope but only read inside the inner block~~ — RESOLVED

**File:** `services/sadstore/src/handlers.rs:1229-1232, 1339, 1341`

```rust
let new_event_count;
let should_publish;
let mut diverged_at_version: Option<u64> = None;
let is_repair;

{
    // ...
    is_repair = new_events.iter().any(|r| r.kind.is_repair());

    if is_repair { ... } else { ... }
    // tx.commit
}

// rest of function uses new_event_count, should_publish, diverged_at_version
// is_repair NOT read after this point
```

Searching the file confirms `is_repair` is read only at line 1341 (inside the block). The outer-scope declaration at `:1232` exists for parity with `new_event_count`, `should_publish`, and `diverged_at_version`, but those three *are* consumed after the block ends (rate-limit accrual, gossip publish, response construction). `is_repair` is purely local to the block.

The asymmetric pattern misleads a reader scanning the function — they see four `let` declarations together and assume all four escape the block. The compiler accepts this (uninitialized-then-assigned-once is fine for `let x;` with no `mut`), but the scope mismatch is a subtle reviewer-hostility.

**Suggested fix:** Move `is_repair` inside the block as a normal `let is_repair = new_events.iter().any(|r| r.kind.is_repair());` immediately before the `if is_repair { ... }` branch. Drop the outer declaration. Three locals stay outside (genuinely needed); one moves in. The remaining outer trio reads as "values that escape the transaction block," which is what the reader expected. No behavior change.

**Resolution (round-6 implementation):** Took the suggested fix verbatim. Outer `let is_repair;` removed at `services/sadstore/src/handlers.rs:1232`; in-block assignment rewritten as `let is_repair = new_events.iter().any(|r| r.kind.is_repair());` at the line preceding `if is_repair { ... }`. The remaining outer trio (`new_event_count`, `should_publish`, `diverged_at_version`) genuinely escape the block; no behavior change.

### ~~3. `compute_sad_event_prefix` allocates a full `SadEvent`, computes Blake3-256 twice (SAID + prefix), and discards everything except `prefix`~~ — RESOLVED

**File:** `lib/kels/src/types/sad/event.rs:164-172`

```rust
pub fn compute_sad_event_prefix(
    write_policy: cesr::Digest256,
    topic: impl Into<String>,
) -> Result<cesr::Digest256, KelsError> {
    Ok(SadEvent::icp(topic, write_policy, None)?.prefix)
}
```

`SadEvent::icp` constructs a full `SadEvent`, sets `said` and `prefix` placeholders, calls `derive_prefix` (Blake3 over the placeholder-said-and-prefix form), calls `derive_said` (Blake3 over the placeholder-said form, with prefix already set), then runs `validate_structure`. The returned event is dropped on the next line; only `event.prefix` survives.

For the prefix-discoverable flow (exchange-key lookup, identity-chain lookup), this function is the bottleneck — every `cmd_exchange_lookup_key` call hits it once, every `compute_identity_prefix` hits it once. The cost is two Blake3-256 hashes plus one `String` clone (from `topic.into()`) plus one `validate_structure` traversal. The SAID hash is wasted — only the prefix is needed.

The Round 4 L4 design intentionally routed prefix derivation through `SadEvent::icp` so that "a future tightening of Icp's structural rules surfaces uniformly across both paths" (`event.rs:184-187`). That's a real benefit. The cost is real too — but probably acceptable at current call rates.

This is borderline a non-issue: prefix derivation isn't on a hot loop. But the comment in `compute_sad_event_prefix` could acknowledge the trade — a reader optimizing identity-chain bootstrap might be surprised the function does two hashes.

**Suggested fix:** Either (a) accept the cost and add a one-line comment noting the SAID computation is along for the ride and that `validate_structure` tightening would surface here uniformly with staging; or (b) factor a private helper that derives just the prefix (skipping `derive_said` and `validate_structure`) and have `SadEvent::icp` call it in addition to its own validation. Option (a) is cheaper and matches the existing design philosophy; (b) only pays off if a profiler shows this on a hot path. Defer until call rates change.

**Resolution (round-6 implementation):** Took option (a). Added a four-line comment to `compute_sad_event_prefix`'s docstring (`lib/kels/src/types/sad/event.rs:164-176`) naming the trade — one extra Blake3 hash (the SAID derivation) plus `validate_structure` is the cost of routing through `SadEvent::icp` and getting uniform structural-rule tightening across staging and prefix derivation. Names the principled fix (factor a prefix-only helper) for if profiling later flags this on a hot path. No code change.

### ~~4. `identity_chain::advance` reconstructs an `Evl` event manually instead of using `SadEvent::evl`, missing the constructor's `validate_structure` gate~~ — RESOLVED

**File:** `lib/policy/src/identity_chain.rs:83-93`

```rust
let mut event = verification.current_event().clone();
event.content = None;
event.custody = None;
event.kind = SadEventKind::Evl;
event.governance_policy = None;
event.write_policy = Some(new_policy.said);
event
    .increment()
    .map_err(|e| PolicyError::InvalidPolicy(format!("Failed to increment event: {e}")))?;

Ok(event)
```

Round 4 L4 introduced per-kind constructors (`SadEvent::icp`, `est`, `upd`, `evl`, `rpr`) that each run `validate_structure` internally so the caller can't escape the structural gate. Sweep: zero `SadEvent::create` callers remain in the codebase. But `advance` here doesn't use `SadEvent::evl` — it clones the previous event, mutates fields, calls `increment`, and skips `validate_structure`.

The produced Evl is structurally valid for the parameters this code passes (Evl with optional `content=None`, `write_policy=Some(_)`, `governance_policy=None`, `previous` carried from the parent — all per `event.rs:338-348`). So the missed gate doesn't surface today. But the L4 design intent was that every Evl construction site enforces structural validity at construction time, not later at verification time. This site sneaks past the gate by going through `clone + mutate + increment` rather than the typed constructor.

The asymmetry also includes the `custody = None` reset that `SadEvent::evl` doesn't perform — `evl` would inherit custody from the previous event. Identity chains carry no custody, so the inheritance is None anyway, but the explicit reset is defensive.

**Suggested fix:** Refactor to use `SadEvent::evl`:

```rust
let mut event = SadEvent::evl(
    verification.current_event(),
    None,                        // content: identity chains carry none
    Some(new_policy.said),       // write_policy: the rotation
    None,                        // governance_policy: not evolved
)
.map_err(|e| PolicyError::InvalidPolicy(format!("Failed to create advance event: {e}")))?;
event.custody = None;            // identity chains carry no custody (defensive)
event.derive_said()              // re-derive after custody clear
    .map_err(|e| PolicyError::InvalidPolicy(format!("Failed to re-derive SAID: {e}")))?;
Ok(event)
```

The `derive_said` call after the custody clear is needed because `SadEvent::evl` already derived the SAID over a value that included the inherited custody. If `verification.current_event().custody` is always `None` for identity chains (which it should be — `create` sets `content=None` and never touches custody, and `advance` itself sets it to `None` here), the re-derive is a no-op and could be skipped after a one-time check in tests.

Defer until another change touches `advance` — the current code is correct, the cleanup is consistency-driven rather than bug-driven.

**Resolution (round-6 implementation):** Replaced the manual `clone + mutate + increment` block with `SadEvent::evl(verification.current_event(), None, Some(new_policy.said), None)` (`lib/policy/src/identity_chain.rs:83-93`). Identity chains carry no custody at any version (per the module-level docstring at `:6`), so the inherited custody is `None` and no explicit reset or re-derive is needed — the auditor's draft sketch was over-cautious. `SadEvent::evl` already runs `increment()` and `validate_structure` internally. Top-level imports tightened (`SadEventKind` and `Chained` moved into the test-only `mod tests` since the production code no longer references them). `test_advance_identity_chain` and the rest of the test suite pass unchanged.

---

## Positive Observations

- **The compaction order-preservation fix is correct and the test that catches it actually exercises multi-field SADs.** `services/sadstore/src/compaction.rs:79-94` — replaces the prior `remove + recurse + reinsert` with `get_mut + recurse`. The block comment names the failure mode precisely (`serde_json::Map::remove` is `swap_remove`-based; for ≥5 keys the round-trip permutes the map). `publish_pending_makes_events_fetchable_by_said` (`sad_builder_tests.rs:395-438`) is the regression guard: it `publish_pending`s SadEvents (7+ fields each for an Icp-with-governance), then asserts `get_sad_object(event.said)` resolves. Pre-fix this would 404 because the canonical SAID (computed over a permuted field order) wouldn't match the client's SAID. The test pins the bug at the realistic-payload level rather than via a synthetic 7-field probe — exactly the right shape.

- **`first_divergent_version` uses parameterized SQL and the comment explains why `ColumnQuery` couldn't express the shape.** `services/sadstore/src/repository.rs:282-299` — drops to `sqlx::query_scalar` with `$1` binding for `prefix.to_string()`. No injection surface. The docstring at `:269-281` names the asymmetry vs `is_divergent` (boolean answer) and points at the dedup-path call site that needs the actual version. The Cargo.toml comment (`services/sadstore/Cargo.toml:60-66`) explains why `sqlx` is promoted from transitive to direct dep. Documentation cost paid at every layer.

- **The `submit_dedup_returns_current_divergence_signal` integration test exercises the full dedup-path divergence-recovery contract end-to-end.** `services/sadstore/tests/sad_builder_tests.rs:600-681` — anchors v0/v1 via the builder, hand-builds two conflicting v2 Upd events bypassing the (single-actor) builder, anchors both forks in the KEL, submits each separately, then re-submits the second. Asserts `applied: false, diverged_at: Some(2)` on the dedup retry — the exact failure mode of Round 5 M1. Without this test, the Round 5 fix would be unpinned at the integration level. The deliberate bypass of `SadEventBuilder` (the comment at `:597-599` names the reason) is the right call: the builder refuses divergent state by design, so a divergence-creating test must stage HTTP-level forks.

- **`set_diverged_at_version`'s `or_else` semantics + `pub(crate)` accessibility match the threat model.** `event.rs:511-515`. External code can read `diverged_at_version()` (an authoritative claim) but can't fabricate one. The single internal caller at `sad_builder.rs:521` lives in `flush`'s post-absorb block, where the server's authoritative response is in scope. The local-detection-wins precedence (`if self.diverged_at_version.is_none()`) means a verifier that already saw the fork directly is trusted over the server's secondary report — which is right because the local detection is a structural observation, the server's report is a state snapshot. `set_diverged_at_version_or_else_semantics` (`sad_builder.rs:1088-1118`) pins both halves: setting on a None-token transitions to Some, and setting a different value on an already-Some token is a no-op.

- **The constructor split (`new` for fresh, `with_prefix` for resume) is internally consistent across the CLI surface.** `clients/cli/src/commands/exchange.rs:136-137` (publish-key) calls `SadEventBuilder::new(...)` because no chain exists yet; `:253-259` (rotate-key) calls `with_prefix(...)` because the chain is being resumed. The Round-4 L2 resolution removed the `Option<&Digest256>` ambiguity from `with_prefix`'s signature, and the CLI sites picked up the right constructor — neither has the "with_prefix(.., None)" contortion that prompted the L2 finding originally. The constructor name now genuinely tells the reader which path is being taken.

- **`KelsError::SelDivergent { at }` and the FFI mapping reuse the C-side `KelsStatus::DivergenceDetected` slot rather than introducing a parallel status code.** `lib/kels/src/error.rs:161-164` (variant), `lib/ffi/src/lib.rs:312` (mapping). KEL `DivergenceDetected { diverged_at, submission_accepted }` and SEL `SelDivergent { at }` are semantically the same C-side thing ("a chain went divergent at some point") — the choice to merge them at the FFI boundary keeps the C surface stable while keeping the Rust types distinct. `test_error_variants_display` enumerates the new variant.

- **The new `kels` dev-dep on `services/sadstore` is justified by a comment that names the principled fix.** `services/sadstore/Cargo.toml:73-86` — explains that the integration test needs a live KELS service for `AnchoredPolicyChecker` to walk a real KEL, that there's no test-mode bypass, that this inverts the usual "services don't depend on services" rule but only at dev-deps, and that the principled fix is "extract a `kels-test-harness` crate if the test-build cost becomes painful — file as a follow-up at that point, not pre-emptively." The `Dockerfile` (`:17-20`) and `garden.yml` (`:14`) updates note the same dev-dep linkage. Future-maintainer-readable.

---

## Discovered During Implementation

### ~~M1-followup. `SadEventBuilder::repair` doesn't heal divergence — Rpr lands at owner_tip+1 instead of at the divergence/corruption boundary~~ — RESOLVED

**Files:** `lib/kels/src/sad_builder.rs:391-421` (`repair`), `lib/kels/src/types/sad/event.rs` (`SadEvent::rpr`), and the new full-stack test at `services/sadstore/tests/sad_builder_tests.rs:683-825` (`flush_repair_on_divergent_chain_succeeds`) which currently pins only the M1 deadlock contract, not divergence resolution.

**Discovery context.** M1's resolution (the parity rework in this round) closed the `absorb_pending` deadlock — divergent cached tokens now resume cleanly, repair stages, flush completes. But the implementor's note flagged that the chain stays divergent server-side after a successful repair flow: `SadEvent::rpr` constructs the Rpr at `owner_tip.version + 1` extending owner's branch tip, the server's `is_repair` path computes `from_version` from the new events' versions, so `truncate_and_replace` runs at `from_version = owner_tip + 1` — past the divergence point. Net effect: Rpr is appended to owner's branch, both branches at the divergence version remain, `effective_said` continues to report `divergent: true`. The audit's M1 finding was about the deadlock; this is the chain-healing semantics that was masked by the deadlock pre-fix.

**Threat model — non-divergent repair is also a real case.** An adversary holding `write_policy` authorization (e.g., a compromised signer in a multisig endorsement) can submit Upd events silently. Server accepts (write_policy satisfied), chain stays linear from the server's perspective (`diverged_at_version` is `None`), but owner's last authoritative event is at `vK` and the chain now extends to `vT > vK` with adversary's events at `v(K+1)..vT`. Owner needs to truncate the corrupted tail and replace it. This is a non-divergent repair — same `Rpr` machinery, same governance-policy authorization, different boundary-detection.

**Authorization equivalence.** `governance_policy` = recovery key in the KEL analogy: `Rpr.evaluates_governance() == true` means every repair (any case) is gated on `governance_policy` server-side, just as KEL's `recover` and `contest` are both gated on the recovery key (not the signing key). Adversary with `write_policy` only can corrupt the tail with Upd but cannot produce an Rpr — only owner can repair. The single trust split applies to all repair cases.

**Why a single API.** KEL has `recover` and `contest` as two methods because they're protocol-semantically distinct (proactive extension vs. reactive contest of a leaked recovery key). SEL has no equivalent semantic split — `governance_policy` is referenced by SAID and held by whoever satisfies it, no "adversary used my governance authorization" scenario. The user has no protocol knob to turn between cases; the chain state determines what repair has to do. Single method, builder reads state and dispatches.

### Resolution

Replace `SadEventBuilder::repair` with an async, state-aware implementation that walks back via `previous` SAIDs through the local `sad_store` to find the truncation boundary, then constructs the Rpr at the right version with the right `previous`. Three cases:

- **Case A — divergent (`diverged_at_version` is `Some(d)`):** boundary is at `v(d-1)`. Walk back from owner's branch tip (`branches().first().tip`) via `previous` SAIDs — exactly `d-1` hops if owner's branch is dense, fewer if not. Construct Rpr at `version = d`, `previous = v(d-1).said`.

- **Case B — adversarially extended linear chain (`diverged_at_version` is `None`, but cached tip is not in owner's local store):** one paginated server fetch via `SadStoreClient::fetch_sad_events` gets the chain tail (≤64 events). Walk the slice in memory backward from the cached tip; at each event probe `sad_store` for ownership; first hit is the boundary at version `K`. Construct Rpr at `v(K+1)`, `previous = vK.said`. Bounded by page size = `MINIMUM_PAGE_SIZE = 64` (= `MAX_NON_EVALUATION_EVENTS + 1`). If the walk exhausts the page without a local-store hit, the local cache is inconsistent with the server's view — error `InvalidKel`.

- **Case C — clean state (`diverged_at_version` is `None`, cached tip is in owner's local store):** the first probe in the Case-B walk hits — there's nothing to repair. Return an error; staging refuses. Add a new variant (`KelsError::NothingToRepair` or repurpose an existing one — implementor's call) so callers can distinguish from authorization failures.

**Bound.** All three walks are bounded by the governance invariant: adversary can't submit `Evl`/`Rpr` (governance-gated), so any adversarial extension is at most `MAX_NON_EVALUATION_EVENTS = 63` hops; divergence point is similarly bounded by the seal because both branches share state up to the last `Evl`/`Rpr`. The bounded-walk pattern parallels KEL's `find_missing_owner_events` (`builder.rs:469-496`) — same shape, inverted probe direction (KEL probes server for archival; SEL probes local for adversarial extension).

**API change.**

```rust
async fn repair(&mut self, content: Option<cesr::Digest256>) -> Result<cesr::Digest256, KelsError>
```

`repair` becomes async (the only async staging method — justified because it's the only one that needs to read state beyond the cached verification token). Existing callers update accordingly. Note that `repair` requires `sad_store: Some(_)` on the builder — error cleanly when not configured.

**One page fetch, in-memory walk.** The bound on adversarial extension is exactly the page size: `MAX_NON_EVALUATION_EVENTS = MINIMUM_PAGE_SIZE - 1 = 63` by construction (`lib/kels/src/lib.rs:139`). So one paginated server fetch via `SadStoreClient::fetch_sad_events` gets every event the walk could possibly need. Walk that slice in memory backward from the cached tip; at each event probe `sad_store` for ownership; first hit is the boundary. The server-fetched events are SAID-integrity-protected (server can return the right event at a given SAID or nothing, no substitution). **The boundary decision remains local-store-only** — an event is owner-authored iff it's in `sad_store`; the server slice is just the chain segment to walk. This mirrors KEL's `find_missing_owner_events` (`lib/kels/src/builder.rs:469-496`) — same shape, mirrored data sources (KEL loads tail from local, probes server in-memory; SEL loads tail from server, probes local in-memory). One round-trip, not iterative SAID-by-SAID.

**Tests to add.**

- Unit-level `repair_at_divergence_version` in `sad_builder.rs` test module: build a divergent token (two branches at vN), seed `sad_store` with owner's branch events, call `repair`, assert the staged Rpr has `version = N`, `previous = v(N-1).said`.
- Unit-level `repair_at_adversarial_extension_boundary` in `sad_builder.rs` test module: build a single-branch token where owner's last authoritative event is at `vK` and cached tip is at `vT > vK`, seed `sad_store` with only owner's events `v0..vK`, call `repair`, assert the staged Rpr has `version = K+1`, `previous = vK.said`.
- Unit-level `repair_clean_state_errors` in `sad_builder.rs` test module: build a single-branch token where cached tip is in `sad_store`, call `repair`, assert the new error variant.
- Full-stack `flush_repair_heals_divergent_chain` in `services/sadstore/tests/sad_builder_tests.rs`: extend the existing `flush_repair_on_divergent_chain_succeeds` test (or replace it) to assert that after `repair` + `flush`, `fetch_sel_effective_said(prefix)` returns `divergent: false` — the divergence is actually healed server-side.

**Walk-back implementation reference.** The bounded walk should follow the structure of `KeyEventBuilder::find_missing_owner_events` (`lib/kels/src/builder.rs:469-496`) — fetch tail, walk backward, terminate at first probe match. Adapt the probe direction (local store hit vs. miss) and the termination condition (boundary found vs. governance-invariant cap).

**Resolution (round-6 implementation):** Implemented per the §Resolution section. New `KelsError::NothingToRepair` variant (`lib/kels/src/error.rs:166-169`) for the Case-C signal. `SadEventBuilder::repair` is now `async` and dispatches on chain state (`lib/kels/src/sad_builder.rs:520-625`); two free helper functions implement the walk: `walk_back_to_version` for Case A (loads each predecessor from `sad_store`, bounded by `MAX_NON_EVALUATION_EVENTS`) at `:83-116`, and `walk_back_to_first_owner` for Case B — **one paginated server fetch + in-memory walk** — at `:130-208`. The Case B walk takes a `&dyn PagedSadSource` (the existing `lib/kels/src/types/sad/sync.rs` trait, which `HttpSadSource` already implements) so unit tests can inject a `VecSadSource` mock; in production `repair` calls `sad_client.as_sad_source()` to bridge `SadStoreClient` to the trait. Case B requires both `sad_store: Some(_)` AND `sad_client: Some(_)` — the local store remains the boundary oracle, the server slice is the chain segment for traversal (events are SAID-integrity-protected; the boundary decision itself stays local-store-only). Case C errors with `NothingToRepair` directly. `flush` grew a post-submit branch (`:730-768`) that re-hydrates from the server via `client.verify_sad_events` whenever the staged batch contains an Rpr — needed because the local verifier's `resume + verify_page` path can't accept a truncating Rpr (its `previous` points pre-truncation and won't match any current branch tip in the rehydrated HashMap). One extra GET on the repair path; non-repair flushes keep the incremental-absorb fast path. The `since` cursor on the page-fetch walk uses `since: None` for the first page and the last event's SAID for subsequent pages, terminating once the cached tip is visible (or `has_more` is false) — avoids over-fetching for chains beyond one page while keeping the common case (chains within `MINIMUM_PAGE_SIZE`) to one round-trip. Tests dropped: `repair_stages_rpr_from_tip` (clean-chain extension contract is gone) and `repair_allowed_on_divergent_chain` (replaced by the boundary-asserting `repair_at_divergence_version`). Tests added: 5 unit tests in `sad_builder.rs` — `repair_at_divergence_version`, `repair_at_adversarial_extension_boundary` (N=1), `repair_at_adversarial_extension_boundary_multi_step` (N=4 — the page-fetch shape's load-bearing pin), `repair_clean_state_errors`, `repair_without_sad_store_errors` — plus two full-stack tests in `services/sadstore/tests/sad_builder_tests.rs`: `flush_repair_heals_divergent_chain` (Case A) and `flush_repair_heals_adversarially_extended_chain` (Case B with N=3 adversary extension; pre-followup-extension this would have failed at `walk_back_to_first_owner`'s single-step probe). Both full-stack tests assert `fetch_sel_effective_said` returns `divergent: false` post-flush. `staged_chain_verifies_from_scratch` was edited to use `evaluate` instead of the now-erroring `repair` on a clean chain. `build_divergent_token` test fixture extended to return `(SelVerification, v0, v1_a, v1_b)` so callers can seed the `sad_store` for walk-back. New `build_adversary_extension_fixture` helper produces parameterized owner+adversary linear chains for the Case B unit tests. The `:repair\b` terminology pattern in `.terminology-forbidden` was tightened to `(^|[^:]):repair\b` to allow Rust's `::repair` while still catching wire-format strings like `sad-announcement:repair`. `make` clean. **Contract decided:** `repair` is for actual healing — clean chains return `NothingToRepair`, divergent chains stage a boundary Rpr at `version=d, previous=v(d-1).said` (truncates both branches), adversary-extended linear chains stage a boundary Rpr at `version=K+1, previous=vK.said` (truncates the adversary tail). The Case B walk uses one or a few server page-fetches to hydrate adversary's intermediate events into an in-memory map; SAID-integrity protects against substitution, and the local store remains the trust boundary for owner-authorship decisions. All flushes that include an Rpr force a fresh server hydration to absorb the post-truncation state.
