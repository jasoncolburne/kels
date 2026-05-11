# Branch Audit: KELS-126_sad-event-builder (Round 4) — 2026-04-25

Fourth-pass audit of the SadEventBuilder branch after `/clear`. Read every changed source file plus the prior three round documents to avoid re-finding resolved issues. Cumulative across prior rounds: 21 resolved (10 in R1 + 7 in R2 + 4 in R3), 0 open. This round adds 4 new findings (1 medium, 3 low), all open — read-only audit.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 1        |
| Low      | 0    | 3        |

---

## Medium Priority

### ~~1. `flush()` silently drops the server's `diverged_at` signal — a concurrent-writer fork during flush leaves the builder thinking the chain is still linear~~ — RESOLVED

**File:** `lib/kels/src/sad_builder.rs:493-528` (flush), `lib/kels/src/client/sadstore.rs:204-214` (submit), `lib/kels/src/types/sad/request.rs:44-52` (response type)

The server's `submit_sad_events` returns `SubmitSadEventsResponse { diverged_at: Option<u64>, applied: bool }` and the type is even annotated `#[must_use = "SubmitSadEventsResponse.applied must be checked — events may be rejected"]`. But `SadStoreClient::submit_sad_events` (client/sadstore.rs:204) returns `Result<(), KelsError>` and throws the body away:

```rust
let resp = self.client.post(&url).json(events).send().await?;
if resp.status().is_success() {
    Ok(())  // body never parsed
} else { ... }
```

The `must_use` annotation is unenforceable because the bearing struct never reaches the caller. `flush()` then runs phase 3 (`absorb_pending`) by re-verifying **only** the local pending events through `SelVerifier::resume`, which has never seen the adversary's fork — so the resulting `SelVerification` has `diverged_at_version = None`. The local `sad_verification` claims the chain is linear; the server holds two branches.

Concrete attack/race:

1. Owner hydrates SEL at v5 (linear). `sad_verification.diverged_at_version() == None`.
2. Owner stages an Upd at v6, calls `flush`.
3. Concurrent (adversarial or not) writer submits a different Upd at v6. Server now has v6_a and v6_b. Submit succeeds; server returns `diverged_at: Some(6), applied: true`.
4. Client discards the response. `absorb_pending` resumes the verifier from the pre-fork token, runs `verify_page(&[owner_v6])`, sees one event at v6, no divergence — produces a token with `diverged_at_version: None`.
5. Owner calls `update()` again. Builder thinks it's appending to a linear chain at v6. Server-side this becomes v7 on one branch of an already-divergent chain. The owner has no signal that anything is wrong — `sad_verification().diverged_at_version()` keeps returning `None` indefinitely.

The Round 2 work added precisely this kind of guard for the prefix-mismatch case (`requested_prefix` + `CannotResumeDivergentChain`). The same shape of silent state drift exists here, just on a different axis.

**Suggested fix:** Three options, in order of preference.

- **(a)** Parse the response in `SadStoreClient::submit_sad_events` and return `(Option<u64>, bool)` (or the full struct). In `flush()`, when `diverged_at` is `Some(_)`, do not absorb locally — re-hydrate `sad_verification` via `verify_sad_events` (server round-trip) so the new token correctly reports `diverged_at_version`. This converts a silent into a loud signal at the cost of one extra fetch on the rare divergent path.
- **(b)** Same response parsing, but on `diverged_at: Some(_)` return a new `KelsError::DivergenceDetected { at: u64 }` variant from `flush()` and leave `pending_events` populated. Caller decides whether to re-hydrate. Less expensive than (a) but pushes complexity onto callers.
- **(c)** At minimum, parse the response and propagate it as a new return value of `flush() -> Result<SubmitSadEventsResponse, KelsError>` so the caller has the option to react. Cheapest change; doesn't fix the local-token-staleness automatically but stops the silence.

The corresponding `HttpSadSink` at `lib/kels/src/types/sad/sync.rs:122-142` has the same shape but is used for forwarding/sync rather than owner-initiated submission, so the divergence signal there is less load-bearing — fixing M1 by changing `SadStoreClient::submit_sad_events` is sufficient. The `HttpSadSink` is symptomatic of the same root (the response type isn't parsed anywhere) but doesn't need a behavior change.

**Resolution:** Implemented the KEL-style "stop pretending, lock down stagers, wait for explicit owner-initiated repair" model — no auto-rehydration, no auto-recovery. Five layers of change:

1. **Parse the submit response.** `SadStoreClient::submit_sad_events` now returns `Result<SubmitSadEventsResponse, KelsError>` and parses the body via `resp.json()`. The `#[must_use]` annotation on `SubmitSadEventsResponse` now actually fires at call sites.
2. **Stamp server divergence onto the local token.** New `pub(crate) fn SelVerification::set_diverged_at_version(&mut self, version: u64)` with `or_else` semantics (preserves existing `Some(_)`, only stamps when the local detection produced `None`). `flush()` calls this after `absorb_pending` whenever the server reported `diverged_at: Some(_)`. The local verifier never saw the adversary's events, so without this stamp the token would report `None` while the server has two branches.
3. **Gate normal stagers on `sad_verification.diverged_at_version()`.** New `KelsError::SelDivergent { at: u64 }` variant whose message names repair as the explicit recovery path. `update` and `evaluate` call `require_non_divergent()` and refuse with this error when the chain is divergent. `repair` is allowed (it's how the owner resolves divergence). `incept` / `incept_deterministic` are already gated by `require_fresh_builder`.
4. **`flush` returns `FlushOutcome` instead of `()`.** New `pub struct FlushOutcome { pub diverged_at_at_submit: Option<u64> }`, marked `#[must_use]`, forward-extensible for future flush signals. CLI `exchange.rs` (publish + rotate) and `sel.rs` (submit) print a `kels sel repair` warning when `diverged_at_at_submit.is_some()`. FFI `lib/ffi/src/sad.rs` keeps a single status code on the C boundary; comment notes that callers needing the version should fetch the SEL after submit.
5. **`HttpSadSink` parses the body but discards.** Forwarding/sync isn't owner-driven, so the signal isn't actionable there — the change is just to honor the `must_use` annotation by invoking the type. No behavior change at sink call sites.

Tests pinned: `update_refused_on_divergent_chain`, `evaluate_refused_on_divergent_chain`, `repair_allowed_on_divergent_chain`, `set_diverged_at_version_or_else_semantics` (all in `lib/kels/src/sad_builder.rs`), plus updated `flush_submits_and_absorbs` (`services/sadstore/tests/sad_builder_tests.rs`) which now asserts `outcome.diverged_at_at_submit.is_none()` on the linear-chain path. `KelsError::SelDivergent { at: 7 }` added to the `test_error_variants_display` enumeration in `lib/kels/src/error.rs`.

Naming note: the plan called for `KelsError::DivergenceDetected { at: u64 }`, but `DivergenceDetected { diverged_at, submission_accepted }` already exists for KEL submissions with different semantics. Added `SelDivergent { at }` instead to avoid breaking the KEL variant; the FFI mapping at `lib/ffi/src/lib.rs:312` routes both variants to the same `KelsStatus::DivergenceDetected` so the C surface is unchanged.

Non-goals honored: no auto-rehydration from server (tie-break may pick the adversary's branch), no auto-trigger of repair, `flush`'s contract that pending events are server-accepted on success unchanged, mutator stays `pub(crate)`. `make` (fmt + clippy + tests + build) passes clean.

---

## Low Priority

### ~~2. `with_prefix` constructor name implies a prefix is required, but `sel_prefix` is `Option<&Digest256>`~~ — RESOLVED

**File:** `lib/kels/src/sad_builder.rs:88-115`

The signature is:

```rust
pub async fn with_prefix(
    sad_client: Option<SadStoreClient>,
    sad_store: Option<Arc<dyn SadStore>>,
    checker: Option<Arc<dyn PolicyChecker + Send + Sync>>,
    sel_prefix: Option<&cesr::Digest256>,
) -> Result<Self, KelsError> {
```

Round 2's M2/L4 fixes intentionally collapsed `with_dependencies` into `with_prefix` because hydration was the only thing distinguishing them. But `with_prefix(.., None)` is now reachable — `clients/cli/src/commands/exchange.rs:137-143` exercises exactly that path on the inception flow:

```rust
let mut sad_builder = SadEventBuilder::with_prefix(
    Some(sad_client.clone()),
    Some(sad_store),
    Some(checker),
    None,  // <-- "with_prefix" called with no prefix
)
```

The CLI comment (`exchange.rs:134-136`) explains it: "No existing chain yet (`sel_prefix = None`) — `with_prefix` simply wires deps without attempting hydration. Keeps the construction path identical to rotate-key so the two don't drift." That rationale is correct, but the constructor's *name* is misleading at the call site — a reader who hasn't looked at the body sees `with_prefix(.., None)` and pauses.

**Suggested fix:** Either (a) rename to a name that doesn't promise a prefix — `connected` or `with_deps` or simply expose two constructors `new(...)` and `hydrated(..., prefix: &Digest256)` where the latter takes a non-Option, with `new` accepting all three Option deps; or (b) keep the current name but change `sel_prefix: Option<&Digest256>` to `sel_prefix: &Digest256` and have the inception caller use a separate constructor that doesn't take a prefix. The current shape — one constructor that ambiguously means both — is the worst of both. Low priority; the docstring at `:73-87` is clear enough that I'd defer this until another constructor-shape change.

**Resolution:** Took option (b) — kept the names `new` and `with_prefix`, tightened `sel_prefix` to `&cesr::Digest256`. Five-part change:

1. **Constructor signature.** `with_prefix` now takes `sel_prefix: &cesr::Digest256` (was `Option<&cesr::Digest256>`).
2. **Internal delegation.** `with_prefix` now calls `Self::new(...)` for field wiring, then sets `requested_prefix = Some(*sel_prefix)` and runs the hydration RPC. No more duplicated struct-literal initialization across the two constructors — adding a builder field touches `new` only.
3. **CLI publish-key switches to `new`.** `cmd_exchange_publish_key` was the only call site passing `None`; the comment about visual parallelism with `cmd_exchange_rotate_key` was eaten by the rename to `with_prefix` in Round 2 and is now removed. Inception calls `new`; resume calls `with_prefix`. The constructor names match the contracts.
4. **CLI rotate-key + tests.** `cmd_exchange_rotate_key` and the unit test `requested_prefix_mismatch_rejected_at_absorb` updated from `Some(&prefix)` to `&prefix`. Compiler-driven.
5. **The Round-2 prefix-mismatch guard is now meaningful through every `with_prefix` call.** Previously a caller passing `None` got `requested_prefix = None`, neutering the guard. With the `Option` gone, every `with_prefix` callsite participates in the prefix-mismatch check at flush time.

`make` passes clean. Tests touched: existing `requested_prefix_mismatch_rejected_at_absorb` (one call-site sweep). No new tests needed — the gating already covered by the existing test, and `new`'s coverage is unchanged.

The CLI publish-flow comment that was excused by the prior shape ("Keeps the construction path identical to rotate-key so the two don't drift") is removed; the two paths *legitimately* differ — inception vs. resume — and the constructor names now reflect that.

### ~~3. `incept`'s `topic: &str` vs the v0 storage as `topic: String` — every call clones the topic via `.to_string()` even when the caller already owns one~~ — RESOLVED

**File:** `lib/kels/src/sad_builder.rs:280-306, 315-355`

```rust
pub fn incept(
    &mut self,
    topic: &str,
    ...
) -> Result<cesr::Digest256, KelsError> {
    ...
    let event = SadEvent::create(
        topic.to_string(),
        ...
    )?;
```

Same shape on `incept_deterministic`. The `SadEvent::create` signature takes `String` (per `event.rs:168`), so the `&str` → `String` clone is forced regardless of whether the caller had an owned string. CLI callers have `&'static str` constants (e.g., `kels_exchange::ENCAP_KEY_KIND`), so the clone is benign there. But identity-chain callers in `lib/policy/src/identity_chain.rs` could in principle pass an owned `String` they constructed — they'd pay one extra clone.

**Suggested fix:** Take `topic: impl Into<String>` and forward directly. Trivial change, removes one allocation on the cold path. Defer until another call-site change touches these functions. Keeping topic as `&str` is the more legible signature for the common case (string literal call sites).

**Resolution:** Tightened together with L4 in a single pass. `SadEventBuilder::incept`, `SadEventBuilder::incept_deterministic`, `compute_sad_event_prefix`, and the new `SadEvent::icp` constructor all take `topic: impl Into<String>`. `&'static str` callers (CLI: `kels_exchange::ENCAP_KEY_KIND`, identity chain: `IDENTITY_CHAIN_TOPIC`) pay the same one allocation they always did; callers passing owned `String` (none currently, but the door is open) skip the clone.

### ~~4. The `SadEvent::create(topic.to_string(), kind, prev, content, wp, gp)` positional argument list is a footgun on a 6-tuple of `Option<Digest256>` slots~~ — RESOLVED

**File:** `lib/kels/src/sad_builder.rs:288-295, 324-331, 891-899` (test fixture)

`SadEvent::create` takes `(topic: String, kind: SadEventKind, previous: Option<Digest256>, content: Option<Digest256>, write_policy: Option<Digest256>, governance_policy: Option<Digest256>)` — four positional `Option<Digest256>` arguments in a row, three of which are `None` in the staging paths. Two are flipped (write_policy at slot 5, governance_policy at slot 6) and a transposition produces a structurally-invalid event that `validate_structure` catches but only after an SAID derivation that costs a Blake3 round.

The Round 1 / Round 2 tests put the call site through enough scenarios that a transposition would surface, but the contract is fragile: a future maintainer who adds an `Est` fixture by hand can easily get the slots wrong. Round 3 fixed this exact class of bug for the test fixture (build_chain `kind: &str` → `topic: &str` rename) — the same cleanup applies one layer up.

**Suggested fix:** Either a builder-style `SadEvent::Builder` that names each slot, or per-kind constructors (`SadEvent::icp(topic, write_policy, governance_policy)`, `SadEvent::est(...)`, etc.). The latter is a bigger rewrite of `event.rs` but eliminates the slot-confusion class. Low priority — the call-site count is bounded (3 in `sad_builder.rs`, a handful in tests), the failure mode is loud (validate_structure rejects), and the cleanup cost is non-trivial.

**Resolution:** Took the per-kind-constructor option. Five new typed constructors in `lib/kels/src/types/sad/event.rs`, each running `validate_structure` internally so the caller can't escape the structural gate:

- `SadEvent::icp(topic: impl Into<String>, write_policy: Digest256, governance_policy: Option<Digest256>)` — v0 inception. Standalone (no `previous` to refer to).
- `SadEvent::est(previous: &Self, content: Option<Digest256>, governance_policy: Digest256)` — v1 governance establishment from a v0 tip.
- `SadEvent::upd(previous: &Self, content: Digest256)` — v+1 update from a chain tip.
- `SadEvent::evl(previous: &Self, content, write_policy, governance_policy: Option<Digest256>×3)` — v+1 governance evaluation from a chain tip.
- `SadEvent::rpr(previous: &Self, content: Option<Digest256>)` — v+1 repair from a chain tip.

Each constructor's signature names the kind-specific contract directly: required fields are `Digest256`, forbidden fields don't appear at all, optional fields are `Option<Digest256>`. The 4-`Option<Digest256>` slot-confusion path is gone — there's no constructor where you can transpose `write_policy` and `governance_policy`.

Sweep: zero `SadEvent::create` callers remain in the codebase. Converted call sites: `lib/kels/src/sad_builder.rs` (`incept`, `incept_deterministic`, `update`, `evaluate`, `repair`, plus `build_divergent_token` and `absorb_pending_errors_on_divergent_cached_verification` test fixtures), `lib/policy/src/identity_chain.rs` (`create` + `test_advance_rejects_wrong_topic`), `lib/kels/src/types/sad/event.rs` (test fixtures + `compute_sad_event_prefix` itself), `lib/kels/src/types/sad/sync.rs` (`test_divergence_detection_at_page_boundary`), `lib/kels/src/types/sad/verification.rs` (`create_v0_no_evaluation`), `lib/kels/src/types/mod.rs` (validate-structure test fixtures), `services/sadstore/tests/integration_tests.rs` (`test_submit_event_invalid_said_rejected`).

Side effects: `compute_sad_event_prefix` now returns `Result<_, KelsError>` instead of `Result<_, StorageError>` because it delegates to `SadEvent::icp` which returns the latter. All callers used either `.context(...)` (anyhow) or `.map_err(...)` so the change is non-breaking. The unused `Chained` and `SadEventKind` imports left behind in `sad_builder.rs` and `sync.rs` test fixtures (their callers no longer mutate `event.kind`/`event.increment()` directly) were dropped.

`make` passes clean (fmt + clippy + 41 test groups + build), zero warnings.

---

## Positive Observations

- **The Round 2 R3-resolution `PostSadObjectResponse` change is symmetric across success and exists-already paths.** `services/sadstore/src/handlers.rs:457-466, 532-538` returns the same `Json(PostSadObjectResponse { said: canonical_said })` body on both 200 (object already exists) and 201 (newly stored). A client doing repeat submissions during retries gets the same authoritative SAID either way. The integration test `post_sad_object_returns_canonical_said_for_expanded_form` (`sad_builder_tests.rs:340-391`) exercises both halves of the contract.

- **The `must_use` annotation on `SubmitSadEventsResponse` (`request.rs:47`) is exactly right even though the client side currently defeats it.** When M1 above is fixed by parsing the response, the annotation will start firing as intended on any caller who tries to `let _ = ...` the result. The upstream marker stays correct; the bug is downstream.

- **The compaction depth bound (`MAX_COMPACTION_DEPTH = 32`) on `compact_sad` is unbounded-recursion defense done right.** `services/sadstore/src/compaction.rs:23, 58-62, 116-120` — both `compact_children` and `compact_value` check `remaining_depth == 0` and return a structured error, preventing stack overflow on adversarial nested SAD payloads. Combined with the size-cap `max_sad_object_size()` (default 1 MiB), the post-handler is bounded in both depth and breadth.

- **The two-phase compaction (`compact_sad` dry-run + HEAD check + `commit_compacted`) is anti-amplification by construction.** `services/sadstore/src/handlers.rs:438-477` — phase 1 computes SAIDs and builds compacted JSON in memory, phase 2 only writes to MinIO if the canonical SAID isn't already there. An attacker submitting the same expanded SAD repeatedly does N hashes per attempt but only one MinIO put-set ever, regardless of N. The block comment at `compaction.rs:5-13` spells out the design intent.

- **Round 3's R3 v0 `validate_structure` calls in `incept` and `incept_deterministic` (`sad_builder.rs:300-302, 336-337`) make the prefix-derivation function `compute_sad_event_prefix` and the staging path agree on shape.** `event.rs:178-180` runs `validate_structure` on its v0 before returning the prefix. If a future tightening of Icp's structural contract adds a new required field, both paths fail in lockstep instead of diverging silently.

- **The repair seal-floor invariant is enforced redundantly across two version sources, by design.** `services/sadstore/src/handlers.rs:1351-1364, 1413-1426` checks `from_version > last_governance_version` (queried directly from the events table pre-truncation) AND `from_version > establishment_version` (read from the post-replacement verification token). Either one alone closes the seal; both together guard against a race where the events table read and the verifier disagree. Low cost (two integer comparisons), high correctness ceiling.

- **The `governance_policy()` accessor's pending walk (`sad_builder.rs:202-212`) gets the precedence right for the staged-Evl-with-None case.** A pending Evl that proposes no governance change (`event.governance_policy.is_none()`) doesn't shadow an earlier pending Evl that did declare one — the inner `if event.governance_policy.is_some()` guard skips it and keeps walking. Without that, a "pure evaluation" Evl staged after a governance-evolving Evl would incorrectly report the pending tail's None as the answer.
