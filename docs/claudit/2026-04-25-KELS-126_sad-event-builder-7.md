# Branch Audit: KELS-126_sad-event-builder (Round 7) — 2026-04-25

Seventh-pass audit of the SadEventBuilder branch after `/clear`. Read every changed source file plus the prior six round documents to avoid re-finding resolved issues. Cumulative across prior rounds: 43 resolved (10 R1 + 7 R2 + 4 R3 + 4 R4 + 4 R5 + 5 R6 + M1-followup + 4 R7), 0 open. This round added 4 findings (2 medium, 2 low), all 4 now resolved.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 2        |
| Low      | 0    | 2        |

---

## Medium Priority

### ~~1. `walk_back_to_first_owner` fetches the whole chain from v0 to find a boundary that is at most 63 hops from the tip — O(N) network/memory where O(63) suffices~~ — RESOLVED

**File:** `lib/kels/src/sad_builder.rs:130-208`

The Case-B walk paginates **forward from v0** (`since: None` on the first call, `since = last_said` thereafter), accumulating every event into the `chain` HashMap until either the cached tip is visible or `has_more = false`:

```rust
let mut since: Option<cesr::Digest256> = None;
loop {
    let (events, has_more) = sad_source.fetch_page(prefix, since.as_ref(), crate::page_size()).await?;
    ...
    for event in &events { chain.insert(event.said, event.clone()); }
    if found_start || !has_more { break; }
    since = last_said;
}
```

Production server semantics (`services/sadstore/src/repository.rs:374-410`) make this a strict forward scan: `since` returns events with `(version, said) > (since.version, since.said)`, ordered by `(version ASC, said ASC)`. So the loop fetches pages contiguously from v0 onward.

The walk itself only needs the events between owner's last authoritative event `vK` and the cached tip `vT` — by construction a span of `T - K ≤ MAX_NON_EVALUATION_EVENTS = 63` events (the governance bound: an adversary holding only `write_policy` can submit at most 63 `Upd` between governance windows). The `for _ in 0..MINIMUM_PAGE_SIZE` traversal bound (`:178`) reflects this.

For a chain that has been live across many governance evaluations — say a long-running exchange-key SEL with 500 events — the walk fetches `ceil(500/64) = 8` pages of 64 events each (≈500 SadEvents and their JSON serialization round-trips) just to reach the last 1–63 events where the boundary actually lives. The walk then traverses 1–63 hops in memory and discards the rest.

The cost grows linearly with chain length, even though the *useful* work is bounded by 63 events. This is the kind of asymmetry that doesn't bite during integration tests (which use 2–6-event chains) but will bite anyone who repairs an established chain. The integration test that does exercise multi-step Case B — `flush_repair_heals_adversarially_extended_chain` (`services/sadstore/tests/sad_builder_tests.rs:868-1019`) — uses T=4, so it always fits in one page and never exercises the multi-page fetch loop either.

The bound check at `:198-201` (`exceeded governance bound` / `MINIMUM_PAGE_SIZE`) is the in-memory traversal cap, not a fetch cap. The fetch loop has no early-termination beyond `found_start`.

**Impact.** A repair on a chain with many governance evaluations does N round-trips to the SAD store where 1 round-trip should suffice. For the exchange-key flow (`cmd_exchange_rotate_key`), this happens in the user-facing CLI — a UX-visible delay. For automated repair flows it's a server-load multiplier on every repair.

**Suggested fix:**

- **(a)** Server-side: add a `fetch_sad_events_tail(prefix, limit)` endpoint that returns the last N events ordered by `(version DESC, said DESC)`. The walk then issues one such call with `limit = MINIMUM_PAGE_SIZE`, walks back in memory, and never paginates. Cleanest fix; requires a server endpoint addition.
- **(b)** Client-side, no server change: walk in two phases. Phase 1: `fetch_sel_effective_said` to learn the tip's version `T`, then bisect-style page-fetch via repeated `since` queries to land on `T - 64` and fetch one page of 64 events. Costs 1 effective-SAID call + 2 page fetches in the worst case, independent of chain length. More fiddly.
- **(c)** Document the asymmetry and ship as-is. The repair flow isn't on a hot path and chains might stay short in practice. Defer until a profiler shows real cost.

(a) is the right shape — the server already has the data ordered by `(version ASC, said ASC)`; reversing the order is a one-flag change. But (a) requires a server endpoint addition and integration test, so (c) for now with a docstring note that current performance is `O(chain length)` is also defensible.

If shipping (c), the docstring at `:130-150` should add an explicit "**Performance.** Fetches the entire chain from v0 forward — `O(chain length)`. Acceptable for short-lived chains; consider a tail-fetch endpoint if profiling flags this." note.

**Resolution (round-7 implementation):** Took option (a). New server endpoint `POST /api/v1/sad/events/tail` (`services/sadstore/src/server.rs:45-48`) backed by `SadEventRepository::get_stored_tail` (`services/sadstore/src/repository.rs:301-323`) which queries with `(version DESC, said DESC)` and reverses before returning so the caller sees `(version ASC, said ASC)`. New request type `SadEventTailRequest` (`lib/kels/src/types/sad/request.rs:38-50`) and handler `get_sad_events_tail` (`services/sadstore/src/handlers.rs:1620-1659`). Client method `SadStoreClient::fetch_sad_events_tail` (`lib/kels/src/client/sadstore.rs:255-282`) plus a `PagedSadSource::fetch_tail` trait method (`lib/kels/src/types/sad/sync.rs:35-50`) with a default impl that errors `OfflineMode` so legacy sources don't silently degrade; `HttpSadSource` overrides at `:118-139`. `walk_back_to_first_owner` (`lib/kels/src/sad_builder.rs:141-188`) replaces the forward-paginate loop with a single `fetch_tail(prefix, MINIMUM_PAGE_SIZE)` call — O(64) regardless of chain length. `VecSadSource` test mock provides a `fetch_tail` impl matching production semantics. Existing repair tests pass unchanged; the multi-step Case B integration test (`flush_repair_heals_adversarially_extended_chain`) still validates the boundary semantics and now exercises the new endpoint end-to-end.

### ~~2. The dedup short-circuit's new `first_divergent_version` query runs **before** the per-prefix rate limit check — gives an adversary submitting duplicates a free DB read amplifier~~ — RESOLVED

**File:** `services/sadstore/src/handlers.rs:1293-1325, 1327-1335`

Round 5 M1's fix added a `first_divergent_version` query inside the `new_events.is_empty()` branch so the dedup-path response carries the chain's *current* divergence state. This query runs at `:1303-1315`, **before** the rate-limit check at `:1327-1335`:

```rust
if new_events.is_empty() {
    let diverged_at = match state.repo.sad_events.first_divergent_version(sel_prefix).await { ... };
    if let Err(e) = tx.commit().await { ... }
    return ...;
}

if let Err(msg) = check_prefix_rate_limit(...) { ... }
```

An attacker who repeatedly submits a previously-applied batch with the same SAIDs hits the dedup path. Each request now costs the server:

1. Begin tx.
2. Bulk SAID-existence lookup over `sad_events` (the dedup query at `:1264-1290`).
3. **`first_divergent_version` query** — a `SELECT MIN(version) FROM (... GROUP BY version HAVING COUNT(*) > 1) ...` over the `sad_events` table.
4. Commit (no-op).
5. Return.

Step 3 is new in this round, and on a long-lived chain it's a non-trivial query — `GROUP BY version HAVING COUNT(*) > 1` over the entire chain's events. With no rate limit upstream, the per-request cost roughly doubles vs. pre-Round-5 baseline.

This isn't a regression in the security sense — the existing pre-fix code also had the dedup query running before the rate limit (the rate limit's purpose is to bound *applied* events, not request volume). But Round 5's fix added the *second* read on the unrate-limited path without flagging the amplifier shape. A duplicate-submit campaign now does roughly twice the database work it did before.

The Round 5 audit document acknowledges that the query "performs no writes, so a pool-level read alongside the in-flight tx is fine" — that's about correctness (no race), not about resource consumption.

**Impact.** Low to medium — one extra `SELECT MIN(version) FROM (... GROUP BY version HAVING COUNT(*) > 1)` per duplicate-submit request, on top of the existing dedup query. Bounded by the chain's total event count via the index on `(prefix, version)`. Real-world impact depends on whether a global IP-level rate limiter sits in front of the service.

**Suggested fix:** Three options.

- **(a)** Move the rate-limit check above the `new_events.is_empty()` branch. The check is `accrue=0` for the dedup path (no new events committed), so it's not currently a write-side gate, but a `check_only=true` variant could still rate-limit *requests* per prefix. Cleanest fix; requires extending `check_prefix_rate_limit` with a non-accruing mode.
- **(b)** Skip the `first_divergent_version` query when the chain isn't already known to be divergent — keep a `divergent` boolean cached per prefix and only run the MIN query when the cache says yes. Adds cache complexity for a niche optimization.
- **(c)** Document the amplification trade-off as deliberate (the divergence signal is more useful than the saved query) and add an upstream IP rate limiter as the right layer to address abuse. Cheapest; pushes the problem out of this code.

(a) is the most direct match for the model — "every request consumes a request budget, even if no events apply." (c) is fine if you're confident the upstream rate limiter handles it.

**Resolution (round-7 implementation):** Took option (a). `check_prefix_rate_limit` (`services/sadstore/src/handlers.rs:158-188`) gains an `accrue: bool` parameter — when `true` it both checks and consumes budget atomically. The single call site moves from after the dedup branch to above the transaction setup (`:1226-1239`) and uses `events.len()` (the request's claimed event count) with `accrue=true`. The dedup branch's `first_divergent_version` query no longer runs unless the rate limit passes. The standalone `accrue_prefix_rate_limit` helper and the post-commit accrual at the bottom of `submit_sad_events` are deleted — pre-flight charge supersedes both. Duplicate-submit campaigns now consume budget at the rate of their claim size, regardless of dedup outcome. Integration test `rate_limit_runs_above_dedup` (`services/sadstore/tests/sad_builder_tests.rs:1022-1078`) submits a 2-event batch four times (8/8 budget consumed), then asserts the fifth submit gets a "Too many events" rejection from the pre-flight gate before reaching the dedup query. `submit_dedup_returns_current_divergence_signal` is unaffected — its 5-event total stays under the 8/day default.

---

## Low Priority

### ~~3. The `flush` docstring still names `CannotResumeDivergentChain` — a stale reference to a Round-6-removed error variant~~ — RESOLVED

**File:** `lib/kels/src/sad_builder.rs:680-685`

```rust
/// Structural errors that survive retry (e.g., a verifier-internal
/// invariant violation that fires identically on every attempt) are
/// bugs — file an issue rather than retrying indefinitely. The
/// round-6 parity rework removed the previous `CannotResumeDivergentChain`
/// deadlock by teaching `SelVerifier::resume` to accept divergent tokens.
```

Round 6 M1 removed `KelsError::CannotResumeDivergentChain` from `lib/kels/src/error.rs` and the FFI mapping, replaced by `SelVerifier::resume` accepting divergent tokens. The variant no longer exists in the codebase (`grep CannotResumeDivergentChain lib/` returns only this docstring and the audit documents).

The docstring's reference is now an archaeology trip for a future reader: "what was that error variant, where is it defined, why doesn't grep find it?" The mention is informational rather than load-bearing — the paragraph explains why retrying transient errors is the right strategy and uses the removed variant as historical context.

**Suggested fix:** Either delete the trailing sentence (the prior sentence stands alone) or rephrase as "Pre-Round-6 the verifier refused divergent tokens; the parity rework now accepts them and incrementally extends the matching branch." The historical context can stay if it's framed in past tense without naming a now-deleted symbol.

**Resolution (round-7 implementation):** Deleted the trailing sentence at `lib/kels/src/sad_builder.rs:680-685`; the prior "Structural errors that survive retry are bugs" sentence stands alone. Added `\bCannotResumeDivergentChain\b` to `.terminology-forbidden` under a new `# === KELS-126 round 7: Removed error variants ===` section so the lint catches future regressions. `make lint-terminology` passes — the remaining mentions live in `docs/claudit/*.md` (excluded from the lint by `:!:docs/claudit`) and in `.garden/build/*` snapshots (gitignored, not in `git ls-files`).

### ~~4. The unit-test `VecSadSource` mock's `since` semantics are **inclusive**, but the production `HttpSadSource` server-side semantics are **exclusive** — mock doesn't faithfully model production~~ — RESOLVED

**File:** `lib/kels/src/sad_builder.rs:1187-1212` (mock), `services/sadstore/src/repository.rs:374-410` (production)

The `VecSadSource` mock in `sad_builder.rs`'s test module:

```rust
let start_idx = match since {
    Some(s) => self.events.iter().position(|e| e.said == *s).unwrap_or(0),
    None => 0,
};
// `since` semantics in the real handler: events at version >=
// since's version. Since events here are unique per version, we
// start at `since`'s position (inclusive).
let end_idx = (start_idx + limit).min(self.events.len());
```

The comment claims production semantics are `version >= since`, and so the mock is inclusive of `since`. But `repository.rs:380-410` shows the actual server semantics:

```rust
if let Some((version, _)) = &since_position {
    query = query.gte("version", *version);
}
...
events.retain(|e| e.version > *version || (e.version == *version && e.said > *said));
```

The `gte` is a fetch-side widening that accommodates same-version forks; the post-fetch `retain` uses **strict** `>` on `(version, said)`. So `since=X` returns events strictly after X.

The mock's comment is wrong, and the mock itself differs from production: with multiple events on a chain and a unit test using `since=last_said`, the production server would return events *after* `last_said`, but the mock would return events *starting at* `last_said` (overlapping by one event).

The two existing unit tests that use `VecSadSource` (`repair_at_adversarial_extension_boundary*`, `:1278-1337`) build chains of 5–6 events and never paginate (the page size is 64, larger than any test chain). So `since` is always `None` and the inclusive-vs-exclusive distinction doesn't surface. The pagination branch in `walk_back_to_first_owner` (`:155-167`, the loop with `since = last_said`) is consequently unexercised by unit tests — only the integration test in `sad_builder_tests.rs` covers multi-page fetches, and that's via real HTTP not the mock.

If a future unit test exercises the pagination loop with `VecSadSource`, the events visible to the walk would double-count by one entry per page — silently, because `chain.insert` is idempotent on SAID. A bug that would surface on real HTTP could be masked by the mock's looser semantics.

**Suggested fix:** Either (a) make the mock match production by changing `start_idx` to `start_idx + 1` (exclusive of `since`) and updating the comment, or (b) keep the inclusive semantic but rename the mock to `InclusiveVecSadSource` and add a test-only `ExclusiveVecSadSource` that does match production. (a) is simpler. After the fix, add a unit test that paginates through `VecSadSource` to pin the boundary semantics.

**Resolution (round-7 implementation):** Took option (a). `VecSadSource::fetch_page` (`lib/kels/src/sad_builder.rs:1180-1216`) now uses `position(...).map(|i| i + 1)` to match production's strictly-exclusive `since` semantics, with the comment rewritten to reference `services/sadstore/src/repository.rs:374-410` directly. `VecSadSource` also gains a `fetch_tail` impl (M1 dependency) so the post-M1 trait surface stays satisfied. New unit test `vec_sad_source_pagination_exclusive_since` (`:1416-1469`) paginates a 6-event fixture in three pages of 2 events each, asserting strictly-disjoint pages with no overlap at boundaries — fails under the prior inclusive impl, passes under exclusive. The fix is defensive: `walk_back_to_first_owner` no longer uses `fetch_page` after M1, but `transfer_sad_events` / `forward_sad_events` still consume the trait, and the test pins the contract for any future caller.

---

## Positive Observations

- **The Round-6 M1-followup contract is reflected end-to-end in two parallel integration tests.** `flush_repair_heals_divergent_chain` (`services/sadstore/tests/sad_builder_tests.rs:694-858`) and `flush_repair_heals_adversarially_extended_chain` (`:868-1019`) each cover one of the two healing cases (Case A divergent, Case B adversary-extended). Both assert the post-flush server state is `divergent: false` AND that the new effective SAID is the freshly-committed Rpr — the boundary contract is pinned at the wire-format level, not just the in-memory token. The deliberate bypass of `SadEventBuilder` for fixture construction (`:622-637`, `:734-737`, `:909-921`) is the right call: the builder refuses divergent and adversary-extended state by design, so a healing test must stage the failure at the HTTP layer.

- **The trust-model split between `sad_store` (boundary oracle) and the server-fetched chain (segment for traversal) is named in three places and survives refactoring.** The `walk_back_to_first_owner` docstring (`lib/kels/src/sad_builder.rs:130-150`) calls out the split, the `repair` docstring (`:559-567`) restates it as "**Authoritative source split**", and the offline-mode error message at `:609-615` reproduces it inline ("boundary decision still uses sad_store"). A reader landing in any one of those places sees the same explanation. This is an example of comment discipline matching architecture: the trust split is the load-bearing claim, and the codebase invests in keeping that claim visible.

- **The `SadBranchTip` unification of runtime and serialized state mirrors the right thing.** The KEL split between `BranchState` (runtime) and `BranchTip` (serialized) exists because KEL's runtime carries derivable crypto values; SEL has nothing derivable, so one struct serves both roles. The docstring at `event.rs:374-382` names this rationale precisely — "SEL's per-branch state has no derivable-at-resume crypto" — saving a future reader from re-deriving the asymmetry. The `SelVerifier` runtime HashMap (`verification.rs:71-72`) and the `SelVerification.branches` slice (`event.rs:417-426`) now share the same value type, and `resume` (`verification.rs:484-512`) is a straightforward HashMap rebuild rather than a translation step.

- **`first_divergent_version` is a parameterized `sqlx::query_scalar` with the binding shape called out in the docstring.** `services/sadstore/src/repository.rs:282-297` uses `sqlx::query_scalar` with `$1` binding to `prefix.to_string()`. No string interpolation on user input; no injection surface. The docstring at `:269-281` names why `ColumnQuery` couldn't express the shape (no `MIN(grouped_column) HAVING COUNT(*) > 1` composition) and points at the dedup-path call site. The Cargo.toml comment at `services/sadstore/Cargo.toml:60-66` explains the promotion of `sqlx` from transitive to direct dep. Layer-by-layer documentation cost paid.

- **The `incept` vs `incept_deterministic` regression test is one of the strongest test designs in the change set.** `incept_prefix_diverges_from_compute_sad_event_prefix` (`lib/kels/src/sad_builder.rs:956-976`) asserts both halves of the contract: `incept` (governance on v0) → prefix does NOT match `compute_sad_event_prefix`, AND `incept_deterministic` (governance on v1 Est) → prefix DOES match. Both assertions live in one test, so a future change that silently aligns the two halves can't pass by accident. The companion guard tests (`requested_prefix_mismatch_rejected_at_absorb`, `:1115-1151`) close the loop on the verifier's role in surfacing prefix mismatches.

- **The `SelVerifier::resume` rehydration test exercises the per-branch-state-survives-resume contract directly.** `resume_then_extend_preserves_other_branch` (`lib/kels/src/types/sad/verification.rs:1843-1891`) builds a divergent chain at v1, resumes the verifier from that token, extends only branch A with a v2 Upd, finishes again, and asserts both branches are still visible. The unextended branch surviving is the load-bearing invariant for the M1 in-builder repair flow — without per-branch survival, the post-Rpr server response would be the only correct view. Pinning the contract at the verifier level (in addition to the builder-level `flush_repair_heals_*` tests) means the invariant doesn't depend on any single layer's correctness.

- **The walk-back functions are pure free fns with explicit deps — easy to test in isolation.** `walk_back_to_version` (`lib/kels/src/sad_builder.rs:83-118`) takes `&Arc<dyn SadStore>` and `&SadEvent`; `walk_back_to_first_owner` (`:130-208`) adds `&dyn PagedSadSource` and `prefix: &cesr::Digest256`. No `&self` on `SadEventBuilder`, no shared state. The unit tests at `:1278-1337` exercise both functions directly with mocked sources. This is a standard refactoring win — extracting state-mutating logic into pure helpers — and pays off here by letting unit tests cover the multi-step Case B walk without standing up a server.

---

## Resolutions

### M1 — option (a): server-side tail-fetch endpoint

The walk needs at most `MINIMUM_PAGE_SIZE` events from the chain tail; fetching the whole chain forward from v0 to find them is `O(N)` where `O(64)` is correct. Add a server endpoint that returns the last N events ordered by `(version DESC, said DESC)`. The walk issues one such call with `limit = MINIMUM_PAGE_SIZE`, walks back in memory, never paginates.

**Server change.** Add `fetch_sad_events_tail(prefix, limit) -> SadEventPage` (request body `SadEventTailPageRequest { prefix, limit }`, response shape mirrors `SadEventPage`). Implementation: same query as `get_stored_in` but with `Order::Desc` on `version` and `said`, then reverse the result before returning so the page reads `(version ASC, said ASC)` for caller convenience. Bound `limit` to `MINIMUM_PAGE_SIZE` server-side.

**Client change.** Add `SadStoreClient::fetch_sad_events_tail` and a corresponding `PagedSadSource` method (`fetch_tail` or similar). `walk_back_to_first_owner` switches from the forward-paginate loop to a single `fetch_tail(prefix, MINIMUM_PAGE_SIZE)` call. The in-memory walk and bound-check logic is unchanged.

**Tests.** Update the existing N=4 integration test to validate against a chain of e.g. T=200 events (built by exercising `evaluate` periodically to advance the seal) — the test fails the new performance contract today by paginating, passes after the endpoint switch. Add a unit test exercising the new tail endpoint via a fake `PagedSadSource`. The existing N=1/N=4 tests work unchanged.

### M2 — option (a): rate limit above the dedup branch with check-only mode

Move the per-prefix rate-limit check before the `new_events.is_empty()` short-circuit so duplicate-submit campaigns consume request budget regardless of whether anything applies. The dedup path uses `accrue=0` (no new events committed) but still gates on the per-prefix request rate.

**Change.** Extend `check_prefix_rate_limit` with a `check_only: bool` (or accept `accrue: u32` where `0` means "check only, don't increment"). Move the existing call at `handlers.rs:1327-1335` to above `:1293` (before the dedup query). The `is_empty()` branch's `first_divergent_version` query then runs only if the rate limit passes.

**Tests.** Add a unit/integration test that submits the same batch repeatedly past the per-prefix limit and asserts the dedup-path requests get `429` instead of doing the divergence query. The existing dedup test (`submit_dedup_returns_current_divergence_signal`) shouldn't trip the rate limit at its current request volume — verify or adjust.

### L3 — terminology lint + docstring trim

Add `\bCannotResumeDivergentChain\b` to `.terminology-forbidden` under a new `# === KELS-126 round 7: Removed error variants ===` section so the lint catches future regressions. Then delete the trailing "The round-6 parity rework removed the previous `CannotResumeDivergentChain` deadlock by teaching `SelVerifier::resume` to accept divergent tokens." sentence in the `flush` docstring at `lib/kels/src/sad_builder.rs:680-685`. The prior sentence ("Structural errors that survive retry are bugs") stands alone; the historical context isn't load-bearing now that the variant is gone.

### L4 — fix the mock to match production semantics, add pagination test

Change `VecSadSource::fetch_page` (`lib/kels/src/sad_builder.rs:1187-1212`) so `since` is exclusive — `start_idx + 1` after the find, with the comment rewritten to match: "Production semantics: `since`-cursor is strictly exclusive (server returns events at `(version, said) > since`'s position)." After the fix, add a unit test that paginates `VecSadSource` (chain longer than `limit`) to pin the boundary semantics — test should fail under the current inclusive impl and pass under exclusive.

Note that L4 may become moot if the M1 endpoint switch removes the pagination loop from `walk_back_to_first_owner` entirely. If so, the mock fix is still worth doing for any future caller of `PagedSadSource::fetch_page`, and the pagination test pins the trait contract at the unit level. Land L4 after M1 lands so the pagination test exercises whatever remaining call sites still use forward-paginate.
