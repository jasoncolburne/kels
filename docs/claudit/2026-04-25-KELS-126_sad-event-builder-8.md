# Branch Audit: KELS-126_sad-event-builder (Round 8) — 2026-04-25

Eighth-pass audit of the SadEventBuilder branch after `/clear`. Read every changed source file plus the prior seven round documents to avoid re-finding resolved issues. Cumulative across prior rounds: 47 resolved (10 R1 + 7 R2 + 4 R3 + 4 R4 + 4 R5 + 5 R6 + M1-followup + 4 R7 + 4 R7 final-resolutions). This round adds 4 new low-priority findings, all open.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 0        |
| Low      | 0    | 4        |

---

## Low Priority

### ~~1. Tail endpoint docstring claims `MINIMUM_PAGE_SIZE` server-side cap; actual cap is `page_size()`~~ — RESOLVED

**File:** `lib/kels/src/types/sad/request.rs:38-50`, `services/sadstore/src/handlers.rs:1624-1656`, `services/sadstore/src/repository.rs:301-323`

~~`SadEventTailRequest`'s docstring (`request.rs:43-45`) says:~~

```
/// in a single round-trip regardless of chain length — bounded by
/// `MINIMUM_PAGE_SIZE` server-side because that's exactly what the
/// adversary-extension walk-back can possibly need.
```

But the handler caps at `kels_core::page_size()`, not `MINIMUM_PAGE_SIZE`:

```rust
let page_size = kels_core::page_size();
let limit = request.limit.unwrap_or(page_size).clamp(1, page_size) as u64;
```

`page_size()` is `LazyLock::new(|| env_usize("KELS_PAGE_SIZE", DEFAULT_PAGE_SIZE).max(MINIMUM_PAGE_SIZE))` (`lib/kels/src/lib.rs:165-166`) — so it's `MINIMUM_PAGE_SIZE` in default deployments but operators can set `KELS_PAGE_SIZE` higher. In a deployment with `KELS_PAGE_SIZE=256` the actual cap diverges from the doc by 4×.

The handler's own docstring (`handlers.rs:1618-1623`) gets it right ("capped at `kels_core::page_size()` server-side"). The `repository.rs:309` docstring also says "MINIMUM_PAGE_SIZE-bounded fetch covers everything" — same drift.

The walk on the client side passes `MINIMUM_PAGE_SIZE = 64` explicitly (`sad_builder.rs:154`), so the production walk never benefits from a higher server cap. The doc inaccuracy is only a reader-trust concern: a future contributor reading `request.rs` may rely on the claimed bound and be surprised when an operator-tuned deployment hands back a longer tail.

**Suggested fix:** Either (a) tighten the server cap to `MINIMUM_PAGE_SIZE` (matches the docstring's claim and matches what the only production caller asks for), or (b) update the docstrings in `request.rs` and `repository.rs` to say "bounded by `page_size()` (default `MINIMUM_PAGE_SIZE = 64`)". (a) is the more conservative fix — the tail endpoint is purpose-built for the repair walk-back, which doesn't need more than 64 events; capping at the constant prevents accidental amplification if an attacker probes the endpoint with `limit: 100000`. (b) is the lighter touch.

**Resolution:** Took option (a). `services/sadstore/src/handlers.rs:1624-1657` — `get_sad_events_tail` now uses `let max_limit = kels_core::MINIMUM_PAGE_SIZE; let limit = request.limit.unwrap_or(max_limit).clamp(1, max_limit) as u64;`. Operator-tunable `KELS_PAGE_SIZE` no longer affects this endpoint's response size. Handler docstring updated to name the constant cap and the rationale ("Capping at the constant (rather than the operator-tunable `page_size()`) keeps an attacker probing this endpoint from amplifying response size when `KELS_PAGE_SIZE` is set higher than the default."). `services/sadstore/src/repository.rs:301-326` docstring extended to note that the handler enforces the `MINIMUM_PAGE_SIZE` cap before reaching the repository — the `limit: u64` signature accepts arbitrary values only because the repository doesn't reference the constant directly.

### ~~2. `SadStoreClient::as_sad_source()` builds a fresh `reqwest::Client` on every call~~ — RESOLVED

**File:** `lib/kels/src/client/sadstore.rs:40-43`

```rust
pub fn as_sad_source(&self) -> Result<crate::HttpSadSource, KelsError> {
    crate::HttpSadSource::new(&self.base_url)
}
```

`HttpSadSource::new` (`lib/kels/src/types/sad/sync.rs:82-92`) calls `reqwest::Client::builder().build()`, which constructs a new HTTP client with its own connection pool. `SadStoreClient` already holds a `reqwest::Client` (`sadstore.rs:21`). Each `as_sad_source()` call discards that pooled state and starts fresh.

The repair flow calls `as_sad_source()` once per `repair()` (`sad_builder.rs:601`), so the cost is one extra TLS handshake per repair. Not a hot path — but `as_sad_sink()` (`sadstore.rs:46-48`) has the same shape and is used by gossip/sync flows that could be hotter.

The fix is structural: `HttpSadSource` could borrow `&reqwest::Client` (or hold an `Arc<reqwest::Client>`) instead of owning one, and `SadStoreClient::as_sad_source` would hand out a view into its own client. The signature change ripples to `HttpSadSink` and any other callers that construct `HttpSadSource` standalone (e.g., `services/sadstore/tests/sad_builder_tests.rs` may construct one directly).

**Suggested fix:** Defer until profiling flags it. The repair path is rare; gossip flows that use `HttpSadSink` more aggressively would be the place to surface this if it bites. As-is, document the trade-off in `as_sad_source`'s docstring so a reader optimizing for connection reuse knows to look here.

**Resolution:** Documented the trade-off without changing behavior. `lib/kels/src/client/sadstore.rs:40-58` — `as_sad_source` and `as_sad_sink` docstrings now name the fresh-Client construction explicitly and point a future caller at the structural fix (sharing the underlying `reqwest::Client`) for hot-loop callers. No code change; the repair path remains the only one-off caller. If a profiler later flags gossip/sync flows, the fix shape is signposted in the docstrings.

### ~~3. `SelVerifier::resume` returns `Result<Self, KelsError>` but has no fallible path~~ — RESOLVED

**File:** `lib/kels/src/types/sad/verification.rs:484-512`

```rust
pub fn resume(
    verification: &super::event::SelVerification,
    checker: Arc<dyn PolicyChecker + Send + Sync>,
) -> Result<Self, KelsError> {
    let mut branches: HashMap<...> = HashMap::new();
    for branch in verification.branches() {
        branches.insert(branch.tip.said, branch.clone());
    }
    let prefix = *verification.prefix();
    let topic = verification.topic().to_string();
    Ok(Self { ... })
}
```

No `?` operators, no early returns, no validation that produces an error. The function unconditionally returns `Ok(_)`.

The signature was inherited from `KeyEventVerifier::resume` (`lib/kels/src/types/kel/verification.rs:360-394`) for parity — but KEL's resume actually fails: `branch_state_from_tip(bt, since_revealing_count)?` (`:368`) can fail because it derives crypto (`KeyEventVerifier` recovers `tracked_signing_key`/`tracked_recovery_key` etc. from the branch tip's establishment event). SEL's `SadBranchTip` has nothing derivable — the docstring at `event.rs:374-382` calls this out explicitly: "SEL's per-branch state has no derivable-at-resume crypto."

The `Result` wrapper on `SelVerifier::resume` is therefore vestigial. Callers `?`-propagate a result that can never be `Err`. Cosmetic, but the dead path makes a reader hunt for a failure mode that doesn't exist.

**Suggested fix:** Either (a) change the signature to `pub fn resume(...) -> Self` and have callers drop the `?` (small ripple — `sad_builder.rs:846` and the test sites), or (b) keep the `Result` for forward-compat in case future structural validation is added (a future change might verify that `branches()` is non-empty, or that all branches share a prefix — both currently invariants of `SelVerification`'s constructor) and add a one-line "kept fallible for forward compat with future validation" comment. (b) is the lighter touch and matches the existing parity argument.

**Resolution:** Took option (b). `lib/kels/src/types/sad/verification.rs:471-490` — added a paragraph to `SelVerifier::resume`'s docstring naming both halves of the rationale: parity with `KeyEventVerifier::resume` (which derives crypto and can fail) and forward-compat with future structural validation (non-empty `branches`, shared-prefix invariants — currently enforced by `SelVerification`'s constructor). No signature change; readers landing here see why the `Result` exists and what would populate the `Err` arm.

### ~~4. Two `VecSadSource` test mocks with the same name and divergent capabilities~~ — RESOLVED

**File:** `lib/kels/src/sad_builder.rs:1173-1215`, `lib/kels/src/types/sad/sync.rs:450-478`

Both files define a private `struct VecSadSource` under `#[cfg(test)]`. They look like the same mock by name but implement different surfaces:

- `sad_builder.rs`'s mock implements **both** `fetch_page` (with strictly-exclusive `since` per the R7 L4 fix) and `fetch_tail` (returns the suffix of length `limit`).
- `sync.rs`'s mock implements **only** `fetch_page` (with similar exclusive semantics) and inherits the trait's default `fetch_tail` (which returns `KelsError::OfflineMode("PagedSadSource::fetch_tail not implemented...")`).

A reader scanning for "the test mock for `PagedSadSource`" sees two definitions and has to compare them line-by-line to know which capabilities each supports. The names don't telegraph which one to use for which test purpose. If a future test in `sync.rs` wants to exercise `fetch_tail` (e.g., tail-fetch divergence detection), it would either have to add the `fetch_tail` impl locally or pull the more-capable mock from `sad_builder.rs` — both module-private, so the second option requires a `pub(crate)` visibility bump.

The R7 L4 fix mostly addresses the `fetch_page` semantics divergence between the mock and production, but it didn't unify the two mocks. The drift between them is now smaller (both use exclusive `since`) but still present (only one implements `fetch_tail`).

**Suggested fix:** Defer until a test outside `sad_builder.rs` needs `fetch_tail`. At that point, lift the more-capable mock to a shared `lib/kels/src/types/sad/test_support.rs` (or similar) under `#[cfg(test)] pub(crate)`, delete the duplicate in `sync.rs`, and have both call sites import from the shared location. Pre-emptive lifting now would be churn for an unproven need; the smell is real but not biting.

**Resolution:** Renamed in place (the cheapest of the three options the deferral discussion sketched, picked over deferral itself). `lib/kels/src/sad_builder.rs:1170-1219` — `VecSadSource` becomes `RepairTestSadSource`, with a docstring note pointing at the sibling mock in `sync.rs`. `lib/kels/src/types/sad/sync.rs:450-481` — `VecSadSource` becomes `PagedVecSadSource`, with a docstring note that it doesn't implement `fetch_tail` and pointing at `RepairTestSadSource` for tests that need it. All call sites within each test module updated; the cross-references make the capability split explicit at the type level. If a future test outside `sad_builder.rs` needs the tail-capable mock, the lift-to-shared-module path remains available.

---

## Positive Observations

- **The Round-7 tail endpoint and the new `PagedSadSource::fetch_tail` trait method are cleanly factored across the layer boundary.** `services/sadstore/src/repository.rs:309-323` (`get_stored_tail`) does the SQL: `(version DESC, said DESC) LIMIT N`, then `events.reverse()` so the caller sees `(version ASC, said ASC)`. `services/sadstore/src/handlers.rs:1624-1656` (`get_sad_events_tail`) wraps it with the request/response shape and clamps the limit. `lib/kels/src/types/sad/sync.rs:44-52` defines the trait method with a default `OfflineMode` implementation so legacy sources that don't override it surface a clear error rather than silently degrading. `HttpSadSource::fetch_tail` (`:121-142`) is a 22-line implementation that mirrors `fetch_page` exactly. Each layer's responsibility is named in its docstring and the boundaries don't leak.

- **The `SelVerification::branches()` accessor is the load-bearing addition that lets `SadEventBuilder::repair` Case A exist at all.** Pre-Round-6 the verification token only exposed a tie-break winner via `current_event()`. The R6 rework added `pub fn branches(&self) -> &[SadBranchTip]` (`event.rs:469-471`) so callers needing the per-branch picture can iterate. `SadEventBuilder::owner_branch_tip` (`sad_builder.rs:818-827`) consumes this — picks `branches().first()` (the lex-smallest SAID per `branches.sort_by_key(|b| b.tip.said)` in `verifier.finish()`) as the deterministic owner-branch convention. The `branches.first()` choice is the same convention as KEL's `BranchState::winning_branch()` deterministic walk, and the docstring at `:809-818` names this parity. No magic, no undocumented ordering — a reader can reproduce the convention from the code.

- **The Round-7 rate-limit pre-flight gate has the right semantics for an unauthenticated entry point.** `check_prefix_rate_limit` (`handlers.rs:162-186`) gains an `accrue: bool` parameter; `submit_sad_events` (`handlers.rs:1225-1232`) calls it with `accrue=true` BEFORE the transaction setup, charging `events.len()` to the per-prefix budget regardless of whether the request commits. The comment at `:1219-1224` names the trade-off ("a failed request over-charges relative to its commits, which is the conservative shape we want for an unauthenticated entry point") and the integration test `rate_limit_runs_above_dedup` (`services/sadstore/tests/sad_builder_tests.rs:1035-1086`) pins the contract: 4 dedup submits exhaust the 8-event/day budget, the 5th gets 429 from the pre-flight gate before the dedup query or `first_divergent_version` MIN aggregate runs. The fix closes the duplicate-submit DB amplifier the R7 M2 audit identified.

- **The `was_repair` post-submit hydration is correctly ordered relative to the local cache write.** `SadEventBuilder::flush` (`sad_builder.rs:704-768`) writes pending events to the local `sad_store` BEFORE checking `was_repair`. This means: (1) on a clean linear-extension flush, the cache contains the new events AND `absorb_pending` rolls them into `sad_verification` via incremental `verify_page` — fast path, no extra GET. (2) On a repair flush, the cache contains the new Rpr (and any prior owner-authored events from earlier flushes), and `verify_sad_events` does a fresh server fetch to absorb the post-truncation chain — the local cache is consistent with the server's view because adversary's events were never owner-authored, never in the cache. The two paths don't share state in a way that could leak inconsistency.

- **`SadEventBuilder::repair`'s authoritative-source split survives across all three implementation paths.** Case A (`sad_builder.rs:570-579`): walks back via `walk_back_to_version`, which loads each predecessor from `sad_store` (the boundary oracle). No server fetch — owner's branch is fully cached locally per design. Case B (`:589-608`): one `fetch_tail` server call hydrates the chain segment into an in-memory `HashMap`, then `walk_back_to_first_owner` probes `sad_store` for ownership at each step — boundary decision still uses `sad_store`, server slice is only the chain segment for traversal. Case C (`:585-588`): probes `sad_store` for the cached tip; hit means owner-authored, return `NothingToRepair`. All three paths name the trust split in their docstrings (`:543-551`) and the offline-mode error message at `:594-599` reproduces it inline. A reader landing at any of these places sees the same explanation.

- **The `requested_prefix` latching from `with_prefix` to `absorb_pending` closes the silent-state-drift footgun named in R4 L2.** `with_prefix(... &sel_prefix)` (`sad_builder.rs:231-249`) latches `sel_prefix` as `requested_prefix` even when hydration short-circuits via `KelsError::NotFound` (the chain may not exist yet — caller is about to incept). `absorb_pending` (`:830-854`) uses `self.requested_prefix.as_ref()` to seed `SelVerifier::new(prefix, ...)`, which the verifier then enforces via `verify_event`'s prefix check at `:118-125`. A caller who asks `with_prefix(X)` and then accidentally `incept_deterministic`s a chain at prefix Y gets a `KelsError::VerificationFailed("doesn't match SEL prefix")` at flush time — pinned by `requested_prefix_mismatch_rejected_at_absorb` (`:1097-1133`). The contract is end-to-end and tested.

- **The Round-7 dedup-path divergence-signal symmetry is reflected in three places: server query, response shape, and CLI surfacing.** `SadEventRepository::first_divergent_version` (`services/sadstore/src/repository.rs:282-299`) returns the earliest divergent version via parameterized SQL (no injection surface). `submit_sad_events`'s dedup branch (`handlers.rs:1300-1331`) populates `SubmitSadEventsResponse.diverged_at` from this query before commit, so a duplicate-submit campaign sees the chain's current divergence state. `cmd_sel_submit` (`clients/cli/src/commands/sel.rs:23-43`) branches on `applied` first (green if true, yellow if false) and unconditionally surfaces the divergence warning after — both `applied: true` and dedup paths print the divergence signal. The full chain from server query to user-visible warning is wired end-to-end.
