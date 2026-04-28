# Branch Audit: KELS-126_sad-event-builder (Round 9) — 2026-04-25

Ninth-pass audit of the SadEventBuilder branch after `/clear`. Read every changed source file plus the prior eight round documents to avoid re-finding resolved issues. Cumulative across prior rounds: 54 resolved (10 R1 + 7 R2 + 4 R3 + 4 R4 + 4 R5 + 5 R6 + M1-followup + 4 R7 + 4 R7 final-resolutions + 4 R8 + 3 R9), 0 open.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 1        |
| Low      | 0    | 2        |

---

## Medium Priority

### ~~1. `walk_back_to_first_owner` trusts server-fetched events without SAID verification — adversary running the SAD store can steer Case-B repair to truncate owner's authoritative tail~~ — RESOLVED

**File:** `lib/kels/src/sad_builder.rs:142-187` (walk), `lib/kels/src/types/sad/sync.rs:121-142` (`HttpSadSource::fetch_tail`), `services/sadstore/src/handlers.rs:1337-1438` (server `is_repair`)

The Case-B walk loads the chain segment via `sad_source.fetch_tail(prefix, MINIMUM_PAGE_SIZE)` and inserts each returned event into a SAID-keyed `HashMap` with no integrity check:

```rust
let tail = sad_source
    .fetch_tail(prefix, crate::MINIMUM_PAGE_SIZE)
    .await?;
let mut chain: HashMap<cesr::Digest256, SadEvent> = HashMap::new();
for event in &tail {
    chain.insert(event.said, event.clone());  // no event.verify_said()?
}
```

`HttpSadSource::fetch_tail` returns whatever the server sends — `resp.json::<SadEventPage>()` parses but doesn't validate (`sync.rs:131-135`). The walk then traverses `previous` links blindly:

```rust
for _ in 0..crate::MINIMUM_PAGE_SIZE {
    let prev_said = current.previous.ok_or_else(...)?;
    if let Some(value) = sad_store.load(&prev_said).await? {
        return Ok(serde_json::from_value(value)?);   // boundary
    }
    let next = chain.get(&prev_said).cloned().ok_or_else(...)?;
    current = next;  // current.previous is server-controlled
}
```

The walk's docstring at `:122-133` claims "Fetched events are SAID-integrity-protected (every server reply must match its SAID by structure or we'd have rejected it earlier), so using them for `previous`-link traversal is sound." **No such rejection happens for tail fetches.** The only place `event.verify_said()` runs on a fetched event is `SelVerifier::verify_event` (`verification.rs:116`), and the tail-fetch path bypasses the verifier entirely.

**Concrete attack.** Owner-authored chain history: `v0 (Icp), v1 (Est), v2 (Upd), v3 (Upd)` — all in owner's `sad_store`. Adversary holding `write_policy` extends with `v4..vT`. Owner runs repair. The walk should:

1. Probe `sad_store(v(T-1).said)` → miss (adversary's).
2. Look up `v(T-1)` in `chain` → find it. Set `current = v(T-1)`.
3. Probe `sad_store(v(T-2).said)` → miss.
4. ... walk down to `v3` (owner's tip), probe → hit, return `v3` as boundary.
5. Build Rpr at `v4`, `previous = v3.said`.
6. Server truncates `v4..vT` (adversary's events) and inserts the Rpr — owner's `v0..v3` preserved.

Adversary controlling the SAD store inserts a forged event `{said: v(T-1).said, content: lies, previous: v0.said}` into the tail response. SAID-keyed lookup returns this forgery. `current.previous = v0.said` is server-controlled. Walk proceeds:

1. Probe `sad_store(v0.said)` → **hit**. Return `v0` as boundary.
2. Build Rpr at `v1`, `previous = v0.said`.
3. Server: `truncate_and_replace` runs at `from_version = 1`. **Establishment seal fires** at `handlers.rs:1426-1438` (`from_version <= establishment_version`) — repair rejected with 400.

So in the simplest "redirect to v0" case the establishment seal saves the chain. But the attacker can pick a more dangerous boundary:

- Set `current.previous = v2.said` (an owner-authored Upd past establishment). Walk hits `sad_store(v2)` → boundary = v2. Rpr at v3. Server: `from_version = 3 > establishment_version (1)` and `> last_governance_version (None)` — passes both seals. Truncate archives `v3, v4..vT` and inserts Rpr@v3. **Owner's authoritative `v3` is now archived as if it were a fork event.**

For a longer authoritative tail (e.g., owner authored `v0..v200` over many governance windows, adversary added 5 Upd at v201..v205), the attacker can pick any boundary `vK` for `K >= last_governance_version + 1`, archiving `v(K)..v200` of owner's real history. The seal floor only protects up to the most recent governance evaluation; everything above it is fair game.

The attack requires SAID-collision-free forgery only of the SAID *field* — the attacker writes `{said: target_said, content: <lies>}` where `target_said` is any event SAID present in the legitimate chain. No Blake3 collision needed because we never check that `said` matches `compute_said(content_with_blanked_said)`. With a one-line `event.verify_said()?` per fetched event, the attack is foiled — the forged SAID won't match the lied-about content's hash.

**Why the existing trust model isn't enough.** The Round-6 design split (`sad_store` is the boundary oracle, server is the chain segment) was correct in spirit — the boundary itself is owner-authored (because it must be in `sad_store`). But the attack doesn't cross that boundary; it manipulates *which* owner-authored event the walk lands on. Since the seal floor is the only constraint on what the chosen boundary can be, the attacker has a wide playing field above the most recent Evl/Rpr.

`SadEvent::verify_said()` exists, is fast (one Blake3 round on the structurally-blanked form), and catches the attack at the natural place. The verifier path through `transfer_sad_events` already runs it for every fetched event; the tail-fetch repair walk is the asymmetry.

**Suggested fix:** In `walk_back_to_first_owner`, immediately after `let tail = sad_source.fetch_tail(...)`, validate every event:

```rust
for event in &tail {
    event.verify_said()?;  // SAID integrity per-event
    if event.prefix != *prefix {
        return Err(KelsError::InvalidKel(format!(
            "fetched tail event {} has prefix {} but expected {}",
            event.said, event.prefix, prefix
        )));
    }
}
```

The prefix check is belt-and-suspenders for the same reason — an attacker could otherwise return events from a different chain that happen to have a matching `said` field. After SAID verification both attacks fail.

Add a regression test that constructs a `RepairTestSadSource` returning a forged event with mismatched `said`/content, calls `walk_back_to_first_owner`, and asserts the walk errors rather than returning a misled boundary. Pre-fix the test would silently succeed at the attacker-chosen boundary; post-fix it errors at SAID verification.

The Round-7 fix that added `fetch_tail` (`sync.rs:121-142`) inherited the no-verification shape from `fetch_page`, which is acceptable for `fetch_page` because every caller routes through `transfer_sad_events`'s verifier. `fetch_tail`'s only consumer (`walk_back_to_first_owner`) bypasses that verifier — so the responsibility falls to the consumer, and the consumer doesn't currently take it.

Note that the docstring at `sync.rs:35-43` for `PagedSadSource::fetch_tail` doesn't mention SAID verification as a caller responsibility either. Once the walk is fixed, also tighten the trait method's docstring to call out "callers MUST verify event SAIDs before trusting `previous` linkage" so a future caller doesn't make the same omission.

**Resolution (round-9 implementation):** Took the structural fix per the §Resolutions section, not just the local patch. The audit's M1 framing assumed adversary-served events would reach a verifier corpus and need per-event integrity checks. The owner-local rework closes the upstream attack surface entirely: `with_prefix` now hydrates `sad_verification` from `sad_store` only (KEL parity with `KeyEventBuilder::with_dependencies`), so the cached tip is always one owner-authored, owner-verified event. `repair` (`lib/kels/src/sad_builder.rs:540-690`) becomes an explicit user-initiated action that consults the server on-demand AND verifies its response: (a) gates on `sad_verification.policy_satisfied()` to catch local tampering, (b) fetches `effective_said` and short-circuits with `NothingToRepair` on tip-equal, (c) fetches the tail and runs `SelVerifier::verify_page` over the entire chain (per-event `verify_said + prefix` check + chain-level integrity + policy), (d) gates on the fetched chain's `policy_satisfied` to catch server-side noise, (e) walks back via the verified in-memory chain map probing `sad_store` for the owner-authored boundary. New `KelsError::ChainHasUnverifiedEvents` (`lib/kels/src/error.rs:161-164`) variant for both gates. Also added `SadEventKind::sort_priority` (`lib/kels/src/types/sad/event.rs:88-112`) — `Icp(0), Est(1), Upd(2), Evl(3), Rpr(4)` — wired into server queries (`get_stored_in`, `get_stored_tail`, `truncate_and_replace` archive page in `services/sadstore/src/repository.rs`) and `SelVerification::winning_branch` (`lib/kels/src/types/sad/event.rs:471-492`) so cross-node convergence is canonical regardless of arrival order. Owner-local infrastructure (parallel to KEL): `SadStore::store_sel_event` + `SadStore::load_sel_events` (required trait methods on `lib/kels/src/store/sad.rs`, ripple through `InMemorySadStore`, `FileSadStore`, and `services/sadstore/src/expansion.rs::ObjectStoreSadAdapter` which errors), `SelPageLoader` trait + `SadStorePageLoader` adapter + `sel_completed_verification` (`lib/kels/src/types/sad/sync.rs:55-180`), `KelStorePageLoader` rename (was `StorePageLoader`, now lives in the renamed slot for parity). Tests pinned: `with_prefix_derives_owner_tip_from_local_store_only`, `with_prefix_no_store_returns_empty_builder`, `forged_said_in_fetched_tail_rejected_by_verifier`, `repair_refuses_when_owner_policy_unsatisfied`, `repair_without_sad_store_errors`, `repair_at_adversarial_extension_boundary*` (rewritten for the new walk-back signature taking a pre-verified chain map). Full-stack tests `flush_repair_heals_divergent_chain` and `flush_repair_heals_adversarially_extended_chain` (`services/sadstore/tests/sad_builder_tests.rs`) updated to assert owner-local hydration semantics — `hydrated.branches().len() == 1`, `current_event == owner_tip`, `diverged_at_version == None` (server divergence detected on-demand by repair, not stored in the token). Regression script extended (`clients/test/scripts/test-sadstore.sh`) with Scenarios 8 (silent extension + repair) and 9 (clean state). The audit's L2 (pending-empty guard) became structurally impossible under owner-local — dropped without a guard. The audit's L3 (rehydrate cost) was resolved by switching the `flush()` `was_repair` branch to re-hydrate from the local store via `sel_completed_verification` (no server round-trip) — comment updated accordingly. `make` clean (fmt + clippy + 17 test groups + build, including 9 sadstore integration tests against testcontainers).

---

## Low Priority

### ~~2. `SadEventBuilder::repair` doesn't reject non-empty `pending_events` — staging `update` then `repair` produces a server-side surprise divergence at the Rpr's version~~ — RESOLVED

**File:** `lib/kels/src/sad_builder.rs:552-609`

`repair` checks `require_established()` and validates `sad_verification.is_some()`, but never inspects `pending_events`. On a linear adversary-extended chain the user-error sequence "stage an Upd, then realize the chain looks wrong and call repair" is reachable:

1. Hydrated chain: server has `v0..vT` where `v0..vK` are owner's, `v(K+1)..vT` are adversary's. `sad_verification.diverged_at_version() == None` (linear). `current_event = vT`.
2. User calls `update(content)`: passes `require_established()` ✓ and `require_non_divergent()` ✓ (linear). Builder stages `Upd_v(T+1)` with `previous = vT.said`. Pending = `[Upd_v(T+1)]`.
3. User then calls `repair(content)`: passes `require_established()`. Diverged version is None → Case-A skipped. `cached_tip = verification.current_event() = vT`. `sad_store.load(vT.said) = None` (adversary-authored) → Case B. Walks back, finds boundary = `vK`. Builds `Rpr_v(K+1)` with `previous = vK.said`. Pending = `[Upd_v(T+1), Rpr_v(K+1)]`.
4. `flush()` submits `[Upd_v(T+1), Rpr_v(K+1)]`. Server detects `is_repair = true` (Rpr present). `truncate_and_replace` (`repository.rs:154-176`) processes events in order:
   - Both events are non-existing → `from_version = events[0].version = T+1`.
   - Archive everything `>= T+1` → no-op (chain ends at `T`).
   - Insert `Upd_v(T+1)` (no version conflict, extends adversary's tail). Insert `Rpr_v(K+1)` — collides with existing `v(K+1)` (adversary's), creating a same-version pair. Server commits. Chain is now divergent at `v(K+1)`.
5. Post-truncation verification re-fetches, sees the new divergence. The `policy_satisfied` check still passes (assuming Rpr's governance check is OK), so the repair "succeeds" structurally. But the chain is now divergent — and the repair was supposed to *resolve* divergence, not create it.

The flush's was_repair branch then runs `verify_sad_events`, which sees the divergent chain. Builder's local token reports `diverged_at_version() == Some(K+1)`. Owner is stuck with a divergent chain that they themselves caused via "update + repair."

Two possible guards:

- **(a)** `repair` errors when `pending_events` is non-empty: `if !self.pending_events.is_empty() { return Err(KelsError::InvalidKel("repair must be called on an empty pending state".into())); }`. Covers the symptom directly.
- **(b)** `repair` errors when `pending_events` contains non-Rpr events. Permits staging multiple Rprs in one batch (currently nothing produces this, but the door is open).

Option (a) is the simpler contract and matches the implicit assumption — the docstring at `sad_builder.rs:506-509` describes repair as a recovery operation, not an extension that cohabits with normal staging. The Round-4 model gates `update`/`evaluate` on `require_non_divergent()` for the same shape of reasoning; `repair` should refuse pending coexistence.

Symmetrically, `update` and `evaluate` don't refuse staging when `repair` is already pending — and the same hazard applies in reverse (Rpr_at_K+1 then Upd_at_T+1 in pending). The fix on `repair` alone covers the common direction; tightening both gates closes the corner case.

**Suggested fix:** Take option (a). One-line guard at the top of `repair` (after `require_established()`). Add a unit test `repair_refuses_when_pending_nonempty` that stages an Upd via the builder then asserts `repair` errors with `InvalidKel`. The test costs ~10 lines and pins the contract.

If you want to pin the symmetric case, add `if self.pending_events.iter().any(|e| e.kind.is_repair())` checks in `update` and `evaluate` too — symmetric with the `require_non_divergent` gate. Smaller blast radius; defer until the user-error path is observed in the wild.

**Resolution (round-9 implementation):** Structurally impossible under the owner-local rework (see M1 Resolution). With `sad_verification` derived from local store only, the cached tip is owner's last authoritative event — there's no adversary-tip-as-cached-tip footgun for `update` to chain off of. The L2 guard was never added; the bug it would have caught can't be reached. No code change beyond the M1 rework.

### ~~3. `flush()`'s `was_repair` rehydrate is documented as "one extra GET" but `verify_sad_events` pages through the entire post-repair chain — could be dozens of round-trips for long-lived chains~~ — RESOLVED

**File:** `lib/kels/src/sad_builder.rs:718-745`

The repair-flush branch comment at `:718-725` says:

> Repair flushes need a fresh server fetch, not incremental absorb. ... a fresh `verify_sad_events` round-trip produces the right post-repair token. **One extra GET on the repair path**; non-repair flushes keep the incremental-absorb fast path.

But `client.verify_sad_events(&prefix, checker)` (`client/sadstore.rs:411-424`) delegates to the `verify_sad_events` free fn, which pages through the chain via `transfer_sad_events` with `page_size()` per page and up to `max_pages()` pages. For a chain at version 200 with `KELS_PAGE_SIZE=64`, that's 4 pages — 4 GETs, not 1.

This isn't an inefficiency that bites today (repair is rare, most chains are short). But the docstring will mislead a future reader debugging slow repairs on a long-lived chain. The asymmetry vs. the surrounding text — which carefully sketches the trade-off rationale — undersells the real cost.

The walk-back is already O(64) by the M1 fix; the rehydrate is the unfixed half of the same asymmetry. A symmetric tail-style endpoint for "fetch the post-repair chain efficiently" doesn't make sense (the rehydrate has to re-verify the whole chain from v0 to populate `establishment_version`, etc.). So the cost is structural — the fix is just to name it accurately.

**Suggested fix:** Update the comment at `:718-725` to read "One full chain re-verification on the repair path (one GET per page; for a chain at version N with `KELS_PAGE_SIZE=P`, that's `ceil(N/P)` round-trips). Acceptable because repair is rare and the chain is bounded by the governance bound × evaluations cycled; profile the rehydrate cost if it becomes a UX issue on long-lived chains." No code change.

Optionally, add a `#[cfg(debug_assertions)]` log line like `tracing::debug!(prefix=%prefix, "post-repair rehydrate: full chain re-verification")` so an operator tailing logs sees the cost is real.

**Resolution (round-9 implementation):** Resolved by switching the rehydrate to local store via `sel_completed_verification` instead of `client.verify_sad_events` (`lib/kels/src/sad_builder.rs:746-789`). The local prefix index now contains owner's pre-repair events plus the freshly-stored Rpr (via `store_sel_event` at `:711-716`), so the local view reconstructs the post-repair owner-authored chain with no server round-trip. The misleading "one extra GET" comment is replaced with an accurate description of the local-store re-hydrate path. Repair flushes are now strictly faster than the pre-round-9 path (no network on the rehydrate), and the comment matches the code.

---

## Positive Observations

- **The Round-7 dedup-rate-limit gate composes cleanly with the Round-5 dedup-divergence-signal fix.** `submit_sad_events` (`services/sadstore/src/handlers.rs:1219-1232`) gates the per-prefix budget pre-flight, then the dedup branch (`:1300-1332`) runs `first_divergent_version` only if budget permits. The two fixes pull in opposite directions — divergence-signal wants more work on the dedup path, rate-limit wants less — and the ordering resolves the tension correctly: budget gate first (cheap, bounds amplification), then divergence query (more expensive, but only on requests that already paid budget). The integration test `rate_limit_runs_above_dedup` (`sad_builder_tests.rs:1037-1086`) pins the four-deductions-then-rejection contract end-to-end.

- **The `was_repair` post-submit branch correctly orders local-cache writes BEFORE the rehydrate.** `flush` (`sad_builder.rs:704-768`) writes pending events to `sad_store` at `:711-716` regardless of `was_repair`. So when the repair commits server-side and the client's network cuts off mid-rehydrate, the local cache already holds the Rpr. A retry `flush` calls `submit_sad_events` (server dedups, `applied: false`), the local cache write is idempotent, and the rehydrate runs again. State converges cleanly. The non-repair branch's `set_diverged_at_version` stamping (`:757-761`) is correctly skipped on the repair branch because the rehydrate already captures the divergence state authoritatively — no risk of double-stamping or stale-stamping.

- **`SadEventBuilder::owner_branch_tip` honors the pending-tail-shadows-verification convention.** `:818-827` returns `pending_events.last()` if any, falling back to `branches().first().tip`. Even though `repair` doesn't currently chain after a staged Upd (see Low 2), the helper's shape is right: it reflects the builder's "local view" semantic that pervades the rest of the accessor surface. When Low 2 is fixed by adding the `pending.is_empty()` guard, this helper will only ever return `branches().first().tip` for the repair caller — the pending-tail branch becomes dead code but documents intent correctly, mirroring `KeyEventBuilder::get_owner_tail`.

- **The Round-6 `SadBranchTip` unification is exercised end-to-end by the integration test pair.** `flush_repair_heals_divergent_chain` (`sad_builder_tests.rs:694-858`) and `flush_repair_heals_adversarially_extended_chain` (`:868-1019`) both round-trip through `with_prefix` → `repair` → `flush` → `verify_sad_events`. The first pins Case A (divergent, `branches().len() == 2` pre-repair, `== 1` post). The second pins Case B (linear, `diverged_at_version() == None`, walk traverses adversary's 3-event extension). Both tests include the post-flush effective-SAID assertion (`fetch_sel_effective_said` returns `divergent: false`) so the M1-followup contract is pinned at the wire-format level. The deliberate hand-construction of fork events bypassing the (single-actor) builder is the right call: the builder refuses divergent state by design, so a healing test must stage the failure at the HTTP layer.

- **The `RepairTestSadSource` rename + `PagedVecSadSource` rename in Round 8 propagated cleanly without leaving stragglers.** `lib/kels/src/sad_builder.rs:1177` (`RepairTestSadSource`) and `lib/kels/src/types/sad/sync.rs:453` (`PagedVecSadSource`) — both renamed from the prior name-collision `VecSadSource`. The cross-references in their docstrings (`sad_builder.rs:1173-1176` and `sync.rs:451-452`) name the capability split (tail-capable vs. paginated-only) and point at each other. A future test author landing in either module sees both halves of the choice. The `RepairTestSadSource` is also (per Low 1 above) the natural place to add the SAID-verification regression test for the medium finding.

- **The `compute_sad_event_prefix` tradeoff comment (Round-6 L3) gives a future profiler exactly the information they need.** `lib/kels/src/types/sad/event.rs:159-176` names the cost (one extra Blake3 + `validate_structure`), the design intent (uniform structural-rule tightening across staging and prefix-derivation), and the principled fix (factor a prefix-only helper) for if profiling later flags this on a hot path. This is the kind of cost-disclosed-in-place comment that prevents future "why is this slow?" archaeology — the answer is right there.

- **The `set_diverged_at_version` `or_else` semantics + `pub(crate)` visibility decision is internally consistent across local-detection and server-stamp paths.** `event.rs:577-588` — local detection (verifier-side observation during `verify_page`) wins precedence over server stamps, and external code can read `diverged_at_version()` but cannot fabricate one. Round 4's `flush` stamping path (`sad_builder.rs:757-761`) is gated on `Some(at) = response.diverged_at`, so a server reporting `None` doesn't clobber a local `Some(_)`. The `set_diverged_at_version_or_else_semantics` test (`sad_builder.rs:1651-1681`) pins both halves: stamps set on a None-token, no-ops on an already-Some token even with a different value. Threat-model-aligned.

---

## Resolutions

### Structural rework: `sad_verification` becomes owner-authoritative (KEL parity)

The audit's M1 and L2 are downstream symptoms of a single architectural mismatch: `with_prefix` calls `client.verify_sad_events(prefix, checker)` which walks the *server's* chain (potentially adversary-extended) and stamps the result into `sad_verification` — so `sad_verification.current_event()` returns server's tip, which under adversarial extension is adversary's. Then `update`/`evaluate`/`repair` extend from a poisoned tip.

KEL doesn't have this problem because `kel_verification` is built by running `KelVerifier::verify_page` over events loaded from local `kel_store` (`load_tail(prefix, limit)`). Owner's tip is `branch_tips().first().tip` — owner's branch by construction, because the local verifier only ever walked owner's events. SEL needs the same.

The rework, in order:

**1. `with_prefix` derives `sad_verification` from local persistence only — no server consultation at construction.**

This mirrors KEL's `KeyEventBuilder::with_dependencies` (`lib/kels/src/builder.rs:67-99`), which runs `completed_verification` over the local `kel_store` via `StorePageLoader` and never calls the server. KEL has the infrastructure for this because `KelStore::load(prefix, limit, offset)` provides prefix-keyed offset-based access. SEL is missing the equivalent — `SadStore::load(said)` is SAID-keyed only — so we need to build the parallel infrastructure first.

**Note on prefix vs SAID:** prefix is *never* equal to a SAID. The prefix is derived from `(write_policy, topic)` *before* v0's SAID is computed (correlation-prevention by design — see `compute_sad_event_prefix` and `SadEvent::icp`). v0 carries the prefix as a field; v0's SAID is computed over a structurally-blanked form that includes the prefix. So owner cannot look up v0 by computing "v0.said from the prefix" — there is no such computation. Local-store iteration must be prefix-indexed.

**Infrastructure to add (KEL parity):**

- **Extend `SadStore`** (`lib/kels/src/store/sad.rs`) with prefix-keyed offset-based access for SEL events. Add a method analogous to `KelStore::load`: `load_sel_events(prefix, limit, offset) -> Result<(Vec<SadEvent>, has_more), KelsError>`. Returns events for the prefix ordered `(version ASC, said ASC)`. Implementations maintain a prefix index alongside the existing SAID-keyed table; the in-memory and on-disk impls grow a per-prefix index, the repository-backed impl gets a `WHERE prefix = $1 ORDER BY version, said LIMIT N OFFSET M` query. Other SAD object types (publications, custody envelopes, etc.) are unaffected — they still use `load(said)`. Trait method, impl on each backend, parallel naming with KEL.
- **Rename KEL's `StorePageLoader` to `KelStorePageLoader`** (`lib/kels/src/types/kel/sync.rs:33-51`) for naming parity with the new SEL type. Update all references (the rename ripples through `KeyEventBuilder::with_dependencies` at `lib/kels/src/builder.rs:73-87` and any tests that name the type).
- **Add `SadStorePageLoader`** (parallel to KEL's renamed `KelStorePageLoader`): wraps `&dyn SadStore`, implements a new `SelPageLoader` trait with `load_page(prefix, limit, offset)`. Lives alongside `PagedSadSource` (the cursor-based trait used for HTTP transfer); the new trait is offset-based for local-store iteration.
- **Add `sel_completed_verification`** (parallel to KEL's `completed_verification` at `lib/kels/src/types/kel/sync.rs:104-155`): takes a `SelPageLoader`, prefix, page_size, max_pages, checker. Walks pages via `loader.load_page`, runs `SelVerifier::verify_page` per page, handles generation-boundary truncation if needed, fail-secure on `max_pages` exhaustion, returns `SelVerification`.
- **`with_prefix`** calls `sel_completed_verification(SadStorePageLoader::new(&sad_store), prefix, page_size(), max_pages(), checker)`. No `client.verify_sad_events`. Token reflects owner's local view.
- **`flush`'s local-cache write path** must populate the prefix index alongside the existing SAID-keyed write. The current `sad_store.store(&event.said, &value)` call should grow a prefix-index update (via the new method or as part of `store`). Owner's events get into the prefix-indexed view automatically as they're flushed.

If `sad_store` is `None` or `checker` is `None`, the constructor returns an empty builder (analogous to KEL's `kel_verification: None` when either is missing). Inception flows go through `new()`; `with_prefix` is the resume-from-existing-chain constructor and requires both local persistence and a checker.

The existing `client.verify_sad_events(prefix, checker)` call is **dropped** from `with_prefix`. Server state is consulted at action time (flush, repair), not at construction.

**Re Jason's suggestion to add an offset param to `transfer_sad_events`:** that's the cursor-based sync path (server-side; `PagedSadSource::fetch_page` with `since` SAID cursor). It's orthogonal to local-store access. KEL has both kinds of trait — `PageLoader` (offset, used by `completed_verification` over `KelStore`) and `PagedKelSource` (cursor, used by `transfer_kel_events` over HTTP). What SEL is missing is the offset-based local-store equivalent — that's the `SelPageLoader` proposed above. The cursor-based transfer functions don't need changes.

**2. `SelVerification` is owner-local — no server-extension flag.**

The token carries owner's view: branches (verified from local store), policy state, `diverged_at_version` retains its existing meaning (set if owner's local store has genuinely divergent events — rare, multi-device edge cases — or stamped from a flush response). **No new flag for "server has events past owner's tip."** That signal is computed on-demand at repair time, not stored in the token.

This matches KEL's `KelVerification` shape: `branch_tips`, `is_contested`, `diverged_at_serial` — all describing owner's local view. No "server has more rotations than I do" flag in the token; that's computed by `should_rotate_with_recovery(server_verification, ...)` when needed, with a separately-fetched `server_verification` parameter (`builder.rs:21-32`).

**3. `update`/`evaluate` semantics unchanged externally — staging extends owner's tip via `current_tip()` as today.**

The bug was upstream in tip-derivation; the staging code is correct.

**4. `repair` becomes an explicit user-initiated action that consults the server on-demand AND verifies its response.**

Drop the existing `if let Some(divergence_at) = ...` / `if sad_store.load(cached_tip.said).await?.is_some()` dispatch. Replace with the following sequence — note that every step that consumes server data verifies it:

- **(a)** Gate on owner's local view: if `sad_verification.policy_satisfied() == false`, refuse with `KelsError::ChainHasUnverifiedEvents`. Owner's local chain failed its own policy verification (disk tampering that recomputed valid SAIDs for forged content, KEL-side corruption, etc.); repair won't fix that and shouldn't operate on it.
- **(b)** Fetch server's `effective_said` for the prefix.
- **(c)** If server's tip == owner's tip: return `KelsError::NothingToRepair`.
- **(d)** Fetch server's tail via `fetch_tail`. M1's per-event `verify_said + prefix check` runs on each fetched event in `walk_back_to_first_owner` (catches per-event content forgery — adversary substituting content for a given SAID).
- **(e)** Run `SelVerifier::verify_page` over the fetched chain to verify chain-level integrity AND policy. This is the heavy lifting that `with_prefix` used to do at construction time; under the rework it moves to repair time. Cost: one full chain verification when repair fires; acceptable because repair is rare.
- **(f)** If the fetched chain's verification reports `policy_satisfied == false` → refuse with `KelsError::ChainHasUnverifiedEvents`. Server is serving events that pass per-event SAID integrity but don't have valid KEL anchoring — i.e., not actually anchored adversarial extension, just noise. Owner doesn't expend governance authorization responding to noise.
- **(g)** Walk back via `walk_back_to_first_owner` (probing local `sad_store`) to find owner's last authoritative event = boundary.
- **(h)** Stage the Rpr at `version = boundary.version + 1`, `previous = boundary.said`.

Two `policy_satisfied` gates fire — (a) on owner's local view, (f) on the server's view-at-repair-time. They guard different data sources. The principle is "verify before you decide" applied symmetrically: every input to the repair decision is verified before contributing.

This matches KEL's user model: `recover()` and `contest()` are explicit user-initiated actions that fetch and verify whatever server state they need at invocation time. No pre-flight signal in the token.

**5. `flush` continues to detect server conflicts at submit time** (existing behavior). When owner attempts to extend a stale tip, the server's response signals divergence or stale-tip; the user reads the error and explicitly invokes `repair`.

**6. Add `SadEventKind::sort_priority` for tie-break meaningfulness and cross-node convergence (KEL parity).**

KEL has `KeyEventKind::sort_priority()` (`lib/kels/src/types/kel/event.rs:86-97`) returning `Icp(0), Dip(1), Ixn(2), Rot(3), Ror(4), Dec(5), Rec(6), Cnt(7)` — state-determining events sort later. Used in DB query `order_by_case` (`lib/kels/src/repository.rs:50`), in test sort fixtures (`lib/kels/src/types/auth.rs:202-212`), and in the verifier's expected event order (`lib/kels/src/types/kel/verification.rs:242` — `serial ASC, kind sort_priority ASC, said ASC`).

SEL needs the analog. Two reasons:

- **Divergent-generation tie-break meaningfulness.** `SelVerification::winning_branch` (`lib/kels/src/types/sad/event.rs`) currently breaks ties on `(version ASC, said ASC) → max`. A high-SAID `Upd` could win over a low-SAID `Rpr` at the same version — semantically wrong, since `Rpr` is state-determining (triggers `truncate_and_replace`). With kind-priority, the announcement winner reflects the most authoritative event.
- **Cross-node convergence under gossip-induced reordering.** If node A receives `Upd@v(K+1)` then `Rpr@v(K+1)`, vs node B in the opposite order, the resulting chain state can diverge depending on which event sets `from_version` for the server's `truncate_and_replace`. Canonical kind-priority gives the server (and verifier) a deterministic answer regardless of arrival order — `Rpr` always wins the version slot.

**Priority assignment:** `Icp(0), Est(1), Upd(2), Evl(3), Rpr(4)`. State-determining sorts later, mirroring KEL's shape.

**Surfaces to update:**

- `SadEventKind::sort_priority(&self) -> u8` method + `sort_priority_mapping() -> Vec<(&'static str, i64)>` (parallel to KEL's `event.rs:86-115`).
- Server-side repository queries: `get_stored_in` (`services/sadstore/src/repository.rs:343-346`), `get_stored`, the new `load_sel_events`, and any other event-fetch query — all change from `order_by("version", Asc) → order_by("said", Asc)` to `order_by("version", Asc) → order_by_case("kind", sort_priority_mapping(), Asc) → order_by("said", Asc)`. Mirrors KEL's pattern at `lib/kels/src/repository.rs:50`.
- `SelVerifier::verify_page` ordering expectations: docstring update naming the canonical ordering, plus internal sort if it processes events grouped by version — confirm in implementation whether the within-generation processing order needs to follow priority.
- `SelVerification`'s `winning_branch` tie-break: `(version ASC, kind sort_priority ASC, said ASC) → max`. Update the comparator.
- `transfer_sad_events` and `verify_sad_events` ordering — expect the new canonical order from sources (HTTP and local).
- `truncate_and_replace` server logic — review whether `from_version = events[0].version` semantics need to account for kind priority. If a divergent batch has `[Upd@v(K+1), Rpr@v(K+1)]` after sorting, `Rpr` comes after `Upd` in `(version, kind)` order, so `events[0]` is still `Upd` and `from_version` is still `K+1`. The truncation truncates `>= K+1` regardless. No change needed there, but document the assumption.

**Tests:**

- Unit test for `SadEventKind::sort_priority` — assert the priority values.
- Unit test for `SelVerification::winning_branch` tie-break with kind-priority: build a divergent token at v(K+1) with `[Upd, Evl]`, assert `winning_branch.tip.kind == Evl`. Same with `[Upd, Rpr]` → `Rpr` wins.
- Server-side query ordering test: insert events at the same version with different kinds, query, assert canonical order returned.
- Cross-node convergence integration test (extension of the regression script): create a divergent generation via direct HTTP submits in different orders on two test runs, assert the post-repair effective_said converges to the same value regardless of submission order.

**5. Drop the L2 pending-empty guard.**

Under owner-authoritative `sad_verification`, the L2 bug is structurally impossible: `update` always stages from owner's tip, and a subsequent `repair` produces an Rpr at owner's-tip + 1 (or whatever the boundary is). The Upd's `previous` link is no longer poisoned because the cached tip is no longer poisoned. No explicit guard needed.

**6. Keep the M1 `policy_satisfied` gate on `repair`** — both halves.

The original M1 framing assumed adversary-served events would reach the verifier corpus and be caught by the gate. Under owner-local design those events never reach the corpus (filtered by local-store membership). New rationale: **owner's local view can still fail policy** via disk tampering that recomputes a valid SAID for forged content. A tampered event passes `verify_said` but its KEL anchor (which referenced the pre-tamper SAID) doesn't match the post-tamper SAID, so `PolicyChecker::satisfies` fails, so `policy_satisfied` is `false`. The gate at `repair` step (a) catches that.

Symmetrically, step (f) gates on the *fetched* chain's `policy_satisfied` — catches server-side noise (forged events that lack KEL anchoring entirely).

Both gates are "verify before deciding" applied to two distinct data sources (local store, server). Neither is redundant.

The M1 `verify_said + prefix check` per fetched event in `walk_back_to_first_owner` also **stays** — the walk still fetches server data and that data still needs per-event integrity checks before chain-level verification can trust the chain's structure.

**7. Cross-node propagation: ordering investigation.**

KEL's `contest` builder prepends `find_missing_owner_events()` output before the cnt event so the receiving server can verify the post-contest chain. SEL's adversary doesn't archive (Case B silent extension) and divergent forks share their below-divergence prefix (Case A), so the receiving server already has every event below the boundary — no missing-event prepend needed in the common case.

But for multi-node gossip propagation: if owner submits to node A, gossip propagates to node B, and node B's chain segment between v0 and the boundary differs from node A's, the repair propagation could fail node B's verification. Investigate during implementation: under what conditions can a receiving node lack events below the repair boundary, and does the repair batch need missing-events prepend like KEL's contest? If yes, mirror `find_missing_owner_events` for SEL — bounded by the governance invariant (≤63 events).

The natural staging order via `current_tip()` produces `[Rpr, optional_extensions...]` automatically — Rpr leads the batch, owner's post-repair extensions follow. That's the right shape regardless of the missing-events question.

### Tests

**Unit tests.**

- The existing `repair_at_adversarial_extension_boundary*` tests need fixture rework to construct owner-authoritative `SelVerification`s. Under the rework, the cached tip is owner's; the Case-B test scenario shifts from "cached tip is adversary's, walk back to find owner's" to "cached tip is owner's, repair flag is set, Rpr extends owner's tip." Re-pin the boundary contract appropriately.
- New unit test for `with_prefix`'s owner-tip derivation: seed `sad_store` with owner's events v0..vK. Fresh `with_prefix` call (server may or may not have additional events — irrelevant, with_prefix doesn't consult). Assert `sad_verification.current_event().version == K`, `pending_events.is_empty()`.
- New unit test for `repair`'s server consultation: seed `sad_store` with v0..vK; spin up a fake `SadStoreClient` whose `fetch_sel_effective_said` reports a different tip and whose `fetch_tail` returns v0..vT (with adversary's events at v(K+1)..vT). Call `repair`; assert it stages `Rpr_v(K+1), previous = vK.said`.
- New unit test for `repair`'s clean-state path: seed sad_store with v0..vK; fake client reports `effective_said` matching vK. Call `repair`; assert `NothingToRepair`.
- Tampered local store test: seed `sad_store` with an event whose `said` doesn't match its content. `with_prefix` should error during local verification, not silently produce a poisoned token.

**Drop tests.**

- `repair_refuses_when_pending_nonempty` from the L2 resolution — no longer needed.
- The M1 `policy_satisfied`-false gate test — dropped along with the gate.
- Any test asserting cached tip is server's tip on `with_prefix` — semantics inverted.

**Regression script: `clients/test/scripts/test-sadstore.sh`.**

End-to-end shell script exercising both repair cases against a live deployment (testcontainers or real services, whichever the existing scripts use). Plan:

1. Create owner identity, incept SEL chain, flush a few Upds. (Script uses the existing `kels` CLI; if SEL CLI is missing, this is the moment to add the relevant subcommands — see #147.)
2. **Case A (divergent):** stage two conflicting Upds at the same version via direct `submit_sad_events` calls (bypassing the builder), confirm server reports divergence. Run repair via the builder. Assert post-repair `effective_said` reports `divergent: false` and the resulting tip is owner's Rpr.
3. **Case B (silent extension):** simulate adversary by submitting an Upd extending owner's tip via direct `submit_sad_events` (signed with a separate signer that satisfies write_policy). Confirm server accepts. Run `with_prefix` on a fresh builder; assert `sad_verification.current_event()` is *owner's* last-authored event, not adversary's. Run repair; assert truncation lands at the right version.
4. **Sanity:** clean state on a fresh chain — `with_prefix` produces `repair_target_version: None`, `repair` returns `NothingToRepair`.

Script lives in `clients/test/scripts/`; runs as part of the existing test orchestration so a future regression flips it red.

### M1 verify_said + prefix check (preserved sub-finding)

Independent of the structural rework above: the per-fetched-event integrity check from the original M1 resolution stays. In `walk_back_to_first_owner`, immediately after `let tail = sad_source.fetch_tail(...)`, run `event.verify_said()?` and check `event.prefix == *prefix` per event. Tighten the `PagedSadSource::fetch_tail` docstring to call out "callers MUST verify event SAIDs before trusting `previous` linkage."

Add a unit test using `RepairTestSadSource` that returns an event with mismatched `said`/content; call `walk_back_to_first_owner` directly; assert `verify_said` error.

### L3 — accurate cost comment on the repair-flush rehydrate path

Replace the "one extra GET" phrasing in the `was_repair` comment block at `lib/kels/src/sad_builder.rs:718-725` with an accurate description: one full chain re-verification on the repair path (one GET per page; `ceil(N/P)` round-trips). Note that this is structural (the rehydrate has to re-verify from v0 to populate `establishment_version`) and acceptable because repair is rare. No code change.
