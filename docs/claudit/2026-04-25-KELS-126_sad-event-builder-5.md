# Branch Audit: KELS-126_sad-event-builder (Round 5) — 2026-04-25

Fifth-pass audit of the SadEventBuilder branch after `/clear`. Read every changed source file plus the prior four round documents to avoid re-finding resolved issues. Cumulative across prior rounds: 25 resolved (10 R1 + 7 R2 + 4 R3 + 4 R4), 0 open. This round added 4 new findings (1 medium, 3 low), all 4 now resolved.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 1        |
| Low      | 0    | 3        |

---

## Medium Priority

### ~~1. The dedup path on the server silently drops the divergence signal — a `flush()` retry after a phase-3 failure leaves the local token reporting "linear" while the chain is divergent~~ — RESOLVED

**File:** `services/sadstore/src/handlers.rs:1294-1304` (server), `lib/kels/src/sad_builder.rs:489-520` (client `flush`)

When `submit_sad_events` finds every submitted SAID already in the DB, it commits and returns:

```rust
let response = kels_core::SubmitSadEventsResponse {
    diverged_at: None,
    applied: false,
};
return (StatusCode::CREATED, Json(response)).into_response();
```

`diverged_at: None` is unconditional on this path — the handler does not query whether the existing chain is currently divergent before composing the response. The Round 4 M1 fix added the `diverged_at` propagation specifically because "the local verifier only saw the owner's batch, so its `diverged_at_version` would be `None` even when the server has two branches at this version" (`sad_builder.rs:505-515`, comment). The dedup path leaves the same hole open in a slightly different shape: the local verifier still sees `None`, the server response also says `None`, and the chain is divergent on the server.

Concrete sequence that hits this:

1. Owner stages two events at v6/v7, calls `flush()`.
2. Server commits the events and observes a concurrent fork at v6 → returns `applied: true, diverged_at: Some(6)`.
3. Client's `submit_sad_events` returns the response. Phase 2 (`sad_store.store(...)`) succeeds.
4. Phase 3 (`absorb_pending`) fails — for example, the local checker errors transiently against the KEL fetch endpoint (any non-`CannotResumeDivergentChain` error survives this scenario; the divergent-token guard isn't in play yet because `sad_verification` is `None` on the first flush of a fresh builder).
5. `flush` returns `Err(...)`. The `Some(6)` from `response.diverged_at` is dropped on the floor — it lived in a local variable. The builder's `pending_events` is unchanged, `sad_verification` is still `None`.
6. Owner retries `flush()`. `submit_sad_events` is invoked again. The server dedups all SAIDs → returns `applied: false, diverged_at: None`.
7. `absorb_pending` succeeds this time. The local verifier processes the owner's pending events as a single linear branch — which they are, when viewed in isolation — and produces a token with `diverged_at_version: None`.
8. The post-absorb stamp at `sad_builder.rs:511-515` is gated on `let Some(at) = response.diverged_at`, which is `None` on this retry. No stamp.
9. `flush` returns `Ok(FlushOutcome { diverged_at_at_submit: None })`. The CLI warning at `clients/cli/src/commands/exchange.rs:162-171` and `:276-285` does not fire. The owner believes the submit was clean.

After this point, `sad_verification.diverged_at_version()` returns `None`. `update()` and `evaluate()` both consult this via `require_non_divergent` (`sad_builder.rs:547-554`) and accept staging. The owner's next `update()` succeeds locally, stages an Upd at v8, calls `flush`. Only on *that* submit does the server re-report `diverged_at: Some(6)` (via the normal-path response from `save_batch`, which exposes the `DivergenceCreated` variant — `:1481-1488`). The signal is recovered, but in the gap the owner's local token has lied to them.

The lie is bounded — it gets corrected on the next non-dedup submit — but in the gap the builder's stagers will accept events that they should refuse with `KelsError::SelDivergent`. The whole point of the Round 4 M1 redesign was to make the builder loudly refuse staging on a divergent chain so the owner explicitly chooses repair. The dedup path defeats that gate for one builder lifecycle.

The shape also affects callers that don't go through the builder. A direct `submit_sad_events` retry (e.g., `clients/cli/src/commands/sel.rs:cmd_sel_submit`) sees `applied: false, diverged_at: None` and prints "{n} SAD event(s) submitted" with no warning, even when the server-side chain is currently divergent.

**Suggested fix:** Three options, in order of preference.

- **(a)** On the dedup path, query the chain's current effective-SAID/divergence state via `state.repo.sad_events.effective_said(sel_prefix)` (already used at `:1525`) and report it in the response. The `EffectiveSaidResponse` already carries `divergent: bool`. Mapping that to `Some(version)` requires one more query (`diverged_at_version` from the events table) but produces an authoritative response. Cost: one DB read on the dedup path. Benefit: the response now describes "the chain's current state" rather than "what this submit did," which is the more useful invariant for a client that's holding a stale view.
- **(b)** Cheaper variant: leave the response shape but always populate `diverged_at` from a lightweight DB query, even when `applied: false`. Same outcome, slightly less response-schema thinking required.
- **(c)** Client-side workaround only: after `flush`, when `outcome.diverged_at_at_submit.is_none()` *and* `applied` was `false` (which currently isn't exposed — see Low 3 below), do a follow-up `fetch_sel_effective_said` call before returning. Pushes the work onto every caller and doesn't fix the direct-submit path in `sel.rs`. Worst of the three.

The Round 4 M1 fix and this finding share a root cause: response shape decisions made at the server layer determine whether the client can avoid silent state drift. Option (a) closes the question at the right layer.

**Resolution:** Took option (a) — the server now reports the chain's *current* divergence state on the dedup short-circuit, not unconditional `None`. Four-part change:

1. **New repository method.** `SadEventRepository::first_divergent_version(prefix)` (`services/sadstore/src/repository.rs:269-298`) returns the lowest version with more than one row, or `None` for linear chains. `ColumnQuery::fetch_grouped_count` returns `Vec<i64>` of counts only — no group keys exposed, no MIN-over-HAVING composition — so the method drops to a hand-written SQL query via `self.pool.inner()` (`sqlx::query_scalar`). Query shape: `SELECT MIN(version) FROM (SELECT version FROM sad_events WHERE prefix = $1 GROUP BY version HAVING COUNT(*) > 1) AS divergent_versions`. Docstring names the asymmetry vs `is_divergent` (which only answers boolean) and points at the dedup-path call site.
2. **Direct `sqlx` dep.** `services/sadstore/Cargo.toml:60-66` adds `sqlx = { version = "0.8", features = ["runtime-tokio", "postgres"] }`. Already transitive via `verifiable-storage-postgres`; promoted so the repository can call `sqlx::query_scalar` without going through `PgPool::inner()` at every call site. `cargo deny` passes for sadstore (the existing `RUSTSEC-2026-0097` advisory ignore covers the transitive `rand 0.8` issue).
3. **Dedup short-circuit populates `diverged_at`.** `services/sadstore/src/handlers.rs:1294-1314` calls `first_divergent_version` before `tx.commit()`, threading errors through the same warn-rollback-500 pattern as the surrounding code. The block-leading comment names the round-4 M1 stamping path as the symmetric write-side mechanism, so a future reader sees both halves of the contract in one place.
4. **Integration test.** `services/sadstore/tests/sad_builder_tests.rs:587-686` — `submit_dedup_returns_current_divergence_signal` stages v0/v1 via the builder + flush, hand-builds two conflicting v2 Upd events bypassing the (single-actor) builder, anchors both, submits each separately, then re-submits the second one and asserts the dedup path returns `applied: false, diverged_at: Some(2)`. Pre-fix this would return `Some(2)` once and `None` thereafter.

`make` passes clean. The new test runs against the existing testcontainer harness (Postgres ×2, Redis, MinIO, both HTTP services).

---

## Low Priority

### ~~2. `cmd_sel_submit` prints `events.len()` regardless of `response.applied`, masking dedup~~ — RESOLVED

**File:** `clients/cli/src/commands/sel.rs:23-26`

```rust
println!(
    "{}",
    format!("{} SAD event(s) submitted", events.len()).green()
);
if let Some(at) = response.diverged_at { ... }
```

If the user submits 5 events that were all already on the server (dedup), the response is `applied: false, diverged_at: None` and the message reads "5 SAD event(s) submitted" in green. From the user's perspective, nothing was submitted — the events were already there. The message conflates "events sent in this request" with "events committed to the chain."

This isn't load-bearing — the chain state is correct either way — but it produces a misleading success indicator. A repair-flow user who submits the same batch twice (e.g., after a transient network failure) sees "submitted" both times and might assume the second call also took effect.

**Suggested fix:** Branch on `response.applied`:

```rust
if response.applied {
    println!("{}", format!("{} SAD event(s) submitted", events.len()).green());
} else {
    println!("{}", "no new events submitted (all already present)".yellow());
}
```

The wording can be tuned, but the binary distinction matches the response-type semantics (`applied: bool`). Round 4's `#[must_use]` annotation already pushes callers toward checking `applied`; this is one of two CLI sites (the other is `exchange.rs`, which doesn't access `response.applied` either) that don't yet honor it.

**Resolution:** `clients/cli/src/commands/sel.rs:23-32` — green "{n} SAD event(s) submitted" only when `applied: true`; yellow "no new events submitted (all already present on server)" when `false`. The divergence warning at `:34-43` runs after either branch unchanged. After M1 lands (it did), the dedup-retry case surfaces divergence here too, completing the loop.

### ~~3. `FlushOutcome` doesn't expose `applied`, so builder callers can't distinguish "events committed" from "all-deduplicated"~~ — RESOLVED

**File:** `lib/kels/src/sad_builder.rs:22-37` (definition), `:489-520` (population)

```rust
pub struct FlushOutcome {
    pub diverged_at_at_submit: Option<u64>,
}
```

The struct is forward-extensible by design (the docstring says so), and `applied` is the obvious next field. Without it, a CLI caller who wants to print "no new events" vs. "events committed" has to do the bookkeeping themselves — and right now neither exchange.rs nor sel.rs distinguishes the two cases. The Medium-1 finding above is the divergence-shaped manifestation of the same gap; this is the more general one.

The connection is direct: the server's dedup-path response is the only `applied: false` path on a healthy server, and it's exactly the path where Medium-1 fires. Exposing `applied` doesn't fix Medium-1 (the divergence info is dropped at the server layer), but it lets callers detect "I retried and the server says nothing new was applied" — which is a useful signal in its own right and a precondition for the client-side workaround (Medium-1 option c).

**Suggested fix:** Add `pub applied: bool` to `FlushOutcome`, populated from `response.applied`. The `#[must_use]` annotation on `FlushOutcome` already steers consumers to check it. Update `cmd_exchange_publish_key`, `cmd_exchange_rotate_key`, and any future flush caller to consult `applied` for user-facing messaging.

**Resolution:** Three-part change.

1. **Struct field.** `lib/kels/src/sad_builder.rs:28-44` adds `pub applied: bool`. Populated from `response.applied` in the success path (`:526`) and `false` in the empty-pending early return (`:478`). The `#[must_use]` message is tightened to mention both fields: "FlushOutcome carries divergence signals — check diverged_at_at_submit before continuing to stage events, and check applied to distinguish committed-new from already-present-on-server."
2. **CLI publish-key.** `clients/cli/src/commands/exchange.rs:162-167` — `cmd_exchange_publish_key` prints yellow "key already published — server reports no new events" when `!outcome.applied`. The divergence warning runs after.
3. **CLI rotate-key.** `clients/cli/src/commands/exchange.rs:283-288` — `cmd_exchange_rotate_key` prints yellow "rotation event already on server — no new events committed" when `!outcome.applied`. Same pattern.

Existing `services/sadstore/tests/sad_builder_tests.rs:620` got a `let _ =` on the `builder.flush()` call — the tightened `#[must_use]` message hits the previously-discarded result and clippy treats it as `unused_must_use`. No new unit tests needed; the existing `flush_submits_and_absorbs` test already asserts the field name compiles via `outcome.diverged_at_at_submit.is_none()`, and the new M1 integration test exercises both `applied: true` and `applied: false` paths.

### ~~4. The repair-path "must include an evaluation" check is unreachable given the `is_repair` precondition~~ — RESOLVED

**File:** `services/sadstore/src/handlers.rs:1316-1379`

```rust
is_repair = new_events.iter().any(|r| r.kind.is_repair());

if is_repair {
    ...
    if !new_events
        .iter()
        .any(|r| r.version >= from_version && r.kind.evaluates_governance())
    {
        let _ = tx.rollback().await;
        return (
            StatusCode::BAD_REQUEST,
            "repair must include an evaluation at or after the divergence point",
        )
            .into_response();
    }
```

`is_repair` is true ⟺ at least one new event has `kind.is_repair()`, i.e., is `Rpr`. Looking at `SadEventKind::evaluates_governance` (`event.rs:74-76`):

```rust
pub fn evaluates_governance(&self) -> bool {
    matches!(self, Self::Evl | Self::Rpr)
}
```

Every `Rpr` event satisfies `evaluates_governance()`. So once `is_repair` is true, the `new_events.iter().any(|r| ... && r.kind.evaluates_governance())` check is satisfied as long as the Rpr event itself is at `version >= from_version` — which is also guaranteed by the construction of `from_version` in `truncate_and_replace`, which derives it from the new events' versions.

The check is a dead branch under the current event-kind taxonomy. It's not wrong — the comment above it ("Repair must include an evaluation at or after the divergence point — an attacker who can only satisfy write_policy cannot repair") describes a real invariant — but the invariant is enforced earlier by `is_repair` itself plus the `Rpr.evaluates_governance() == true` definition.

This is brittle in one direction: if a future refactor splits `Rpr` into a non-evaluating "rewind" kind and an evaluating "repair-with-eval" kind, the check would suddenly become load-bearing. Right now it's defensive scaffolding without a documented threat model — a reader will ask "how could this fail?" and have to derive the proof that it can't.

**Suggested fix:** Either (a) delete the check and trust the kind taxonomy, with a comment at the top of the repair branch stating the invariant `is_repair ⟹ at least one new event evaluates governance ⟹ check holds by construction`; or (b) keep the check but rewrite the comment to call out *why* it's defensive ("future-proofs against a non-evaluating repair kind"). Low priority — the code is correct today either way. Skewing toward (a): the redundant check is more confusing than the absent one.

**Resolution:** Took option (a). `services/sadstore/src/handlers.rs:1384-1391` — the runtime check + brief comment is replaced with a concise by-construction proof comment that ends "If `Rpr` is ever split into evaluating / non-evaluating subkinds, restore an explicit check here." Existing repair tests pass unchanged — the deleted block was unreachable, so the change is behavior-preserving. No new regression test for deleted dead code.

---

## Positive Observations

- **The Round 4 M1 stamping path is sequenced correctly relative to `absorb_pending`.** `flush()` calls `set_diverged_at_version` after `absorb_pending().await?`, so the stamp lands on the freshly-populated `sad_verification` rather than racing it. The `or_else` semantics preserve any local detection (verifier-side detection wins, server-side report fills in only when local was None). Pinned by `set_diverged_at_version_or_else_semantics` at `sad_builder.rs:1080-1110`.

- **`SelVerifier::resume`'s prefix-derivation is authoritative from the verification token rather than caller-supplied.** `verification.rs:534-553` reads `prefix = tip.prefix`, drops any external prefix argument, and seeds `prefix: Some(prefix)` into the resumed verifier. A future caller of `resume` cannot accidentally rebind the chain to a different prefix mid-flight — the only way to operate on a chain is via `new(prefix, ...)` (fresh hydration) or `resume(token, ...)` (continuation from verified state). Two paths, each unambiguous.

- **`incept`'s `governance_policy: Digest256` (required) vs `incept_deterministic`'s `governance_policy: Digest256` + `content: Option<Digest256>` keeps the discoverable-prefix contract typed-in.** `sad_builder.rs:292-334` — the per-kind constructor split (Round 4 L4) carried through to the builder API: `incept` produces a v0-with-governance whose prefix bakes in `governance_policy`, while `incept_deterministic` produces a bare-Icp-plus-Est pair whose v0 SAID is a pure function of `(topic, write_policy)`. The signature distinction names the contract. The regression test `incept_prefix_diverges_from_compute_sad_event_prefix` (`:669-689`) pins both halves.

- **The `SubmitSadEventsResponse.applied` and `.diverged_at` fields are independently meaningful and the `#[must_use]` annotation enforces caller awareness.** `request.rs:44-52`. After Round 4 M1, the type's contract is fully observable: parse the response, check `applied` to see whether anything new committed, check `diverged_at` to see whether the chain is/became divergent at this version. The Medium-1 finding above is about the dedup path under-populating `diverged_at`, not about the type's shape — the shape is right.

- **The `or_else` mutator on `SelVerification` is `pub(crate)` and the only writer is `flush`.** `event.rs:511-515`, used at `sad_builder.rs:511-515`. External callers cannot fabricate a divergence claim, and the single internal call site is in the place that sees the authoritative server response. The accessibility decision aligns with the threat model — a divergence stamp is a load-bearing claim, and only the flush-completion path has a basis to make one.

- **The two-phase compaction in `post_sad_object` is correctly amplification-bounded under repeated submits.** `services/sadstore/src/handlers.rs:438-510` — phase 1 hashes nested SADs in memory and short-circuits via the HEAD check on the canonical SAID before any MinIO write. An attacker submitting the same expanded SAD N times pays N hash rounds but exactly one MinIO put-set, regardless of N. The depth and size bounds (`MAX_COMPACTION_DEPTH = 32`, `max_sad_object_size()`) cap each individual submission; the HEAD check caps cross-submission amplification. Defense in depth is real here.

- **`flush()`'s phase-3 fail-fast guard for `checker = None` (Round 3 M1 fix) is properly placed before any side effects.** `sad_builder.rs:483-487` — the check fires immediately after the `sad_client` validation and before `submit_sad_events`, so a builder constructed without a `PolicyChecker` errors cleanly without leaving server-committed events that the local builder cannot absorb. The guard inside `absorb_pending` (`:566-569`) is preserved for direct test callers. Belt-and-suspenders, both in the right places.
