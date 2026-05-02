# Deviations Log

The durable record of where implementation diverges from plan: deferrals, scope-narrowings, parked subsystems, exemptions, deliberate-by-design corners. Anything that's not a straight execution of the plan-as-written.

## Conventions

**When to log.** Any of: implementation differs from the plan's prescription, work was deferred or scope-narrowed, a subsystem is parked, a lint/forbid rule has a documented exemption, behavior is deliberate-by-design but non-obvious enough that future review would otherwise flag it. If a strict execution of the plan would be wrong (incorrect plan, missing constraint), log the corrected behavior with rationale rather than silently diverging.

**Entry shape.** `### [Issue # introduced → Issue # that should resolve] One-line summary` as the heading, followed by the detail body. Keep entries self-contained: the `why` matters as much as the `what`, since the log outlives the conversation that produced it. Inline file paths, error variants, and code references where they pin the deviation.

**Open entries live inline in this README** with their full body. The README serves as the live index of active deviations — readable top-to-bottom for "what's currently open."

### On resolution — mechanics

When an open entry resolves (the work shipped, the exemption was retired, the deferral was paid down), follow this exact mechanism so the slug-files and README index stay consistent:

1. **Pick a slug.** Lowercase kebab-case derived from the entry's topic — typically a compressed form of the summary words. Examples: `iel-verifier-and-walker-extraction`, `sad-event-icp-parameter-ordering`, `gap-11-doc-sweep-spillover`. If multiple entries describe the same area at different times, disambiguate by tagging with the resolving stage (e.g., `cli-exchange-parked-gap-2-resolved-gap-5` vs the still-open `cli-exchange-parked-gap-5-resolved-147`). No leading numbers; no dates in slugs.

2. **Create `<slug>.md` in this directory.** First line: H1 heading matching the entry's original heading verbatim, including the `[X → Y]` tag. Body: the entry's full detail block, rewritten to past tense to describe what shipped (what code changed, where, what tests pin it). Include the file paths, line ranges, and error-variant names that anchor the resolution.

3. **Replace the README entry with a one-line index entry** in the `## Resolved` section. Format:

   `- **[X → Y]** [Heading-summary text](slug.md) — one-sentence summary of what shipped.`

   The bolded `[X → Y]` tag preserves the audit trail (what was open, what closed it). The link points to the slug file. The em-dash + summary gives the reader a "should I click through?" preview. Keep the summary tight — one sentence, ideally under 25 words.

4. **Order in the Resolved section: newest first.** New entries go at the top of the list; older entries shift down.

5. **Don't delete.** Resolved entries are permanent audit trail. The Open section gets shorter on resolution; the Resolved section grows.

### Long-form open entries

If an entry's open body grows past several paragraphs (e.g., a multi-page design rationale or test-cell taxonomy) and is impeding the README's readability, you may split it early using the same mechanism: move the body to `<slug>.md`, leave a summary + link inline. Default is to keep open entries inline; this is a reserve for unusually long ones. When such an early-split entry resolves, it stays in its slug file and the README's Open-section pointer migrates to the Resolved section in the standard format.

### Reading cadence

Read this README at the start of every new issue or planning phase. Each open entry is a question: is this still open? Did the work just done close it? Is the reasoning still correct? An entry that's still open after several rounds is either correct as a permanent design choice (move to a `Permanent` section if scale demands it) or a real omission worth scheduling.

### Historical terminology

Entries from before the issue-numbered convention use `Gap N` (numbered chunks within the round-12 development effort on `KELS-126_sad-event-builder`). Historical labels like `[Gap N → Gap M]` or `[Round-12 review fix → ...]` identify the source-of-deviation; preserve them on retirement so the audit trail stays readable. New entries use `Issue #N`.

### Lint exemption

This subtree has its own `.terminology-forbidden` (empty) so the lint doesn't fire on entries that legitimately reference retired terminology to explain what was renamed. The lint script's "deepest replaces shallowest" semantics scope the exemption to this directory only; elsewhere in the repo the production forbid file applies normally.

---

## Open

### [Round-12 review fix → pre-production / #152] `is_satisfied` per-call IEL re-verification

`AnchoredIelResolver::is_satisfied` and `RepositoryIelResolver::is_satisfied` each rebuild the full `IelVerification` token on every call (now via the shared `verify_identity_events_with_queried` helper). For an SE chain with N v1+ events, that's N IEL walks per SE verification — bounded by `max_pages × page_size = 4096` events per walk at default config.

For round-12 production (short chains, 1–3 v1+ events) this is fine. Pre-production with deeper SE chains, this becomes a meaningful per-SE-verification cost multiplier.

**Fix path:** cache the per-identity `IelVerification` inside the resolver (Mutex<HashMap<Digest256, IelVerification>> or OnceCell keyed by identity). Cache lifetime equals resolver lifetime equals SE-verification lifetime, so no invalidation needed during the SE walk. Same shape on both impls. Not blocking #147 e2e gating; tracked here for the #152 perf pass.

### [Round-12 third follow-up commit 1] Verifier-side queried/satisfied SAID + post-divergence soft-fail propagation

Closes Important #1 from the second max review. Two mechanisms shipped together because they share the same per-event flow rewrite.

**Caller-bounded SAID querying.** `IelVerification` and `SelVerification` gain `queried_saids` / `satisfied_saids` fields plus `is_said_satisfied(said)` / `satisfied_saids()` / `queried_saids()` accessors mirroring `KelVerification`'s shape. Verifiers gain a `check_satisfied(saids)` builder method (analog of KEL's `check_anchors`). During the walk, an event whose SAID is in `queried_saids` is added to `satisfied_saids` iff the event passed its auth check AND lives at `version < first_divergent_version` (or chain non-divergent). Cnt is structurally always at-or-after divergence and never lands in `satisfied_saids`; Dec on a clean chain CAN.

**`IelResolver::is_satisfied`** added to the trait + both production impls. SE caller pre-walks its own chain (streaming via `collect_identity_event_saids` / `_from_loader`, accumulating SAID-level metadata only — never events), feeds the result into `AnchoredIelResolver::with_queried_saids` / `RepositoryIelResolver::with_queried_saids`, then `is_satisfied` answers consistently. SE per-event flow consults it via β-ordering: after `resolve_*_at`, before `is_anchored`. SOFT-fails for terminals or post-SE-divergence non-terminals; HARD pre-divergence non-terminals.

**Post-divergence soft-fail propagation.** Pre-divergence events keep their existing soft/hard mapping. For events at `version >= first_divergent_version`: auth-check failures (IelDivergent gate, is_satisfied=false, anchor-fail) convert to SOFT — the verifier sets chain-wide `policy_satisfied=false` and the event lands without Err. Implemented on both `IelVerifier` (the round-11 gap: round 11 shipped Cnt's-own-soft-fail but not propagation) and `SelVerifier`. Structural integrity rules (SAID validity, version monotonicity, content preservation, BadIdentityBinding, IEL Evl-immunity) stay HARD always — Cnt doesn't change well-formedness.

**Resume-rehydrate divergence from KEL.** `IelVerifier::resume` / `SelVerifier::resume` rehydrate `queried_saids` and `satisfied_saids` from the prior token, unlike `KelVerifier::resume` which resets them. The IEL/SE streaming pre-walk pattern needs registered interest to persist across page boundaries. KEL's symmetric fix is deferred to #152 (changing it now would touch the KEL surface for no functional gain on the KEL path).

**KEL parity.** `KelVerification` already has the `queried_saids` / `anchored_saids` shape (round-11 baseline); no token-shape changes on KEL. Names differ between primitives intentionally: KEL's "anchored" reflects "SAID found in an IXN event's anchor field"; IEL/SE "satisfied" reflects "auth-passed AND pre-divergence."

### [Gap 11 → standalone] `write_policy` not globally forbidden by `.terminology-forbidden`

Plan §Gap 11 line 481 instructed forbidding `write_policy` globally as part of the round-12 doc/terminology sweep. Implementation deviated: `write_policy` is **not** globally forbidden because Custody legitimately uses `write_policy` as a distinct concept from SE auth — see `lib/kels/src/types/sad/custody.rs` (round-11 baseline, unchanged in round 12). Forbidding globally would have broken Custody's field naming.

Resolution: `.terminology-forbidden` keeps `write_policy` allowed; the Custody usage stays. Plan author was wrong about Custody usage in the round-12 plan — the rename was scoped to SE only, not Custody.

### [Round-12 follow-up] Gap 8 PUSH-direction post-sync check — chose Option 1

`services/gossip/src/sync.rs` (~lines 1807-1908 pre-fix) applied the PULL-shaped post-sync check (`new_said != local_said` against the local effective SAID) uniformly across both PUSH and PULL directions. On a successful PUSH the local SAID doesn't change (we sent; remote advanced), so the check returned `false`, the loop classified success as `Failed`, and the entry re-queued. Self-healed next cycle but inflated retry metrics.

Chose **Option 1**: skip the post-sync state-advancement check on PUSH; trust HTTP-2xx from `forward_sad_events` as proof of remote acceptance.

Rationale: `HttpSadSink::store_page` (lib/kels/src/types/sad/sync.rs:279-301) already converts any non-2xx-non-409 remote response into `Err`. The remote's submit handler runs the verifier inside the request/response cycle, so verifier rejection surfaces as a 4xx and propagates back as `forward_sad_events.is_err()`. PUSH's HTTP-2xx therefore genuinely carries the remote's accept signal, which is structurally different from PULL where the local sink's verifier runs *after* the HTTP layer returns 2xx. The original Gap 8 anti-pattern was PULL-specific; KEL Phase 1 (the architectural reference) has no PUSH branch, so the uniform check was a copy-error rather than a design choice.

Implementation: dropped the shared `sync_ok` boolean; PUSH and PULL each end with their own outcome dispatch (PUSH returns `Repaired` directly on success; PULL keeps the local-SAID re-fetch). Direction-anchored comments replace the conflated comment block. `any_peer_differs` semantics (NoOp vs Failed) unchanged.

### [Gap 5 → #147] Builder-level IEL state caching not implemented

Plan §Gap 5 (lines 359-361) called for cached IEL state on the `SadEventBuilder` plus `iel_client` caching, so that successive `update()` / `seal()` / `repair()` / `contest()` / `decommission()` calls don't each round-trip to the IEL HTTP endpoint to resolve `identity_event`. Implementer skipped without tracking — every lifecycle op currently re-fetches the current IEL binding via `fetch_current_iel_binding(&identity)` (sad_builder.rs).

Performance, not correctness. Each call sees fresh IEL state, which is the safe default; the tradeoff is N HTTP round-trips for N builder calls within a session.

Deferred to #147 (CLI + script migration). The CLI consumer drives the repeated-builder-call access pattern, so the cache shape (TTL, invalidation triggers, manual `flush()` semantics) can be designed against the actual usage rather than guessed up front.

### [Gap 11 → #147] est/evl wire-format patterns exempted at `clients/test/scripts/`

Path-scoped exemption via `clients/test/scripts/.terminology-forbidden`. The patterns `kels/sad/v1/events/est` and `kels/sad/v1/events/evl` are dropped from the test-scripts subtree's forbid file but retained in the production root file. Rationale: the test scripts in this directory still build pre-round-12 SE events (writePolicy on Icp, governancePolicy on Est-v1, SEL prefix derived from policy_said). They will be rewritten to drive the round-12 CLI surface in #147 (CLI + script migration). Until then the production lint stays strict and the test scripts compile/run as-is (they are runtime-broken vs. round-12 servers, but that's deferred).

Restore those two patterns to the subtree forbid when #147 lands. The lint infrastructure now supports per-subtree forbid files (`scripts/lint-terminology.sh`, deepest-wins replacement semantics) — same mechanism can be used for future short-lived exemptions.

### [Gap 8 → end-of-round verification] Phase-1 anti-entropy unit + integration tests deferred

The Gap 8 plan asks for:
- Unit tests for the new `NoOp` branch.
- Unit tests for the post-sync state check.
- An integration test where a forwarded chain is rejected at the sink (mock policy resolver) and the local stale entry stays queued for retry rather than being cleared.

Implementation reality: the SEL Phase 1 task is an inline async closure inside `run_sad_anti_entropy_loop` (`services/gossip/src/sync.rs`). Unit-testing the dispatch arms requires extracting the closure into a standalone function — a meaningful refactor with API-shape implications on adjacent KEL Phase 1 code. The integration test needs a mock SADStore returning HTTP 2xx but rejecting at verification time, plus testcontainer scaffolding none of the existing gossip tests rely on (the file's tests are constants/error-wrapping/handler-lifecycle only — KEL Phase 1 itself has no comparable unit tests).

Given (a) KEL Phase 1 — the architectural reference — has no unit tests for the same dispatch shape, (b) the Heisenbug-carry-forward verification step at end-of-round explicitly exercises this path under load with 50+ test-sadstore.sh runs, and (c) Gap 9 lands the test-harness convergence wait that makes deployment-test failures attributable, the testing burden is best paid through the deployment-test sweep rather than redundant unit/integration tests.

If the deployment-test sweep surfaces a regression in Gap 8's logic (NoOp incorrectly clearing a stale entry, or HTTP-success-but-not-advanced incorrectly declaring Repaired), revisit and add the unit tests then. Until then this is documented work-skipped, not work-missed.

Tracked in #119 (Codebase Hygiene) under Test coverage.

### [Gap 0 → Gap 0] `IelChainPosition` shape extended beyond plan's suggestion

Plan suggested `{ version: u64, branch_marker: Option<BranchId> }`. Shipped: `{ version: u64, kind: IdentityEventKind, said: cesr::Digest256, branch_marker: Option<cesr::Digest256> }`.

Added `kind` and `said` because the canonical IEL sort key is `(version ASC, kind sort_priority ASC, said ASC)` — `try_cmp` needs all three to break ties correctly within a version. Plan said "suggested"; this is a reasonable elaboration, not a contradiction. Logged for visibility, not because it needs resolution.

### [Gap 1 → standalone] `lib/policy/src/identity_chain.rs` deleted

The pre-round-12 SE-based identity-chain primitive (`create_identity_chain`, `advance_identity_chain`, `compute_identity_prefix`, `IDENTITY_CHAIN_TOPIC`) was tightly coupled to SE's dropped policy fields and is structurally superseded by IEL in round 12. Removed entirely (and from `lib/policy/src/lib.rs`'s re-exports). No external consumers existed — verified by grep before deletion.

The `UnreachableIelResolver` test fake added in Gap 0 went with it. Gap 2's verifier tests will define narrower per-test fakes inside their own test modules, matching the existing per-file `PolicyChecker` fake pattern (`lib/kels/src/types/sad/verification.rs`, `lib/kels/src/types/iel/verification.rs`, etc.).

### [Gap 10b — open] 5 sealed-divergent tests `#[ignore]`'d as single-node-untestable

The round-12 plan calls for a 5-test family covering the sealed-divergent routing matrix:

- `sealed_divergent_chain_accepts_cnt_terminates_with_contested`
- `sealed_divergent_chain_rejects_dec_with_contest_required`
- `sealed_divergent_chain_rejects_upd_with_contest_required`
- `sealed_divergent_chain_rejects_sea_with_contest_required`
- `sealed_divergent_chain_rejects_rpr_with_contest_required`

All five `#[ignore]`'d in single-node testing because the sealed-divergent state — defined as `first_divergent_version <= last_governance_version` — requires a fork at-or-behind the seal, but `SadEventRepository::save_batch` rejects exactly that case ("Cannot fork at version X — sealed by evaluation at version Y"). In production the state arises transiently across federation when node-A authors a Sea at the same version where node-B authored a competing Upd before the two synced; single-node tests can't reproduce that race.

A future expansion could either (a) add a test-only insert API that bypasses the seal-check, or (b) build a 2-SADStore harness with gossip wiring. Until then the routing branches are exercised at code review (Gap 4 routing matrix) and via the Heisenbug deployment-test sweep.

### [Gap 10b — open] 4 gossip-propagation tests deferred to deployment-test

The round-12 plan also calls for 4 gossip-propagation tests:

- `gossip_full_chain_appends_to_empty_sink`
- `gossip_propagates_cnt_to_divergent_sink`
- `gossip_propagates_cnt_to_active_sink`
- `gossip_propagates_dec_to_active_sink`

These need a 2-SADStore harness with the gossip mesh wired up (allowlist setup, peer-state machine, the gossip background loop running). That's significantly outside the existing harness's scope and the plan's "covered by Gap 9's harness convergence wait + the Heisenbug deployment-test sweep" framing applies.

### [Gap 10b → next k8s test-client update] multi-node cases owed to test-sadstore.sh

When `clients/test/scripts/test-sadstore.sh` (the k8s deployment-test script) gets its next round-12 expansion pass, ensure the multi-node cases this Gap 10b couldn't reach are covered there. Two families:

1. **Sealed-divergent routing matrix** (5 cases — see Open section above). In k8s the state arises naturally: node-A submits a Sea while node-B submits a competing Upd at the same version; gossip delivers them out of order and the receiver creates the sealed-divergent state. Add scenarios that:
   - Cnt on sealed-divergent → lands.
   - Dec / Upd / Sea / Rpr on sealed-divergent → ContestRequired.

2. **Gossip propagation of terminal events** (4 cases — see Open section above). The current `test-sadstore.sh` already exercises linear-chain gossip propagation; add:
   - Cnt propagates to a divergent sink.
   - Cnt propagates to an active sink (matrix Contested→Active).
   - Dec propagates to an active sink.
   - Full-chain append to an empty sink (already implicit but pin explicitly).

Both groups depend on the test harness having ≥2 sadstore nodes (the existing FEDERATED=true mode does); just need the scenario logic added.

---

## Resolved

Newest first. Each entry's body lives in its own slug file in this directory.

- **[Gap 5 → #147]** [Exchange CLI commands parked compile-clean since SE rewrite](cli-exchange-parked-gap-5-resolved-147.md) — `cmd_exchange_publish_key` / `_rotate_key` / `_lookup_key` rewired onto round-12 SE primitives; new `--identity <iel-prefix>` arg replaces inline `write_policy` derivation.

- **[Round-12 review fix → audit + resolver fix on KELS-126]** [Post-divergence auth-failed Evl: `policy_history` records prior tracked policies, not event-declared values](iel-resolver-verifier-adopted-policy-view.md) — KELS-126 Group A audit found one consumer (`RepositoryIelResolver::resolve_{auth,governance}_policy_at`) reading `event.auth_policy` / `event.governance_policy` directly; rerouted through a new `verification_for` helper + `verification.auth_policy_at(said)` / `governance_policy_at(said)` so the resolver consults the verifier-adopted view (mirroring `AnchoredIelResolver`). DB-tamper integration test pins the new contract.

- **[Round-12 review fix → audit confirmed clean]** [Auth-passing post-SE-divergence event keeps `chain.policy_satisfied=true`](policy-satisfied-consumer-audit.md) — KELS-126 Group A consumer audit walked all five `.policy_satisfied()` production sites; every one answers "did any auth check fail in the walk?" rather than the divergence/terminal questions. SE Cnt path explicitly does NOT gate on the flag (SOFT-auth design respected). No code changes needed; design contract pinned for future consumers.

- **[Pre-existing → round-12 third follow-up commit 2]** [HttpSadSink/HttpIelSink 409 silent-skip + server-side response-code semantics](sink-409-and-response-code-semantics.md) — audit + fix of all server-side 409 sites; server-internal integrity failures split off to 500 via `ChainVerificationFailed`; IEL terminal-state-gate response moved to 200-with-`terminal: Some(_)` indicator (option C); SE side picks up symmetric idempotency.

- **[Round-12 review fix → resolved]** [IEL verifier + walker structural extraction](iel-verifier-and-walker-extraction.md) — page-walk + queried/satisfied registration triplication eliminated; closes Important #1 (multi-page IEL walk duplicate-event bug at page boundaries) plus M1 and M11.

- **[Round-12 review fix → resolved]** [SE pre-walk + soft-fail predicate split + β-ordering documentation](se-prewalk-and-soft-fail-predicate.md) — handler pre-walk fail-secures on `max_pages`; `auth_soft_eligible` split into named pieces; β-ordering rationale documented inline.

- **[Round-12 review fix → resolved]** [Test coverage closeout](round-12-third-followup-test-coverage.md) — post-SE-divergence cell tests, IEL send-side coverage, V=D+1 walk-back integration test.

- **[Pre-round-12 IEL primitive gap → Round-12 third follow-up commit 4]** [IEL send-side divergence partitioning implemented](iel-send-side-divergence-partitioning.md) — `send_divergent_iel_events` mirroring KEL's pattern; KEL/SEL/IEL symmetry restored.

- **[Gap 1 → 40c9ef2]** [`SadEvent::icp` parameter ordering corrected](sad-event-icp-parameter-ordering.md) — `(topic, identity)` flipped to plan-spec `(identity, topic)` in the round-12 cleanups commit.

- **[Gap 11 → 7a2f374]** [Gap 11 doc-sweep spilled to a follow-up commit](gap-11-doc-sweep-spillover.md) — AGENTS.md / README.md / event-log.md / reconciliation.md updates landed across two commits; process deviation logged.

- **[Gap 0 → Round-12 third follow-up commit 2]** [`iel_chain_positions` post-divergence walk-back implemented](iel-chain-positions-walk-back.md) — both resolvers walk `event.previous` to the divergence-version ancestor; same-branch events now compare canonically; approximation retired.

- **[Gap 10a → Gap 10b]** [critical-subset → broader taxonomy](gap-10b-test-taxonomy-expansion.md) — Gap 10b extended Gap 10a's 10 critical tests to 23 covering the round-12 plan's prescribed taxonomy minus the 5 sealed-divergent matrix cases and 4 gossip-propagation cases (both still Open).

- **[Gaps 0/4/5 → Gap 6]** [error variant placeholders](error-variant-placeholders.md) — `IncompleteInception` / `BadIdentityBinding` / `DecommissionBlockedByDivergence` variants added; placeholder call sites swept.

- **[Gap 1 → Gap 5]** [`sad_builder.rs` stub](sad-builder-rs-stub.md) — Gap 5 shipped the round-12 `SadEventBuilder` end-to-end with `incept_chain` / `update` / `seal` / `repair` / `contest` / `decommission`.

- **[Gap 0 → Gap 5]** [`AnchoredIelResolver` moved from lib/policy to lib/kels](anchored-iel-resolver-relocation.md) — relocation upstream so the SE builder can construct it.

- **[Gap 2 → Gap 5]** [CLI exchange commands parked](cli-exchange-parked-gap-2-resolved-gap-5.md) — Gap 2's "parked pending Gap 11 CLI rewrite" stubs documented as resolved; the follow-on parking (Gap 5 → #147) is tracked as a separate Open entry.

- **[Gap 2 → Gap 4]** [handler `PlaceholderIelResolver` + repair-seal-check downgrade](placeholder-iel-resolver-and-seal-check.md) — `RepositoryIelResolver` supplants the Placeholder; round-12 routing matrix replaces the seal-check downgrade.

- **[Gap 1 → Gap 3]** [4 schema-dependent `repair_tests.rs` cases](repair-tests-schema-dependency.md) — schema migration unblocked; Gap 3 also added `is_contested` / `is_decommissioned` and rewired `effective_said`.

- **[Gap 1 → Gap 2]** [`verification.rs` stub](verification-rs-stub.md) — Gap 2's full `SelVerifier` rebuild with the round-12 branch-state shape and 13 test cases.
