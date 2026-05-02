# Deviations Log

The durable record of where implementation diverges from plan: deferrals, scope-narrowings, parked subsystems, exemptions, deliberate-by-design corners. Anything that's not a straight execution of the plan-as-written.

## Conventions

**When to log.** Any of: implementation differs from the plan's prescription, work was deferred or scope-narrowed, a subsystem is parked, a lint/forbid rule has a documented exemption, behavior is deliberate-by-design but non-obvious enough that future review would otherwise flag it. If a strict execution of the plan would be wrong (incorrect plan, missing constraint), log the corrected behavior with rationale rather than silently diverging.

**Entry shape.** `### [Issue # introduced → Issue # that should resolve] One-line summary` as the heading, followed by a short detail block. Keep entries self-contained: the `why` matters as much as the `what`, since the log outlives the conversation that produced it. Inline file paths, error variants, and code references where they pin the deviation.

**Sections.** `## Open` for unresolved or deliberate-and-permanent entries. `## Resolved` for entries retired by a later issue's work — keep these as audit trail (don't delete on resolution; they document what was once open and how it closed). New entries always go in `## Open`.

**Retiring an entry.** When the resolving issue ships, move the entry to `## Resolved`, prepend `**[<original heading> → <resolving issue/commit>]** ` to the heading, and rewrite the body to past tense describing what shipped. Don't delete; the trail is the value.

**Reading cadence.** Read this file at the start of every new issue or planning phase. Each entry is a question: is this still open? Did the work just done close it? Is the reasoning still correct? An entry that's still open after several rounds is either correct as a permanent design choice (move to a `Permanent` section if scale demands it) or a real omission worth scheduling.

**Historical terminology.** Entries from before the issue-numbered convention use `Gap N` (numbered chunks within the round-12 development effort on `KELS-126_sad-event-builder`). Historical labels like `[Gap N → Gap M]` or `[Round-12 review fix → ...]` identify the source-of-deviation; preserve them on retirement so the audit trail stays readable. New entries use `Issue #N`.

**Cross-linking.** When an entry's body grows past a few paragraphs (e.g., a multi-page design rationale or test-cell taxonomy), move the body to `docs/planning-deviations/<slug>.md` and replace the entry body with a one-paragraph summary plus a link. The Open/Resolved entry stays in this file; the depth lives next to it.

---

## Open

### [Round-12 review fix → pre-production / #152] `is_satisfied` per-call IEL re-verification

`AnchoredIelResolver::is_satisfied` and `RepositoryIelResolver::is_satisfied`
each rebuild the full `IelVerification` token on every call (now via the
shared `verify_identity_events_with_queried` helper). For an SE chain
with N v1+ events, that's N IEL walks per SE verification — bounded by
`max_pages × page_size = 4096` events per walk at default config.

For round-12 production (short chains, 1–3 v1+ events) this is fine.
Pre-production with deeper SE chains, this becomes a meaningful per-SE-
verification cost multiplier.

**Fix path:** cache the per-identity `IelVerification` inside the
resolver (Mutex<HashMap<Digest256, IelVerification>> or OnceCell
keyed by identity). Cache lifetime equals resolver lifetime equals
SE-verification lifetime, so no invalidation needed during the SE walk.
Same shape on both impls. Not blocking #147 e2e gating; tracked here
for the #152 perf pass.

### [Round-12 review fix → standalone, deliberate] Auth-passing post-SE-divergence event keeps `chain.policy_satisfied=true`

The post-divergence soft-fail propagation rule (commit 1 of the third
follow-up) flips `chain.policy_satisfied=false` only when an auth-related
gate (`IelDivergent`, `is_satisfied`, `is_anchored`) FAILS for an event
at `version >= diverged_at_version`. An auth-PASSING post-SE-divergent
event leaves `chain.policy_satisfied=true`.

The pinned test
`upd_post_divergence_auth_pass_advances_ratchet_excludes_from_satisfied`
in `lib/kels/src/types/sad/verification.rs` confirms this is the
deliberate behavior: chain-wide `policy_satisfied` tracks
"any auth failures encountered in the walk" — orthogonal to the
divergence cutoff. The per-event SAID query (`is_said_satisfied`)
is the cutoff-aware signal: post-divergence SAIDs are NOT in
`satisfied_saids` even on auth-pass.

A strict reading of the design's "verification doesn't bless" framing
would also flip `chain.policy_satisfied=false` for any post-divergence
event. Implementation diverges from that strict reading because
consumers needing the cutoff signal use `is_said_satisfied` per-SAID;
the chain-wide flag is the auth-validity aggregate, not the
divergence-status flag. `is_contested` / `is_decommissioned` carry
the divergence-status signal content-based.

No behavior change planned in #152; logged here so future review
knows this pairing is intentional.

### [Round-12 review fix → standalone, deliberate] Post-divergence auth-failed Evl: `policy_history` records prior tracked policies, not event-declared values

When a post-IEL-divergence Evl auth-fails (soft path), the IEL verifier
records `policy_history[event.said] = (PRIOR auth, PRIOR governance)` —
the event payload's declared policies are NOT adopted into branch state
(the unauthenticated evolution is rejected from trust). Consumers
calling `auth_policy_at(post_div_evl_auth_failed.said)` get prior
policies, not the event's stated values.

This is the verifier's adopted-state view, distinct from the raw event
payload. Documented on `auth_policy_at` / `governance_policy_at`'s
doc-comment in `lib/kels/src/types/iel/verification.rs` (see
"Verifier-view, not raw-event-view"). Consumers must use these accessors
rather than reading `event.auth_policy` directly to honor the trust
contract.

### [Round-12 third follow-up commit 1] Verifier-side queried/satisfied SAID + post-divergence soft-fail propagation

Closes Important #1 from the second max review. Two mechanisms shipped
together because they share the same per-event flow rewrite.

**Caller-bounded SAID querying.** `IelVerification` and `SelVerification`
gain `queried_saids` / `satisfied_saids` fields plus
`is_said_satisfied(said)` / `satisfied_saids()` / `queried_saids()`
accessors mirroring `KelVerification`'s shape. Verifiers gain a
`check_satisfied(saids)` builder method (analog of KEL's `check_anchors`).
During the walk, an event whose SAID is in `queried_saids` is added to
`satisfied_saids` iff the event passed its auth check AND lives at
`version < first_divergent_version` (or chain non-divergent). Cnt is
structurally always at-or-after divergence and never lands in
`satisfied_saids`; Dec on a clean chain CAN.

**`IelResolver::is_satisfied`** added to the trait + both production
impls. SE caller pre-walks its own chain (streaming via
`collect_identity_event_saids` / `_from_loader`, accumulating SAID-level
metadata only — never events), feeds the result into
`AnchoredIelResolver::with_queried_saids` /
`RepositoryIelResolver::with_queried_saids`, then `is_satisfied` answers
consistently. SE per-event flow consults it via β-ordering: after
`resolve_*_at`, before `is_anchored`. SOFT-fails for terminals or
post-SE-divergence non-terminals; HARD pre-divergence non-terminals.

**Post-divergence soft-fail propagation.** Pre-divergence events keep
their existing soft/hard mapping. For events at `version >=
first_divergent_version`: auth-check failures (IelDivergent gate,
is_satisfied=false, anchor-fail) convert to SOFT — the verifier sets
chain-wide `policy_satisfied=false` and the event lands without Err.
Implemented on both `IelVerifier` (the round-11 gap: round 11 shipped
Cnt's-own-soft-fail but not propagation) and `SelVerifier`. Structural
integrity rules (SAID validity, version monotonicity, content
preservation, BadIdentityBinding, IEL Evl-immunity) stay HARD always —
Cnt doesn't change well-formedness.

**Resume-rehydrate divergence from KEL.** `IelVerifier::resume` /
`SelVerifier::resume` rehydrate `queried_saids` and `satisfied_saids`
from the prior token, unlike `KelVerifier::resume` which resets them.
The IEL/SE streaming pre-walk pattern needs registered interest to
persist across page boundaries. KEL's symmetric fix is deferred to
#152 (changing it now would touch the KEL surface for no functional
gain on the KEL path).

**KEL parity.** `KelVerification` already has the `queried_saids` /
`anchored_saids` shape (round-11 baseline); no token-shape changes on
KEL. Names differ between primitives intentionally: KEL's "anchored"
reflects "SAID found in an IXN event's anchor field"; IEL/SE
"satisfied" reflects "auth-passed AND pre-divergence."

### [Gap 11 → standalone] `write_policy` not globally forbidden by `.terminology-forbidden`

Plan §Gap 11 line 481 instructed forbidding `write_policy` globally as
part of the round-12 doc/terminology sweep. Implementation deviated:
`write_policy` is **not** globally forbidden because Custody legitimately
uses `write_policy` as a distinct concept from SE auth — see
`lib/kels/src/types/sad/custody.rs` (round-11 baseline, unchanged in
round 12). Forbidding globally would have broken Custody's
field naming.

Resolution: `.terminology-forbidden` keeps `write_policy` allowed; the
Custody usage stays. Plan author was wrong about Custody usage in the
round-12 plan — the rename was scoped to SE only, not Custody.

### [Round-12 follow-up] Gap 8 PUSH-direction post-sync check — chose Option 1

`services/gossip/src/sync.rs` (~lines 1807-1908 pre-fix) applied the
PULL-shaped post-sync check (`new_said != local_said` against the
local effective SAID) uniformly across both PUSH and PULL directions.
On a successful PUSH the local SAID doesn't change (we sent; remote
advanced), so the check returned `false`, the loop classified success
as `Failed`, and the entry re-queued. Self-healed next cycle but
inflated retry metrics.

Chose **Option 1**: skip the post-sync state-advancement check on PUSH;
trust HTTP-2xx from `forward_sad_events` as proof of remote acceptance.

Rationale: `HttpSadSink::store_page` (lib/kels/src/types/sad/sync.rs:279-301)
already converts any non-2xx-non-409 remote response into `Err`. The
remote's submit handler runs the verifier inside the request/response
cycle, so verifier rejection surfaces as a 4xx and propagates back as
`forward_sad_events.is_err()`. PUSH's HTTP-2xx therefore genuinely
carries the remote's accept signal, which is structurally different
from PULL where the local sink's verifier runs *after* the HTTP layer
returns 2xx. The original Gap 8 anti-pattern was PULL-specific; KEL
Phase 1 (the architectural reference) has no PUSH branch, so the
uniform check was a copy-error rather than a design choice.

Implementation: dropped the shared `sync_ok` boolean; PUSH and PULL
each end with their own outcome dispatch (PUSH returns `Repaired`
directly on success; PULL keeps the local-SAID re-fetch). Direction-
anchored comments replace the conflated comment block. `any_peer_differs`
semantics (NoOp vs Failed) unchanged.

### [Gap 5 → #147] Builder-level IEL state caching not implemented

Plan §Gap 5 (lines 359-361) called for cached IEL state on the
`SadEventBuilder` plus `iel_client` caching, so that successive
`update()` / `seal()` / `repair()` / `contest()` / `decommission()`
calls don't each round-trip to the IEL HTTP endpoint to resolve
`identity_event`. Implementer skipped without tracking — every
lifecycle op currently re-fetches the current IEL binding via
`fetch_current_iel_binding(&identity)` (sad_builder.rs).

Performance, not correctness. Each call sees fresh IEL state, which
is the safe default; the tradeoff is N HTTP round-trips for N builder
calls within a session.

Deferred to #147 (CLI + script migration). The CLI consumer drives
the repeated-builder-call access pattern, so the cache shape (TTL,
invalidation triggers, manual `flush()` semantics) can be designed
against the actual usage rather than guessed up front.

### [Gap 11 → #147] est/evl wire-format patterns exempted at `clients/test/scripts/`

Path-scoped exemption via `clients/test/scripts/.terminology-forbidden`. The
patterns `kels/sad/v1/events/est` and `kels/sad/v1/events/evl` are dropped
from the test-scripts subtree's forbid file but retained in the production
root file. Rationale: the test scripts in this directory still build
pre-round-12 SE events (writePolicy on Icp, governancePolicy on Est-v1, SEL
prefix derived from policy_said). They will be rewritten to drive the
round-12 CLI surface in #147 (CLI + script migration). Until then the
production lint stays strict and the test scripts compile/run as-is (they
are runtime-broken vs. round-12 servers, but that's deferred).

Restore those two patterns to the subtree forbid when #147 lands. The lint
infrastructure now supports per-subtree forbid files (`scripts/lint-terminology.sh`,
deepest-wins replacement semantics) — same mechanism can be used for
future short-lived exemptions.

### [Gap 5 → #147] Exchange CLI commands parked compile-clean since SE rewrite

`cmd_exchange_publish_key` / `cmd_exchange_rotate_key` (clients/cli/src/commands/exchange.rs)
return `Err("parked pending Gap 11 CLI rewrite")` on invocation. The
underlying flow assembled pre-round-12 SE events declaring `write_policy` /
`governance_policy` inline at inception and computed the SEL prefix from
`(write_policy, topic)`. Round-12 SE chains bind to an existing IEL via
the `identity` parameter. The full functional rewiring (build IEL Icp first,
feed identity into `incept_chain(identity, topic, …)`) is in #147's body
along with the test-scripts migration that drives the new CLI.

`cmd_exchange_lookup_key` and `mail send` use the same pre-round-12 prefix
derivation (`compute_sad_event_prefix(write_policy, …)`) and are runtime-
broken vs. round-12 servers but compile clean. They surface wrong prefixes
silently rather than erroring; #147 fixes both alongside publish/rotate.

`exchange_write_policy` helper in `clients/cli/src/helpers.rs` builds a
single-endorser policy SAD object (Custody-style write_policy SAID); the
helper's name is consistent with Custody's field naming and stays.

### [Gap 8 → end-of-round verification] Phase-1 anti-entropy unit + integration tests deferred

The Gap 8 plan asks for:
- Unit tests for the new `NoOp` branch.
- Unit tests for the post-sync state check.
- An integration test where a forwarded chain is rejected at the sink
  (mock policy resolver) and the local stale entry stays queued for retry
  rather than being cleared.

Implementation reality: the SEL Phase 1 task is an inline async closure
inside `run_sad_anti_entropy_loop` (`services/gossip/src/sync.rs`). Unit-
testing the dispatch arms requires extracting the closure into a
standalone function — a meaningful refactor with API-shape implications
on adjacent KEL Phase 1 code. The integration test needs a mock SADStore
returning HTTP 2xx but rejecting at verification time, plus testcontainer
scaffolding none of the existing gossip tests rely on (the file's tests
are constants/error-wrapping/handler-lifecycle only — KEL Phase 1 itself
has no comparable unit tests).

Given (a) KEL Phase 1 — the architectural reference — has no unit tests
for the same dispatch shape, (b) the Heisenbug-carry-forward verification
step at end-of-round explicitly exercises this path under load with
50+ test-sadstore.sh runs, and (c) Gap 9 lands the test-harness
convergence wait that makes deployment-test failures attributable, the
testing burden is best paid through the deployment-test sweep rather
than redundant unit/integration tests.

If the deployment-test sweep surfaces a regression in Gap 8's logic
(NoOp incorrectly clearing a stale entry, or HTTP-success-but-not-
advanced incorrectly declaring Repaired), revisit and add the unit
tests then. Until then this is documented work-skipped, not work-missed.

(resolved by Gap 6 — see Resolved section)

### [Gap 0 → Gap 0] `IelChainPosition` shape extended beyond plan's suggestion

Plan suggested `{ version: u64, branch_marker: Option<BranchId> }`.
Shipped: `{ version: u64, kind: IdentityEventKind, said: cesr::Digest256,
branch_marker: Option<cesr::Digest256> }`.

Added `kind` and `said` because the canonical IEL sort key is
`(version ASC, kind sort_priority ASC, said ASC)` — `try_cmp` needs all
three to break ties correctly within a version. Plan said "suggested"; this
is a reasonable elaboration, not a contradiction. Logged for visibility, not
because it needs resolution.

---

(resolved by Gap 4 — see Resolved section)

(both resolved by Gap 5 — see Resolved section)

(resolved by Gap 5 — see Resolved section)

### [Gap 1 → standalone] `lib/policy/src/identity_chain.rs` deleted

The pre-round-12 SE-based identity-chain primitive (`create_identity_chain`,
`advance_identity_chain`, `compute_identity_prefix`, `IDENTITY_CHAIN_TOPIC`)
was tightly coupled to SE's dropped policy fields and is structurally
superseded by IEL in round 12. Removed entirely (and from
`lib/policy/src/lib.rs`'s re-exports). No external consumers existed —
verified by grep before deletion.

The `UnreachableIelResolver` test fake added in Gap 0 went with it.
Gap 2's verifier tests will define narrower per-test fakes inside their
own test modules, matching the existing per-file `PolicyChecker` fake
pattern (`lib/kels/src/types/sad/verification.rs`,
`lib/kels/src/types/iel/verification.rs`, etc.).

(resolved by Gap 3 — see Resolved section)

(resolved by Gap 4 — see Resolved section)

(Gap 10a→10b resolved — see Resolved section)

### [Gap 10b — open] 5 sealed-divergent tests `#[ignore]`'d as single-node-untestable

The round-12 plan calls for a 5-test family covering the
sealed-divergent routing matrix:

- `sealed_divergent_chain_accepts_cnt_terminates_with_contested`
- `sealed_divergent_chain_rejects_dec_with_contest_required`
- `sealed_divergent_chain_rejects_upd_with_contest_required`
- `sealed_divergent_chain_rejects_sea_with_contest_required`
- `sealed_divergent_chain_rejects_rpr_with_contest_required`

All five `#[ignore]`'d in single-node testing because the
sealed-divergent state — defined as
`first_divergent_version <= last_governance_version` — requires a fork
at-or-behind the seal, but `SadEventRepository::save_batch` rejects
exactly that case ("Cannot fork at version X — sealed by evaluation
at version Y"). In production the state arises transiently across
federation when node-A authors a Sea at the same version where node-B
authored a competing Upd before the two synced; single-node tests
can't reproduce that race.

A future expansion could either (a) add a test-only insert API that
bypasses the seal-check, or (b) build a 2-SADStore harness with
gossip wiring. Until then the routing branches are exercised at code
review (Gap 4 routing matrix) and via the Heisenbug deployment-test
sweep.

### [Gap 10b — open] 4 gossip-propagation tests deferred to deployment-test

The round-12 plan also calls for 4 gossip-propagation tests:

- `gossip_full_chain_appends_to_empty_sink`
- `gossip_propagates_cnt_to_divergent_sink`
- `gossip_propagates_cnt_to_active_sink`
- `gossip_propagates_dec_to_active_sink`

These need a 2-SADStore harness with the gossip mesh wired up
(allowlist setup, peer-state machine, the gossip background loop
running). That's significantly outside the existing harness's scope
and the plan's "covered by Gap 9's harness convergence wait + the
Heisenbug deployment-test sweep" framing applies.

### [Gap 10b → next k8s test-client update] multi-node cases owed to test-sadstore.sh

When `clients/test/scripts/test-sadstore.sh` (the k8s deployment-test
script) gets its next round-12 expansion pass, ensure the multi-node
cases this Gap 10b couldn't reach are covered there. Two families:

1. **Sealed-divergent routing matrix** (5 cases — see Open section
   above). In k8s the state arises naturally: node-A submits a Sea
   while node-B submits a competing Upd at the same version; gossip
   delivers them out of order and the receiver creates the
   sealed-divergent state. Add scenarios that:
   - Cnt on sealed-divergent → lands.
   - Dec / Upd / Sea / Rpr on sealed-divergent → ContestRequired.

2. **Gossip propagation of terminal events** (4 cases — see Open
   section above). The current `test-sadstore.sh` already exercises
   linear-chain gossip propagation; add:
   - Cnt propagates to a divergent sink.
   - Cnt propagates to an active sink (matrix Contested→Active).
   - Dec propagates to an active sink.
   - Full-chain append to an empty sink (already implicit but pin
     explicitly).

Both groups depend on the test harness having ≥2 sadstore nodes (the
existing FEDERATED=true mode does); just need the scenario logic
added.

- `incept_lands_chain_with_upd_in_same_batch` (happy path).
- `incept_alone_rejected_with_incomplete_inception` (inception batch rule).
- `update_rejects_when_anchor_not_anchored_under_iel_resolved_auth_policy`
  (HARD Upd auth — replaces dual-policy SEL's soft-Upd behavior).
- `submit_lands_govfailed_cnt_chain_becomes_contested_with_policy_unsatisfied`
  (live-handler govfail elevation).
- `submit_lands_govfailed_dec_chain_becomes_decommissioned_with_policy_unsatisfied`
  (live-handler govfail elevation).
- `unsealed_divergent_chain_rejects_cnt_with_repair_required`
  (sealed/unsealed routing matrix).
- `unsealed_divergent_chain_rejects_dec_with_repair_required`
  (sealed/unsealed routing matrix).
- `contest_terminates_chain` (builder.contest happy path + ContestedSel
  refusal).
- `decommission_terminates_chain` (builder.decommission happy path +
  DecommissionedSel refusal).
- `builder_decommission_fail_fasts_on_divergent_chain`
  (DecommissionBlockedByDivergence pre-flight).

**Deferred to Gap 10b** (~20 remaining cases per the plan's full
taxonomy):
- IelDivergent soft-Cnt / soft-Dec live-handler cases (paired with
  the anchor-fail soft cases above).
- Sealed-divergent acceptance: Cnt lands on sealed-divergent, Rpr
  rejected with ContestRequired, Dec rejected with ContestRequired,
  Upd/Sea rejected with ContestRequired.
- Algorithmic ContestRequired (linear-sealed-past-version Upd/Sea).
- Repair tests (existing `repair_tests.rs` covers most via the
  schema layer; full builder-level `repair_resolves_divergence...`
  belongs here).
- BadIdentityBinding cases (unknown identity_event SAID, prefix
  mismatch, monotonic regression).
- Compute-prefix contract pin (`compute_sad_event_prefix_uses_identity_and_topic`).
- Gossip propagation cases (4 cases: full-chain to empty sink,
  Cnt to divergent sink, Cnt to active sink, Dec to active sink).
- `active_sealed_chain_accepts_dec_terminates_decommissioned`
  (seal-past-version Dec subcase).
- `verifier_terminal_flags_content_based_on_govfailed_cnt`
  (already covered partially by the unit tests in Gap 2 + the
  govfailed-Cnt live-handler test in Gap 10a).

The stub IEL-event SAID literals in `store/sad.rs` / `sync.rs` /
`repair_tests.rs` (from Gap 1) remain — those tests don't exercise
builder semantics; the literals are stable noise. Optional Gap 10b
polish, not required.

## Resolved

- **[Pre-existing → round-12 third follow-up commit 2] HttpSadSink/HttpIelSink
  409 silent-skip + server-side response-code semantics** — The original
  entry called out `HttpSadSink::store_page` silently treating `409
  CONFLICT` as success. Audit + fix shipped together:

  **Audit conclusion.** All `StatusCode::CONFLICT` sites in
  `submit_sad_events` (`services/sadstore/src/handlers.rs`) and
  `submit_identity_events` are genuine client-vs-state rejections, not
  duplicate-idempotent paths — the dedup short-circuits at the SE and
  IEL submit handlers return `201 CREATED` with `applied=false`. **No
  duplicate-case path** surfaced in the audit. Two semantic classes
  inside the existing 409 sites:

  1. *Real client-vs-state conflicts* — `truncate_and_replace` failing
     repair preconditions (SE), `save_batch` rejecting sealed-fork or
     divergent-append (SE+IEL). Stay 409, surface client-side as
     `KelsError::ServerError(_, ErrorCode::Conflict)`.
  2. *Server-internal integrity failures* — `verify_existing_chain` /
     `verify_existing_iel_chain` rejection on already-stored data, and
     post-dedup-advisory-locked `insert_event` failures for Cnt/Dec.
     Now 500 via the new `KelsError::ChainVerificationFailed(String)`
     variant; client surfaces `ServerError(_, ErrorCode::InternalError)`
     with body containing the variant's Display prefix
     `"Chain verification failed: …"`. The split lets federation peers
     and operators distinguish DB integrity loss / tampering from
     routine client-vs-state conflicts.

  **Asymmetry surfaced + fixed.** `HttpIelSink::store_page` swallowed
  *both* 409 and 403 silently — wider hole than `HttpSadSink::store_page`'s
  409-only silent-skip. The 403 silent-skip masked real failures
  (`policy_satisfied=false`, divergent-rejection) alongside its
  intended gossip-race-already-terminal idempotency. Fixed at the
  server-side via 200-with-indicator (Option C):

  - Server-side terminal-state gates in both handlers now return
    `200 OK` with `SubmitIdentityEventsResponse.terminal=Some(_)` /
    `SubmitSadEventsResponse.terminal=Some(_)` instead of `403`.
    `IdentityEventTerminalState` / `SadEventTerminalState` enums
    (`Contested` | `Decommissioned`) live in
    `lib/kels/src/types/{iel,sad}/request.rs`.
  - Sinks (`HttpSadSink`, `HttpIelSink`) drop their CONFLICT/FORBIDDEN
    silent-skips entirely; gossip-relay idempotency now flows through
    `200 OK + terminal: Some(_)` (the 2xx path drains the body and
    returns Ok). 403 stays for genuine failures and propagates as
    `ServerError(_, ErrorCode::InternalError)`.
  - 409 → `ErrorCode::Conflict` mapping added to all three submit
    paths (`HttpSadSink::store_page`, `HttpIelSink::store_page`,
    `SadStoreClient::submit_{sad,identity}_events`).
  - Owner-side builder API: `FlushIdentityOutcome` /
    `FlushOutcome` extended with
    `terminal: Option<{Identity,Sad}EventTerminalState>`. When set,
    `flush()` skips local-store write-through and `absorb_pending`
    so callers can reconcile state. SE side fixes a previously-quiet
    bug: SE gossip relays into a remote with a terminal SE chain
    used to `Err` on 403 (no SE silent-skip existed), so SE now
    matches IEL's gossip-race-already-terminal idempotency.

  **Tests.** Coverage spans the SE/IEL × conflict-409 / integrity-500 /
  terminal-200-with-indicator matrix:

  - **Terminal-200 (SE+IEL).** 7 existing terminal-state-gate tests
    in `services/sadstore/tests/{sad,identity}_builder_tests.rs`
    updated to assert `Ok(response)` with
    `response.terminal == Some(_)` instead of the prior
    `assert_err_contains` on the 403 text body.
  - **Conflict-409 wire-mapping (SE+IEL).** `wiremock`-backed unit
    tests in `lib/kels/src/types/{sad,iel}/sync.rs::tests` and
    `lib/kels/src/client/sadstore.rs::tests` pin
    409 → `ServerError(_, ErrorCode::Conflict)` for both sinks
    (`HttpSadSink`, `HttpIelSink`) and both typed-client methods
    (`SadStoreClient::submit_{sad,identity}_events`). Server-side
    conflict-409 paths in the submit handlers (`save_batch`
    sealed-fork, `truncate_and_replace` repair preconditions) are
    pre-screened by the routing matrix's
    algorithmic-`ContestRequired` check and divergent-rejection
    branches, so the typed-mapping unit tests are the actionable
    contract for callers; if those defense-in-depth paths ever fire,
    callers branch on `Conflict` without parsing the error body.
  - **Integrity-500 (SE+IEL).** Direct-DB-tampering integration tests
    `submit_returns_500_when_existing_se_chain_fails_reverification`
    and `submit_returns_500_when_existing_iel_chain_fails_reverification`
    in the respective `*_builder_tests.rs` files: corrupt a stored
    event row's `version` column without updating its `said`, submit
    a fresh event, assert the response is
    `Err(ServerError(body, ErrorCode::InternalError))` with
    `body.starts_with("Chain verification failed:")`. The IEL test
    extends the IEL harness with `sad_db_url` (mirroring the SE
    harness) for raw sqlx access. Parallel 500-mapping unit tests
    (mocked `Chain verification failed:` body) sit alongside the
    409 unit tests in the same files and pin the wire-mapping for
    typed callers. `KelsError::ChainVerificationFailed` covered by
    the variant Display test in
    `lib/kels/src/error.rs::tests::test_error_variants_display`.

- **[Round-12 review fix → resolved] IEL verifier + walker structural extraction** —
  Eliminates the page-walk + queried/satisfied registration triplication
  across `AnchoredIelResolver::verification_for`,
  `RepositoryIelResolver::is_satisfied`, and the existing
  `verify_identity_events` / `iel_completed_verification` helpers.
  Adds `verify_identity_events_with_queried` and
  `iel_completed_verification_with_queried` in
  `lib/kels/src/types/iel/sync.rs`; existing helpers become thin
  wrappers (zero behavior change for legacy callers; new callers
  register `queried_saids` upfront).

  - `AnchoredIelResolver::verification_for` collapses to a one-liner
    delegating to `verify_identity_events_with_queried`.
  - `RepositoryIelResolver::is_satisfied` likewise — now driven through
    a new private `RepositoryIelPageSource` adapter wrapping the IEL
    repo's connection pool. **Closes Important #1** (multi-page IEL
    walk duplicate-event bug at page boundaries): the inline pool walk
    that lacked the strict-greater-than `(version, kind, said)`
    post-filter is gone; the new adapter goes through
    `IdentityEventRepository::fetch_iel_page_pool` (added in
    `services/sadstore/src/repository.rs`), which mirrors
    `fetch_iel_page`'s post-filter exactly.
  - `walk_back_to_branch_identity` made `pub` in
    `lib/kels/src/iel_resolver.rs` so the in-process resolver shares
    the algorithm; `RepositoryIelResolver` materializes the IEL chain
    once via a new `materialize_iel_chain` and feeds the shared walker
    (drops the per-step `fetch_event_by_said` walk and ~90 lines of
    duplicated walk-back logic).
  - `collect_all_events` (HTTP variant) now fail-secures on `max_pages`
    overrun (**M11 fix**) so the walk-back never operates on an
    incomplete chain map.
  - `collect_identity_event_saids` (HTTP variant) returns
    `Ok(collected)` instead of `InvalidKel` on empty mid-walk pages
    (**M1 fix**) — now consistent with the loader sibling.

- **[Round-12 review fix → resolved] SE pre-walk + soft-fail predicate + β-ordering documentation** —
  - SE handler's inline pre-walk replaced with a private helper
    `collect_se_chain_identity_event_saids_via_tx` colocated with
    `verify_existing_chain` in `services/sadstore/src/handlers.rs`.
    Mirrors `kels_core::collect_identity_event_saids[_from_loader]`
    for the transactional repository path. Fail-secures on `max_pages`
    overrun (was silently using a partial set, which would soft-fail
    every binding past the limit).
  - `auth_soft_eligible` predicate in `SelVerifier::flush_generation`
    split into named pieces (`terminal_soft` for the round-11 baseline;
    `post_divergence_soft` for the round-12 third-follow-up rule). Each
    rule independently documented; their union still drives gate severity.
  - β-ordering rationale (Step 1 fetch / Step 2 resolve_*_at IelDivergent
    / Step 3 is_satisfied / Step 4 is_anchored / Step 5 monotonic-ratchet)
    documented inline at the SE per-event auth gate sequence — explains
    why both the IelDivergent gate and the `is_satisfied` gate stay
    wired (defense-in-depth + complementary coverage).

- **[Round-12 review fix → resolved] Test coverage closeout** —
  - Post-SE-divergence cell tests added in
    `lib/kels/src/types/sad/verification.rs`: Sea / Rpr post-SE-div
    anchor-fail soft-lands; Upd post-SE-div IelDivergent soft-lands;
    Upd post-SE-div BadIdentityBinding stays HARD; Upd post-SE-div
    auth-pass advances ratchet but is excluded from `satisfied_saids`.
    The is_satisfied=false post-SE-div cell is consciously skipped at
    the unit level (the existing fake's `is_satisfied` doesn't model
    auth-fail-pre-divergence; covered by the integration tests via the
    full IEL verifier path).
  - IEL send-side tests added in `lib/kels/src/types/iel/sync.rs`:
    unrecovered (no Cnt) divergent partitioning (longer chain first,
    fork event from shorter); multi-page contested partitioning
    (pre-divergence + non-cnt chain spans multiple pages); page-boundary
    divergence detection (held-back-event strategy bridges same-version
    overlap split across pages).
  - RepositoryIelResolver V=D+1 walk-back integration test added in
    `services/sadstore/tests/sad_builder_tests.rs`: a Cnt extending one
    of the divergent v=1 Evls lands at v=2; its `branch_marker` traces
    back through `previous` to the v=1 ancestor on the same branch.
    Confirms the materialize-then-walk flow against the real
    Postgres-backed repo.



- **[Pre-round-12 IEL primitive gap → Round-12 third follow-up commit 4]
  IEL send-side divergence partitioning implemented** — `send_divergent_iel_events`
  added at `lib/kels/src/types/iel/sync.rs`, mirroring KEL's
  `send_divergent_events` (`lib/kels/src/types/kel/sync.rs:517`).

  Partitions post-divergence events into `chain_a` / `chain_b` by
  tracing forward from each fork event. **Contested** case (Cnt on
  either branch): pre-divergence + non-cnt chain go as paged appends,
  cnt-chain as an atomic single-page batch (errors if cnt-chain exceeds
  `MINIMUM_PAGE_SIZE` — indicates DB tampering). **Unrecovered**
  (defensive — production routing rejects this state with
  `ContestRequired`): longer chain as paged appends, then the fork
  event from the shorter chain establishes divergence at the receiver.

  `forward_identity_events` refactored from a flat paging loop into a
  thin wrapper around new private `transfer_identity_events`, which
  detects divergence at page boundaries via the held-back-event
  strategy (mirrors SE's `transfer_sad_events`) and invokes
  `send_divergent_iel_events` on detection.

  Removes the pre-round-12 asymmetry where `forward_identity_events`
  relied on the receiver's submit handler to "figure out" complex
  batches — sender-side composition is now the cryptographic-soundness
  gate, matching the round-12 design's explicit framing in
  `docs/design/iel/merge.md §Gossip Send-Side Partitioning`.
  KEL/SEL/IEL symmetry restored.

  Test coverage: 2 unit tests in `lib/kels/src/types/iel/sync.rs` test
  module — contested-divergent partitioning order + linear-passthrough
  unchanged.

- **[Gap 1 → 40c9ef2] `SadEvent::icp` parameter ordering corrected** —
  Gap 1 (commit `baadf7e`) shipped `SadEvent::icp(topic, identity)` —
  topic first. Plan §Gap 1 line 218 specified `(identity, topic)` —
  identity first. Every gap from 1 through 11 used the topic-first
  ordering. The round-12 cleanups commit `40c9ef2` flipped the
  parameter order to match the plan and rewrote ~20 call sites.
  Implementation now matches plan. Process deviation: the ordering
  divergence existed across most of round 12 and was resolved
  silently — should have been recorded at the time. Logged here per
  the deviations log's own preamble.

- **[Gap 11 → 7a2f374] Gap 11 doc-sweep spilled to a follow-up commit**
  — Gap 11 (`d741f3e`, "sel identity gap 11 - docs & terminology")
  shipped the bulk of Gap 11's design-doc / terminology work but left
  several round-12 doc updates unfinished. The round-12 documentation
  sweep follow-up commit `7a2f374` finished the spillover:
  - `AGENTS.md` SEL paragraph rewrite (Gap 11 ask line 487).
  - `README.md` SEL identity-rooted note (Gap 11 ask line 488).
  - `docs/design/sel/event-log.md` Server-Observable Case Taxonomy
    table sealed/unsealed split (Gap 11 ask line 495).
  - `docs/design/sel/reconciliation.md` Active row Rpr cell rewrite
    (Gap 11 ask line 496).

  Process deviation: the plan called for "one commit per numbered gap";
  Gap 11's doc work landing across two commits violates that. Logged
  here per the deviations log's standard for "every divergence."

- **[Gap 0 → Round-12 third follow-up commit 2] `iel_chain_positions`
  post-divergence walk-back implemented** — both `AnchoredIelResolver`
  (`lib/kels/src/iel_resolver.rs`) and `RepositoryIelResolver`
  (`services/sadstore/src/iel_resolver.rs`) now walk `event.previous`
  from each post-divergence SAID until reaching the event at version
  `first_divergent_version`; that ancestor's SAID becomes the branch
  identity. O(K·D) per-batch with no memoization (D≈1–2 in production).
  Defensive `BadIdentityBinding` on chain-integrity breaches mid-walk
  (event.previous=None on a non-Icp, version skipping past D, missing
  ancestor, cross-IEL contamination, step-bound exceeded).

  Two events on the same post-divergence branch now share the same
  `branch_marker` and compare via canonical chain order (`Less` /
  `Greater`); two events on different branches surface `IelDivergent`.
  Approximation `branch_marker = Some(event.said)` retired.

  `RepositoryIelResolver` extracted from `services/sadstore/src/handlers.rs`
  into its own pub module so integration tests can drive it directly
  against the live Postgres-backed IEL repository.

  Test coverage:
  - `lib/kels/src/iel_resolver.rs` test module — 3 unit tests against
    a fake `PagedIelSource` (V=D base case, V=D+1 walk, pre-divergence
    no-marker).
  - `services/sadstore/tests/sad_builder_tests.rs::repository_walk_back_different_branches_compares_iel_divergent`
    — V=D base case against the real IEL repository. The V=D+1 walk
    case is unit-tested at the AnchoredIelResolver level (same algorithm
    shape) rather than at the integration level: injecting a V=D+1
    event would require bypassing IEL routing (which rejects
    post-divergence submissions with `ContestRequired`); the
    integration value-add is small relative to the harness cost.

- **[Gap 10a → Gap 10b] critical-subset → broader taxonomy** — Gap 10a
  shipped 10 critical tests + the harness; Gap 10b extended to 23
  passing tests covering the round-12 plan's prescribed taxonomy minus
  the 5 sealed-divergent matrix cases (single-node-untestable, see
  Open section) and the 4 gossip-propagation cases (deferred to
  deployment-test sweep, see Open section).

  Gap 10b additions (13 new tests):
  - `compute_sad_event_prefix_uses_identity_and_topic` — pure-Rust
    contract pin (no harness needed).
  - `update_rejects_when_identity_event_unknown_in_iel` —
    `BadIdentityBinding` (SAID-not-found).
  - `update_rejects_when_identity_event_prefix_mismatches_branch_identity`
    — `BadIdentityBinding` (cross-IEL contamination).
  - `update_rejects_when_identity_event_regresses_monotonic_ratchet`
    — `BadIdentityBinding(monotonic)`.
  - `update_rejects_when_bound_iel_event_lives_on_divergent_iel_branch`
    — HARD `IelDivergent` for Upd.
  - `submit_lands_iel_divergent_cnt_chain_becomes_contested_with_policy_unsatisfied`
    — SOFT `IelDivergent` for Cnt.
  - `submit_lands_iel_divergent_dec_chain_becomes_decommissioned_with_policy_unsatisfied`
    — SOFT `IelDivergent` for Dec.
  - `pre_divergence_iel_event_resolves_even_when_iel_is_divergent`
    — pre-divergence shared event resolves cleanly even on divergent IEL.
  - `seal_advances_last_governance_version_and_ratchets`.
  - `repair_resolves_divergence_archives_adversary_events`.
  - `contest_after_seal_via_algorithmic_trigger` — algorithmic
    `ContestRequired` (Upd/Sea at version <= seal on linear chain).
  - `active_sealed_chain_accepts_dec_terminates_decommissioned` —
    Dec on linear sealed chain (post-seal-version) lands cleanly,
    pinning the algorithmic-trigger exclusion for terminal kinds.
  - `update_appends_with_identity_event_binding_to_later_iel_evl` —
    binding to a post-Icp IEL Evl advances the SE ratchet.

  Helpers added: `establish_se_chain`, `evolve_iel`,
  `create_iel_divergence` (returns the new policies for verifier
  policy-resolver seeding), `seal_se_chain`, `create_se_divergence`,
  `verify_chain_with_policies`. The IEL divergence helper differentiates
  the two competing Evls via fake-endorser SAIDs (Policy::build rejects
  poison+immune as mutually exclusive).

- **[Gaps 0/4/5 → Gap 6] error variant placeholders** — Gap 6 added the
  three round-12 variants and swept all placeholder call sites:
  - `IncompleteInception(String)` — handler at
    `services/sadstore/src/handlers.rs::submit_sad_events` returns the
    real variant (via `err.to_string()` for the HTTP body).
  - `BadIdentityBinding(String)` — replaces the Gap-0 `InvalidIel`
    placeholders in both `AnchoredIelResolver` (lib/kels) and
    `RepositoryIelResolver` (services/sadstore handlers); also replaces
    the verifier's `VerificationFailed` site for monotonic-ratchet
    regression and the unreachable cross-branch divergence case;
    test fakes updated (`FakeIelResolver` in
    `lib/kels/src/types/sad/verification.rs` test module); two
    verifier tests updated to assert `BadIdentityBinding` instead of
    `InvalidIel` / fragment-only.
  - `DecommissionBlockedByDivergence(String)` — replaces Gap-5's
    `InvalidKel("decommission blocked by divergence …")` placeholder
    in `SadEventBuilder::decommission` and the unreachable
    defense-in-depth path in `choose_terminal_anchor`.
  - `Display` impl + the test-variants list in `error.rs` were
    extended with the three new variants. `contest_required_sel`
    helper already existed (Gap 1).
  - `PendingEventsBlockRepair` SE-side: no SE call sites exist
    (already removed when sad_builder.rs was stubbed in Gap 1 and
    again rebuilt in Gap 5). Variant stays for KEL-side until #152.

- **[Gap 1 → Gap 5] `sad_builder.rs` stub** — Gap 5 shipped the round-12
  builder end-to-end:
  - Single `incept_chain(identity, topic, initial_content)` atomically
    stages `[Icp, Upd]` (per the inception batch rule). Drops both
    pre-round-12 incept paths.
  - `update(content)`, `seal()` (replaces `evaluate(...)`), `repair()`
    (boundary derivation unchanged; identity_event binding via IEL
    fetch). All async because each fetches the current IEL binding.
  - `contest()` and `decommission()` lifecycle ops with pending bundling.
    `contest` does NOT pre-flight on divergent (Cnt is valid on
    sealed-divergent — the server routes); `decommission` fail-fasts
    on any divergent chain (the matrix's RepairRequired/ContestRequired
    rules don't apply locally).
  - `verify_server_chain_pre_action` helper extracted, mirroring
    `IdentityEventBuilder::verify_server_chain_pre_action`. Used by
    `repair`, `contest`, and `decommission` for full server-chain
    pre-flight verification.
  - Lower-SAID branch tip rule for `Cnt` on divergent SE chains
    (mirrors IEL's rule at `docs/design/iel/event-log.md:174`).
  - **Field surface change**: dropped the Gap-2 `iel_resolver` field
    from `SadEventBuilder` per the plan's "Don't store a separate
    `Arc<dyn IelResolver>` field" guidance. The builder constructs an
    `AnchoredIelResolver` per-call from `sad_client`. This dropped the
    4th `iel_resolver` parameter from `new()` and `with_prefix()` —
    callers updated.
  - `flush()` rebuilds the post-repair owner-local rehydrate
    (mirrors round-10) using a fresh `AnchoredIelResolver` from
    `sad_client.as_iel_source()`.
  - `is_terminal()` accessor added (chain has terminated locally
    or per the verifier's content-based flags).
  - Test module deleted (Gap 10's responsibility) — replaced with a
    placeholder shim.

- **[Gap 0 → Gap 5] `AnchoredIelResolver` moved from lib/policy to
  lib/kels** — the impl uses only kels-core types (no policy DSL
  machinery), and the SE builder lives in lib/kels which can't import
  from lib/policy (downstream). Moving it upstream lets the builder
  construct one. The `pub use AnchoredIelResolver` re-export moved
  from `kels_policy` to `kels_core`. No external consumers existed
  before Gap 5 (verified).

- **[Gap 2 → Gap 5] CLI exchange commands parked** — `cmd_exchange_publish_key`
  and `cmd_exchange_rotate_key` returned errors with descriptive
  "parked pending Gap 11 CLI rewrite" messages. The pre-round-12 flow
  declared `write_policy` / `governance_policy` inline at inception
  and computed the SEL prefix from `(write_policy, topic)`. Round-12
  SE chains bind to an existing IEL via `identity` instead. Gap 11
  reshapes the CLI surface to feed an IEL identity into
  `incept_chain(identity, topic, initial_content)`.

- **[Gap 2 → Gap 4] handler `PlaceholderIelResolver` + repair-seal-check
  downgrade** — Gap 4 replaced both with the round-12 routing matrix:
  - `RepositoryIelResolver` (in-process; wraps `Arc<SadStoreRepository>`,
    reads `iel_events` directly via the repo's pool) supplants the
    Placeholder at both `SelVerifier::new` sites.
  - The `establishment_version` → `last_governance_version` swap is now
    moot — Gap 4's routing matrix uses `pre_batch_seal` directly
    (snapshot of `last_governance_version` *before* the verifier sees
    the new batch) for the sealed/unsealed predicate, the
    repair-past-seal guard, and the algorithmic-ContestRequired check.
  - Pre-batch state snapshot (`is_contested`, `is_decommissioned`,
    `first_divergent_version`, `last_governance_version`) collected via
    repo queries before the verifier runs, mirroring the IEL handler's
    round-11 hygiene.
  - Terminal-state gates (`ContestedSel` / `DecommissionedSel` 403s)
    fire on contested/decommissioned chains regardless of batch
    contents.
  - Inception batch rule enforced before tx-start: any batch with `Icp`
    must include `Upd` at v1 (deviation: surfaced as a generic
    `BAD_REQUEST` body fragment "incomplete inception"; Gap 6 swaps to
    `KelsError::IncompleteInception`).
  - Routing matrix per `docs/design/sel/reconciliation.md §Local
    Submissions Matrix` — `is_repair` / `is_contest` /
    `is_decommission` / non-terminal each routed against the
    sealed/unsealed predicate, with `ContestRequired` /
    `RepairRequired` rejections at the appropriate cells.
  - Algorithmic ContestRequired catches linear-sealed-past-version Upd
    / Sea (uses kind-relevant authorization gating: verifier already
    ran and returned `policy_satisfied=true` to reach this branch).
  - `SadEventRepository::insert_event` added to mirror IEL's; used by
    the contest / decommission paths to bypass `save_batch`'s
    divergent-rejection so Cnt can land on a sealed-divergent chain.

- **[Gap 1 → Gap 3] 4 schema-dependent `repair_tests.rs` cases** — Gap 3
  migrated `migrations/0001_initial.sql` in place (dropped
  `write_policy` / `governance_policy`, added NULLABLE `identity` /
  `identity_event`). All 7 `repair_tests.rs` cases now pass against the
  new schema, plus 22 `integration_tests.rs` and 13 SADStore lib tests.
  Gap 3 also added `is_contested` / `is_decommissioned` to
  `SadEventRepository` and rewired `effective_said` + `list_prefixes`
  with the round-12 terminal-state precedence
  (Decommissioned > Contested > Divergent > linear).

- **[Gap 1 → Gap 2] `verification.rs` stub** — resolved by Gap 2's full
  `SelVerifier` rebuild. New shape:
  - `SadBranchTip` carries `identity` + `last_identity_event` + the kept
    `tip` / `events_since_evaluation` / `last_governance_version`.
  - `SelVerification` exposes chain-wide `is_contested` /
    `is_decommissioned` / `last_governance_version` plus a
    `last_identity_event()` accessor (linear chains only — divergent
    chains return `None`). Reason: deriving a canonical chain-wide
    value requires comparing per-branch positions via
    `IelChainPosition::try_cmp`, which needs the prefetched-positions
    map produced by the verifier loop's pre-batch resolver call; the
    synchronous accessor has no resolver state and so can't compute
    the canonical ordering even when the underlying values would
    compare cleanly. The Update precondition (verification.rs:405-447)
    guarantees `last_identity_event` only ratchets after hard-pass on
    steps 1–4, so per-branch values are structurally pre-divergence
    or on the same non-divergent IEL and always compare cleanly — the
    limit is the accessor's API surface, not "no canonical ordering."
    Behavior is correct; the original framing was poisoning the
    durable design record.
  - `SelVerifier` walks events page by page, generation by generation;
    pre-batch IEL position fetch per generation; per-event flow per the
    plan's "Authorization resolution" steps 0–6 with the soft/hard
    mapping (Upd/Sea/Rpr HARD, Cnt/Dec SOFT, content preservation HARD,
    monotonic ratchet HARD-for-all-kinds, terminal flags content-based).
  - Test module replaced with 13 round-12 test cases covering the
    plan's test list (linear chain, ratchet advance, unknown binding,
    monotonic regression, hard anchor failure on Upd, IEL-divergent
    binding HARD on Upd / SOFT on Cnt, Sea seal advance, content
    preservation, resume, pre-divergence shared event).
  - Tests use a `FakeIelResolver` defined in the test module
    (`identity` + SAID-keyed `(version, kind, auth_policy,
    governance_policy)` map + optional `first_divergent_version`),
    matching the established per-file fake convention.
