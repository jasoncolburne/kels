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

### [Issue #171 → Issue #174] Cnt-supersedes-Dec + Cnt-from-non-tip family deferred

The full Cnt operator-contestation surface across all three log primitives (KEL, IEL, SEL) requires verifier-side non-tip parent-lookup so `Cnt.previous` can resolve to any event in the chain (not just current branch tips). Two compromise-recourse modes depend on this primitive:

- **Cnt-supersedes-Dec** — the operator's recourse against forced/coerced `Dec` or post-`Dec` key compromise. `Cnt` forks from a pre-`Dec` ancestor, creating divergence at `Cnt.version` with `Dec` and `Cnt` as competing branches; chain becomes contested-terminal. The naive "Cnt extends Dec tip" linear shape (`[..., Dec@N, Cnt@N+1]`) is structurally invalid: Cnt always creates divergence, so a linear-and-contested chain shape can't exist (per `memory/project_kels_terminal_semantics.md`). Correct shape requires non-tip parent-lookup.

- **Cnt-from-non-tip on a clean linear chain** — retroactive contestation of a previously-clean chain after compromise. Operator submits `Cnt` whose `previous` points at any event in the chain at versions `0` through `N-1`; result is a divergent chain at `Cnt.version` with the contested events on one branch. KEL Mode 2 (full-key-compromise recourse where `Rec` is unavailable because the adversary controls the recovery key too) is the same primitive applied to KEL.

Both modes are structurally inseparable from #174's unified-walk primitive; the verifier needs a SAID-keyed map of chain events (or its bounded equivalent) to resolve non-tip `previous` targets in O(1) without re-walking. Until #174 lands the current implementation rejects:

- All post-`Dec` submissions including `Cnt` (extending `Dec` tip linearly is structurally invalid, and the legitimate Cnt-from-pre-Dec-ancestor shape can't be expressed).
- All `Cnt` whose `previous` is a non-tip event (parent-lookup fails on current branch tips).

Operator's recourse for forced/coerced `Dec` or full-key-compromise of a previously-clean chain is **abandon-and-re-incept** under a new prefix until #174 lands. Documented at `docs/design/iel/event-log.md §Decommissioned`, `sel/event-log.md §Decommissioned`, `kel/event-log.md §Cnt §Mode 2`.

### [Issue #171 → standalone] `insert_event` privileged-write bypass cleanup deferred

Item 6 of #171's tracker called for cleaning up the `insert_event` privileged-write path that bypasses `save_batch`'s divergent-rejection so `Cnt` / `Dec` can land on (sealed-)divergent chains. After items 4 and 5 (terminal-state gate + divergent-chain gate) lifted the chain-validity rules into the verifier, `save_batch` was supposed to accept terminals on the right divergent states cleanly, removing the privileged path.

Cleanup is still pending. `insert_event` remains called at:

- `services/sadstore/src/handlers.rs:1892` (SEL Cnt path).
- `services/sadstore/src/handlers.rs:1934` (SEL Dec path).
- `services/sadstore/src/handlers.rs:2562` (IEL Cnt path).
- `services/sadstore/src/handlers.rs:2576` (IEL Dec path).

The cleanup is blocked on the unified-walk primitive replacing the merge-engine routing matrix; defer to #174 or follow-up PR. Code-quality cleanup, not structural correctness — current implementation is functionally correct.

### [Issue #171 → standalone] Phase 2B duplicate-handler-check sweep deferred

Phase 2B of #171 enumerated six handler-side duplicate checks for deletion (each duplicates a check the verifier already performs):

- All-events-same-prefix (SEL `services/sadstore/src/handlers.rs:1503-1510`, IEL `:2301-2307`).
- Per-event `verify_said` + `validate_structure` (SEL `:1513-1521`, IEL `:2310-2325`).
- `Icp` `verify_prefix` (SEL `:1524-1532`, IEL `:2328-2336`).
- `policy_satisfied` gate post-verifier (SEL `:1844`, `:1978`, IEL `:2537`) — these are post-verifier handler reads, may be intentional defense-in-depth rather than duplicate; needs review.
- KEL `signatures.is_empty()` check (`services/kels/src/handlers.rs:401-411` block — exact line drift not re-audited at this pass).
- KEL dual-signature on recovery events (`services/kels/src/handlers.rs:401-411` block — same).

None deleted in #171. Code-quality cleanup, not structural correctness — submit handlers reduce one step further toward `parse → verifier → persist → respond` after sweep; defer to follow-up PR.

### [Issue #171 → standalone] E2E deployment-test scenarios for #171 rules deferred

#171's revised test plan called for deployment-test scenarios in `clients/test/scripts/`:

- Federation race producing divergence (multi-node).
- Tampered-DB rejection (pre-populate violating shape — e.g., `[Icp]` alone, post-terminal event — consumer rejects).
- Cross-primitive consequence: SEL bound to pre-divergence vs post-divergence IEL events.

Verifier-side rule lifts (items 1, 4, 5) are exercised at unit level + the existing heisenbug long-loop. The federation/tampered/cross-primitive scenarios add coverage for cross-node and cross-primitive trust-layer interactions that aren't reachable from a single-node harness. Defer to follow-up PR alongside the next `test-sadstore.sh` expansion pass; pair with the Gap 10b multi-node cases owed in the entry below.

### [Issue #156 → standalone] `verify_custody_write` typed-422 body retrofit deferred

#156's status-code intersection table calls for `verify_custody_write` (services/sadstore/src/handlers.rs:602) to emit a typed `DeferredDepsResponse` body for the deferrable cases:

- `MissingIelEvent` → 422 + `iel_event` dep on `resolve_identity_for_event` SAID-only failure.
- `IelDivergent` → 422 + `transient_chain_state` body.
- `MissingKelAnchor`-could-flip → 422 + `kel_anchor` dep on the anchor evaluation step.

Gap 4 only retrofitted **status codes** at this surface (services/sadstore/src/handlers.rs:665 — `custody_write_resolver_error`):

- `IelDivergent` → 422 (was 400) with the legacy text body, no `DeferredDepsResponse` shape.
- `ContestedIel` / `IelDecommissioned` → 403 (was 400). Spec-aligned permanent.
- `MissingIelEvent` (rare here, only fires from `resolve_auth_policy_at` post Gap 1's classification) → 400 with text body.
- `IdentityBindingViolation` (the SAID-not-found-in-any-IEL case from `resolve_identity_for_event`) → 400 with text body.

**Why deferred.** The `resolve_identity_for_event` call (kels_core::IelResolver::resolve_identity_for_event) takes only an event SAID and returns an identity prefix on success, or `IdentityBindingViolation` when the SAID isn't in any locally-known IEL. At that surface we don't have an `iel_prefix` to populate the `MissingDependency::IelEvent` wire shape (which requires both `iel_prefix` and `event_said`). Constructing a full DeferredDepsResponse body here means inventing a placeholder `iel_prefix` (semantically wrong — gossip drain would enrol in the wrong `pending:chain:` index) or surfacing a non-spec-shaped fallback dep type.

The high-traffic SAD-event path (submit_sad_events) is fully retrofitted; custody.write is a lower-traffic write-side custody check that the heisenbug doesn't gate on. Status codes are spec-aligned, which is the externally-observable contract.

**Resolution.** Either:
- Custody.write's wire format gets reshaped to carry `iel_prefix` alongside `iel_event_said` (pushes the gap upstream into the SAD object's `custody.write` field shape — design change).
- The deferred-deps protocol gets extended with a `MissingIelEventBySaid { event_said }` dep type that gossip drains via a SAID-only secondary index. Materially more design work.
- Accept the AE-backstop latency cost on custody.write deferrable cases and document as permanent. Lowest-cost path; consider for #82's read-side cleanup pass.

Tracked here for follow-up; not blocking the heisenbug fix or deployment validation.

### [Issue #156 → polish pass] `build_deferred_deps_response` chain_eff_said fallback to divergent synthetic

Gap 4's `build_deferred_deps_response` helper (services/sadstore/src/handlers.rs) populates `chain_eff_said` on each `MissingDependency::KelAnchor` / `MissingDependency::IelEvent` by querying:

- `state.repo.iel_events.effective_said(&iel_prefix)` for IEL deps.
- `state.kels_client.fetch_effective_said(&kel_prefix)` for KEL deps.

When either lookup returns `None` (chain truly unknown locally — zero events from that prefix), the helper falls back to `kels_core::hash_effective_said(&format!("divergent:{prefix}"))` as the chain_eff_said.

**Why this is a soft compromise.** The wire-format value is honest about the fact that we don't know the chain's state, but it's not the *actual* effective SAID the chain will eventually reach. Gossip drain's chain-update branch (Gap 6b) compares observed effective SAIDs against parked `eff_said_at_park`; if the parked value is the divergent synthetic but the chain's first-ever event committed naturally (no divergence), the drain trigger would still fire (chain advanced from divergent-synthetic to a real tip → re-eval). So the fallback is functionally correct — the parked record drains on first chain advance — but it's semantically a lie.

**Resolution.** The fix is to leave the chain_eff_said field nullable (Optional) on the wire and have gossip drain handle absent values as "drain on any chain advance for this prefix." That's a minor wire-format change. Defer to a polish pass; not blocking heisenbug.

### [Issue #167 → Issue #82] Read-enforcement positive-path + IEL-state-mapping test cells deferred

#167's test plan calls for read-enforcement cells covering:

- Authenticated fetch with valid IEL identity → 200 (positive case).
- Read against IEL not locally known → 403.
- Read against divergent IEL → 503.
- Read against contested IEL → 403.
- Read against decommissioned IEL → 403.
- Identity-current behavior: read passes after KEL rotation under the same IEL.

Shipped: `custody_read_unauthenticated_fetch_rejected` (the no-SignedRequest 403 path; `services/sadstore/tests/sad_builder_tests.rs`). The remaining cells are deferred.

**Why deferred.** All five remaining cells require the request to be authenticated, which requires:

1. A `PeerSigner` over the KEL owner's `SoftwareKeyProvider` (the existing harness moves the provider into `KeyEventBuilder`, so the test would need a parallel keyed signer).
2. The shared sadstore harness modified to pass `redis_url` to `kels_sadstore::run` (currently `None` at `services/sadstore/tests/sad_builder_tests.rs:227` — `state.redis_conn` is `None`, and `authenticate_peer_request` early-returns 403 with "Peer verification unavailable in standalone mode").
3. Direct injection of `kels:verified-peer:{prefix}` Redis entries (the harness has empty `registry_urls`, so the registry-fetch peer-cache refresh path is a no-op).

That's a ~150–250-line test-infrastructure expansion across a harness used by 30+ existing tests, with non-trivial regression risk on the unrelated SEL-builder coverage. The federation-peer-auth surface is being reworked under #82 (service access control via `AuthorizedPayload<T>`); the test infrastructure built now would be replaced.

**Code paths ARE in place.** `verify_custody_read` (`services/sadstore/src/handlers.rs`) and `custody_read_resolver_error` map `KelsError::NotFound`/`IelDivergent`/`ContestedIel`/`IelDecommissioned` to the right HTTP status codes (403/503/403/403). Code review confirms the contract; only execution-time pinning is missing.

**Resolution.** When #82 lands the credential-gated request infrastructure, retrofit the read-side cells against that. If a regression in this code path is observed before #82, the deployment-test sweep (`clients/test/scripts/test-sadstore.sh`) is the catch-all.

### [Round-12 review fix → pre-production / #152] `is_satisfied` per-call IEL re-verification

`AnchoredIelResolver::is_satisfied` and `RepositoryIelResolver::is_satisfied` each rebuild the full `IelVerification` token on every call (now via the shared `verify_identity_events_with_queried` helper). For an SEL with N v1+ events, that's N IEL walks per SEL verification — bounded by `max_pages × page_size = 4096` events per walk at default config.

For round-12 production (short chains, 1–3 v1+ events) this is fine. Pre-production with deeper SELs, this becomes a meaningful per-SEL-verification cost multiplier.

**Fix path:** cache the per-identity `IelVerification` inside the resolver (Mutex<HashMap<Digest256, IelVerification>> or OnceCell keyed by identity). Cache lifetime equals resolver lifetime equals SEL-verification lifetime, so no invalidation needed during the SEL walk. Same shape on both impls. Not blocking #147 e2e gating; tracked here for the #152 perf pass.

### [Issue #171 → Permanent design choice] SEL seal-divergence cap and IEL Evl-at-or-below-seal stay at storage layer

Items 2 and 3 of #171's Phase 2A audit enumerated the SEL seal-divergence cap (`save_batch` rejects fork-creation when `divergence_version <= last_governance_version`) and the IEL Evl-at-or-below-seal cap (analog) as candidates for verifier-side lift. After analysis (slice 1 §F2, slice 2 §F1, slice 7 binding decision 1), **the storage-layer placement is the correct design choice** per `docs/design/iel/event-log.md §Chain Validity vs Consumer Trust`:

- The verifier's job is chain-shape authenticity. A sealed-divergent chain is a structurally-authentic shape (the events landed under valid auth at submit time); the verifier accepts it.
- The trust layer (post-divergence soft-fail propagation, `policy_satisfied`, `satisfied_saids`) suspends consumer trust on post-divergence events.
- The seal-cap is a source-side write-time gate that prevents creation of consumer-trust-failing shapes. A tampered DB serving such a shape produces the same consumer trust outcome as if the cap had fired source-side: post-divergence soft-fail flips `policy_satisfied=false` for every post-divergence event.

Implementation: `services/sadstore/src/repository.rs:148-156` (SEL), `:1065-1080` (IEL). Rationale comments: `services/sadstore/src/handlers.rs:1990-1997` (SEL), `:2589-2596` (IEL). The chain-validity-vs-consumer-trust split is canonically described at `docs/design/iel/event-log.md` lines 84-94 and 111-118.

Items 2 and 3 of #171's audit are closed as design-by-intent. No follow-up scheduled.

### [Issue #167 → Issue #101] Disclosure-expansion bypasses `custody.read` on referenced sub-SADs

A public parent SAD that references a private sub-SAD by SAID can leak the private sub-SAD's content through `disclosure="*"`. The expansion path (`services/sadstore/src/expansion.rs::expand_recursive` at lines 156-236, called from `apply_disclosure_to_sad` at lines 85-100, called from `serve_sad` at `services/sadstore/src/handlers.rs:1078-1113`) reads child SADs directly from `object_store` by SAID with no consultation of `sad_objects.custody_read` on the referenced sub-SADs.

**Concrete leak shape:**

1. Author A POSTs SAD `X` with `custody.read = Some(prefix_A)`. `X` is gated; direct `fetch_sad_object` on `X.said` requires authentication and policy satisfaction.
2. Anyone POSTs SAD `Y` (public, no custody) that contains `X.said` as a string field somewhere in its tree.
3. Anyone fetches `Y` with `disclosure="*"` — `expand_recursive` hits `X.said` as a string, calls `object_store.get(X)`, embeds `X`'s content into the response. No 403; X's content leaks through Y's public fetch.

#101 covers the **inline-extraction** case (server-side `compact_sad` extracting nested SADs into object_store on POST); #101's "steel boot" prevents this for private children. **#101 does NOT cover the by-SAID-reference case** — that's this entry's surface.

**Resolution.** Either:

- Extend #101's scope to include by-reference expansion gating: `expand_recursive` consults `sad_objects.custody_read` for each referenced SAID and either skips expansion (preserves the SAID string in output) or 403s the whole disclosure when any referenced sub-SAD has non-NULL `custody_read`.
- Open a follow-up issue scoped to disclosure-expansion enforcement specifically.

The federation transitional posture (#167's "private SADs are local-only" framing) is unrelated — that constrains gossip replication, not same-process disclosure-expansion reads.

Slice 3 §S1 surfaced this; slice 7 §Item 5 (System Thesis pass) flagged it as the one fail-secure-on-uncertainty gap in PR #150's surface. Tagged here so it doesn't get lost between #101's compaction scope and #82's read-side test work.

### [Issue #156 → standalone] `try_parse_deferred_deps` distinguishes 422 from other ServerError responses by JSON-shape match alone

`try_parse_deferred_deps` at `services/gossip/src/sync.rs`:

```rust
fn try_parse_deferred_deps(err: &KelsError) -> Option<DeferredDepsResponse> {
    let KelsError::ServerError(body, ErrorCode::InternalError) = err else {
        return None;
    };
    let parsed: DeferredDepsResponse = serde_json::from_str(body).ok()?;
    if parsed.is_empty() {
        return None;
    }
    Some(parsed)
}
```

`HttpSelSink` / `HttpIelSink` / `SadStoreClient::post_sad_object` wrap any non-2xx-non-409 response into `KelsError::ServerError(text, ErrorCode::InternalError)`. The body text is JSON-decoded as `DeferredDepsResponse`; the actual HTTP status code is **lost**. Routing relies on the body shape (`kind: "rejected"` field) rather than status code.

**Why this works today.** Per slice 2's audit, the typed-422 shape is only emitted at SEL submit, IEL submit, and `verify_custody_write` boundaries; no other endpoint emits it. Until the read-side typed-422 retrofit lands (deferred to #82), the surface is bounded.

**Fragility.** A future endpoint that emits the `kind: "rejected"` shape on a non-422 status code would silently park. The contract relies on body shape, not status code.

**Resolution.** Either:

- Pin the contract that `kind: "rejected"` is only emitted on 422 across all sadstore endpoints (this entry serves that pinning).
- Thread the actual status code through the sink wrap (`HttpSelSink::store_page`, `HttpIelSink::store_page`, `SadStoreClient::post_sad_object`) so `try_parse_deferred_deps` can require status==422. Cleaner but touches the sink shape across SEL/IEL/SAD-object sinks.

Slice 4 §H1. Defer until the typed-422 retrofit on `verify_custody_write` (`[#156 → standalone]` above) or read-side cleanup (#82) makes a status-code thread feasible alongside.

### [Issue #156 → Issue #82] `MissingDependency::IelPrefix` variant is dormant pending read-side typed-422 retrofit

`MissingDependency::IelPrefix { iel_prefix }` is defined at `lib/kels/src/types/deferred_deps.rs:92-95` but no code path emits it today. Per #156's design, `iel_prefix` deps surface from read-side rejections (a SAD object's `custody.read` resolves to an unknown IEL).

Slice 3 §Read-flow walk confirmed `verify_custody_read` (`services/sadstore/src/handlers.rs:993-1034`) maps unknown-IEL to **403** via `custody_read_resolver_error` (handlers.rs:1041-1043), not to a 422 deferred-deps response. The matching `deferred_deps_to_park_inputs` arm (`services/gossip/src/sync.rs:488-499`) translates `IelPrefix` into `DepRef::TransientChain { prefix, eff_said_at_park: divergent_synthetic }` — also unreachable today.

The wire-format slot is **reserved for the read-side typed-422 retrofit deferred to #82**. Forward-compat code; not wrong, just dormant. An inline comment at the variant definition (added in this PR) points future readers here.

**Resolution.** When #82 lands authenticated read paths and the read-side rejection contract gets reshaped to emit typed-422 instead of permanent-403, the `IelPrefix` variant becomes load-bearing. Until then this is documented forward-compat.

Slice 4 §H1 + sync.rs §H2. Cross-reference: `[#167 → #82] Read-enforcement positive-path + IEL-state-mapping test cells deferred`.

### [Issue #150 → Issue #161] SEL/IEL inbound-gossip handlers diverge from KEL's recovery shape

Three asymmetries between SEL/IEL and KEL inbound-gossip handlers, all flagged by slice 5 (§F1, §F2, §F3):

**§F1 — No stale-prefix Redis hash population on non-422 forward failures.** SEL/IEL inbound handlers (`handle_sel_announcement` at `services/gossip/src/sync.rs:1039-1201`, `handle_iel_announcement` at `:1211-1367`) park on 422 (deferred-deps protocol) but on other failures (HTTP 5xx, network, peer-not-in-allowlist) just log and return. KEL's `handle_announcement` calls `record_kel_stale_prefix` on no-state-change AND on no-peer-had-events, feeding the AE Phase 1 retry queue. SEL/IEL non-422 errors fall through with no targeted retry — only Phase 2 random sampling catches them, statistically.

**§F2 — Origin-only retry, no full-peer-list iteration.** SEL/IEL inbound handlers try only the origin peer. KEL's `handle_announcement` iterates the full peer list (origin first, then others) on `forward_with_fallback` failure. For SEL/IEL, an origin-down event becomes "park if 422, drop otherwise" — drop falls to Phase 2 backstop, statistically.

**§F3 — No `forward_with_fallback` (delta-with-NotFound-fallback-to-full-fetch).** KEL AE Phase 1 routes through `sync_prefix → forward_with_fallback`. SEL/IEL AE Phase 1 calls `forward_sel_events` / `forward_identity_events` directly with `since_digest` and no NotFound fallback. SEL/IEL handle the divergence case via `use_repair = local_divergent && !remote_divergent` upfront. The missing fallback covers the case where the `since` SAID isn't on the remote because the remote did a recovery that removed it. SEL has Rpr (could rotate canonical branch); IEL has no Rpr, so for IEL the asymmetry is moot. For SEL the gap is theoretical (Rpr establishes a new branch tip but doesn't remove events) but worth flagging.

**Why these are functionally bounded today.** Deferred-deps protocol (#156) covers the dependent cases for SEL/IEL via park-and-drain; AE Phase 2 random sampling backstops the rest, eventually-consistent over O(N_pages × interval). Cost is statistical convergence latency vs. KEL's targeted retry latency.

**Resolution path.** #161 (KEL pending-bundling work, referenced from `docs/design/sel/event-log.md:157` for the `verify_server_chain_pre_repair` rename candidate) is the natural carrier for KEL/SEL/IEL recovery-shape harmonization. Slice 5 reads the asymmetries as low-risk and design-defensible (deferred-deps shifts the recovery model for SEL/IEL); pinned here so the asymmetry is documented at the deviations-log level rather than implicit.

### [Round-12 audit → Permanent design choice] `iel_chain_positions` divergence-source split (server-DB vs client-verifier)

Server-side `RepositoryIelResolver::iel_chain_positions` reads `first_divergent_version` from the DB (`services/sadstore/src/iel_resolver.rs::iel_chain_positions`); client-side `AnchoredIelResolver::iel_chain_positions` runs the verifier walk via `verification_for(identity)` and reads `verification.diverged_at_version()` (`lib/kels/src/iel_resolver.rs:319-320`).

The asymmetry is **design-intent** per `docs/design/streaming-verification-architecture.md §Operation Categories`. The system defines three categories: (1) Serving — no verification needed; (2) Consuming — must verify (verification token required); (3) Resolving — wrong answer triggers unnecessary sync, not a security hole. `iel_chain_positions` fits category 3.

The trust boundary for SEL auth is `IelResolver::is_satisfied` (slice 1 §Q4 β-ordering: step 3.5), which runs the full IEL verifier walk on both client and server impls (`sadstore/iel_resolver.rs:222-271`, `lib/kels/iel_resolver.rs:258-297`). A tampered DB lying about `first_divergent_version` causes a wrong monotonic-ratchet comparison; the next `is_satisfied` call independently runs the IEL verifier and catches the actual divergence (slice 1 §Q3 post-divergence soft-fail propagation).

Server-side perf preserved (one DB read vs. one full IEL walk per SEL event; the IEL walk cost per `iel_chain_positions` call is the same concern tracked under `[Round-12 review fix → pre-production / #152]`).

Inline comment at the storage-layer site (added in this PR) cites this entry and the streaming-verification design doc.

Slice 6 §F2 + slice 7 binding decision 3. No follow-up scheduled; placement closed as design-by-intent.

### [Gap 8 → end-of-round verification] Phase-1 anti-entropy unit + integration tests deferred

The Gap 8 plan asks for:
- Unit tests for the new `NoOp` branch.
- Unit tests for the post-sync state check.
- An integration test where a forwarded chain is rejected at the sink (mock policy resolver) and the local stale entry stays queued for retry rather than being cleared.

Implementation reality: the SEL Phase 1 task is an inline async closure inside `run_sad_anti_entropy_loop` (`services/gossip/src/sync.rs`). Unit-testing the dispatch arms requires extracting the closure into a standalone function — a meaningful refactor with API-shape implications on adjacent KEL Phase 1 code. The integration test needs a mock SADStore returning HTTP 2xx but rejecting at verification time, plus testcontainer scaffolding none of the existing gossip tests rely on (the file's tests are constants/error-wrapping/handler-lifecycle only — KEL Phase 1 itself has no comparable unit tests).

Given (a) KEL Phase 1 — the architectural reference — has no unit tests for the same dispatch shape, (b) the Heisenbug-carry-forward verification step at end-of-round explicitly exercises this path under load with 50+ test-sadstore.sh runs, and (c) Gap 9 lands the test-harness convergence wait that makes deployment-test failures attributable, the testing burden is best paid through the deployment-test sweep rather than redundant unit/integration tests.

If the deployment-test sweep surfaces a regression in Gap 8's logic (NoOp incorrectly clearing a stale entry, or HTTP-success-but-not-advanced incorrectly declaring Repaired), revisit and add the unit tests then. Until then this is documented work-skipped, not work-missed.

Tracked in #119 (Codebase Hygiene) under Test coverage.

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

- **[Round-12 doc drift → resolved]** [SEL `is_proactively_governed` flag mirrors KEL's `is_proactive_ror_compliant`](se-proactive-governance-flag.md) — added a chain-wide proactive-governance compliance flag to `SelVerifier` / `SelVerification` that flips false once any branch's `events_since_evaluation` exceeds `MAX_NON_EVALUATION_EVENTS = 63`; closes the slice 1 §F1 doc/code mismatch.

- **[Issue #156 → resolved]** [PendingMap::refresh same-SAID short-circuit](pending-refresh-same-said-shortcircuit.md) — `refresh()` now compares the candidate ParkRecord SAID against the old record and skips the cleanup+park when they match; bounds park lifetime to the original 5-minute TTL on busy chains (slice 4 §F1).

- **[Round-12 review fix → 3rd follow-up c1]** [Verifier queried/satisfied + post-divergence soft-fail propagation](verifier-queried-satisfied-and-post-divergence-soft-fail.md) — IEL/SEL caller-bounded SAID querying + `IelResolver::is_satisfied` trait method + post-divergence soft-fail propagation on both verifiers; KEL parity deferred to #152.

- **[Round-12 follow-up → resolved]** [Gap 8 PUSH-direction post-sync chose Option 1](gap-8-push-direction-post-sync-option-1.md) — PUSH skips post-sync state-advancement check (HTTP-2xx is acceptance proof); PULL keeps local-SAID re-fetch; uniform check was a copy-error from KEL Phase 1's no-PUSH branch.

- **[Gap 1 → standalone]** [lib/policy/src/identity_chain.rs deleted](identity-chain-rs-deleted.md) — pre-round-12 SEL-based identity-chain primitive removed (superseded by IEL); UnreachableIelResolver test fake removed alongside.

- **[Gap 0 → Gap 0]** [IelChainPosition shape extended beyond plan's suggestion](iel-chain-position-shape-extended.md) — added kind + said fields beyond the plan's `{version, branch_marker}` suggestion to satisfy try_cmp's canonical (version, kind, said) tie-break; permanent design choice.

- **[Gap 11 → standalone]** [write_policy not globally forbidden](write-policy-global-forbid-exempted.md) — Custody legitimately uses `write_policy` as a distinct concept from SEL auth; global forbid would have broken Custody's field naming. Plan author error scoped to SEL only.

- **[Issue #154 → Issue #154]** [Sadstore integration tests still use minio/minio:latest testcontainer](sadstore-tests-rustfs-testcontainer.md) — testcontainer fixture migrated to `rustfs/rustfs:latest` with `WaitFor::seconds(5)`; container env vars switched to `RUSTFS_ACCESS_KEY`/`RUSTFS_SECRET_KEY`/`RUSTFS_VOLUMES`/`RUSTFS_ADDRESS`/`RUSTFS_CONSOLE_ADDRESS`; locals + struct field renamed `_minio`→`_objects`.

- **[Gap 5 → #162]** [Builder-level IEL state caching retargeted to client-side caching strategy](gap-5-builder-iel-state-caching-retargeted-to-162.md) — narrow CLI-builder-cache item reframed as one instance of a broader client-side dep-graph caching strategy; #162 captures the general concern.

- **[Gap 11 → #147]** [est/evl wire-format patterns exempted at `clients/test/scripts/`](test-scripts-est-evl-exemption.md) — test-script migration rewrote every IEL/SEL script onto the round-12 CLI surface (no inline event JSON), retired the subtree `.terminology-forbidden` exemption, and added `--owner-prefix` to `sel repair` for kels-style silent-extension boundary discovery.

- **[Gap 5 → #147]** [Exchange CLI commands parked compile-clean since SEL rewrite](cli-exchange-parked-gap-5-resolved-147.md) — `cmd_exchange_publish_key` / `_rotate_key` / `_lookup_key` rewired onto round-12 SEL primitives; new `--identity <iel-prefix>` arg replaces inline `write_policy` derivation.

- **[Round-12 review fix → audit + resolver fix on KELS-126]** [Post-divergence auth-failed Evl: `policy_history` records prior tracked policies, not event-declared values](iel-resolver-verifier-adopted-policy-view.md) — KELS-126 Group A audit found one consumer (`RepositoryIelResolver::resolve_{auth,governance}_policy_at`) reading `event.auth_policy` / `event.governance_policy` directly; rerouted through a new `verification_for` helper + `verification.auth_policy_at(said)` / `governance_policy_at(said)` so the resolver consults the verifier-adopted view (mirroring `AnchoredIelResolver`). DB-tamper integration test pins the new contract.

- **[Round-12 review fix → audit confirmed clean]** [Auth-passing post-SEL-divergence event keeps `chain.policy_satisfied=true`](policy-satisfied-consumer-audit.md) — KELS-126 Group A consumer audit walked all five `.policy_satisfied()` production sites; every one answers "did any auth check fail in the walk?" rather than the divergence/terminal questions. SEL Cnt path explicitly does NOT gate on the flag (SOFT-auth design respected). No code changes needed; design contract pinned for future consumers.

- **[Pre-existing → round-12 third follow-up commit 2]** [HttpSelSink/HttpIelSink 409 silent-skip + server-side response-code semantics](sink-409-and-response-code-semantics.md) — audit + fix of all server-side 409 sites; server-internal integrity failures split off to 500 via `ChainVerificationFailed`; IEL terminal-state-gate response moved to 200-with-`terminal: Some(_)` indicator (option C); SEL side picks up symmetric idempotency.

- **[Round-12 review fix → resolved]** [IEL verifier + walker structural extraction](iel-verifier-and-walker-extraction.md) — page-walk + queried/satisfied registration triplication eliminated; closes Important #1 (multi-page IEL walk duplicate-event bug at page boundaries) plus M1 and M11.

- **[Round-12 review fix → resolved]** [SEL pre-walk + soft-fail predicate split + β-ordering documentation](se-prewalk-and-soft-fail-predicate.md) — handler pre-walk fail-secures on `max_pages`; `auth_soft_eligible` split into named pieces; β-ordering rationale documented inline.

- **[Round-12 review fix → resolved]** [Test coverage closeout](round-12-third-followup-test-coverage.md) — post-SEL-divergence cell tests, IEL send-side coverage, V=D+1 walk-back integration test.

- **[Pre-round-12 IEL primitive gap → Round-12 third follow-up commit 4]** [IEL send-side divergence partitioning implemented](iel-send-side-divergence-partitioning.md) — `send_divergent_iel_events` mirroring KEL's pattern; KEL/SEL/IEL symmetry restored.

- **[Gap 1 → 40c9ef2]** [`SadEvent::icp` parameter ordering corrected](sad-event-icp-parameter-ordering.md) — `(topic, identity)` flipped to plan-spec `(identity, topic)` in the round-12 cleanups commit.

- **[Gap 11 → 7a2f374]** [Gap 11 doc-sweep spilled to a follow-up commit](gap-11-doc-sweep-spillover.md) — AGENTS.md / README.md / event-log.md / reconciliation.md updates landed across two commits; process deviation logged.

- **[Gap 0 → Round-12 third follow-up commit 2]** [`iel_chain_positions` post-divergence walk-back implemented](iel-chain-positions-walk-back.md) — both resolvers walk `event.previous` to the divergence-version ancestor; same-branch events now compare canonically; approximation retired.

- **[Gap 10a → Gap 10b]** [critical-subset → broader taxonomy](gap-10b-test-taxonomy-expansion.md) — Gap 10b extended Gap 10a's 10 critical tests to 23 covering the round-12 plan's prescribed taxonomy minus the 5 sealed-divergent matrix cases and 4 gossip-propagation cases (both still Open).

- **[Gaps 0/4/5 → Gap 6]** [error variant placeholders](error-variant-placeholders.md) — `IncompleteInception` / `BadIdentityBinding` / `DecommissionBlockedByDivergence` variants added; placeholder call sites swept.

- **[Gap 1 → Gap 5]** [`sad_builder.rs` stub](sad-builder-rs-stub.md) — Gap 5 shipped the round-12 `SadEventBuilder` end-to-end with `incept_chain` / `update` / `seal` / `repair` / `contest` / `decommission`.

- **[Gap 0 → Gap 5]** [`AnchoredIelResolver` moved from lib/policy to lib/kels](anchored-iel-resolver-relocation.md) — relocation upstream so the SEL builder can construct it.

- **[Gap 2 → Gap 5]** [CLI exchange commands parked](cli-exchange-parked-gap-2-resolved-gap-5.md) — Gap 2's "parked pending Gap 11 CLI rewrite" stubs documented as resolved; the follow-on parking (Gap 5 → #147) is tracked as a separate Open entry.

- **[Gap 2 → Gap 4]** [handler `PlaceholderIelResolver` + repair-seal-check downgrade](placeholder-iel-resolver-and-seal-check.md) — `RepositoryIelResolver` supplants the Placeholder; round-12 routing matrix replaces the seal-check downgrade.

- **[Gap 1 → Gap 3]** [4 schema-dependent `repair_tests.rs` cases](repair-tests-schema-dependency.md) — schema migration unblocked; Gap 3 also added `is_contested` / `is_decommissioned` and rewired `effective_said`.

- **[Gap 1 → Gap 2]** [`verification.rs` stub](verification-rs-stub.md) — Gap 2's full `SelVerifier` rebuild with the round-12 branch-state shape and 13 test cases.
