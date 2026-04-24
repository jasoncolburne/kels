# Branch Audit: KELS-133_rename-concepts (Round 7) — 2026-04-23

Branch `KELS-133_rename-concepts` vs `main`: 105 files, 3305 insertions / 2494 deletions. Cold re-read after `/clear`. Focus: the `SadEventVerification` public accessor surface (which round 4 #2 and round 5 #3 only audited in docstring prose for one side of the role/mechanism split), the `SadStoreClient`-side doc prose for layer-2 methods (round 6 fixed one docstring at line 196, but sibling doc comments weren't re-swept), and "chain record" prose inside renamed surfaces. Total resolved cumulatively across rounds 1–6: 34.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 1        |
| Low      | 0    | 4        |

Cumulative across rounds 1–7: 39 resolved. Round 7 surfaced 5 new stragglers — 1 medium, 4 low — all doc-comment drift in surfaces the prior six rounds touched but didn't fully sweep. All resolved.

---

## Medium Priority

### ~~1. Public accessor `SadEventVerification::last_governance_version` has a mechanism-named docstring — same role/mechanism slip rounds 5 #3 and 6 #3 fixed on every companion site~~ — RESOLVED

**File:** `lib/kels/src/types/sad/event.rs:338-342`

~~```rust~~
~~/// The version of the most recent evaluated checkpoint, if any.~~
~~/// Versions at or before this are sealed by governance_policy.~~
~~pub fn last_governance_version(&self) -> Option<u64> {~~
~~    self.last_governance_version~~
~~}~~
~~```~~

~~Round 5 #3 fixed the same mechanism-for-role wording in the `PolicyChecker::satisfies` trait docstring (`verification.rs:22`): `"last checkpoint version"` → `"last governance version"`. Round 6 #3 fixed it in the repository method (`services/sadstore/src/repository.rs:269-270`): the rewrite was `"most recent evaluated checkpoint for a chain"` → `"most recent governance evaluation for a chain"`, and `"if no checkpoint exists"` → `"if no governance evaluation has been recorded"`.~~

~~The **primary public API** — the accessor on `SadEventVerification`, which is the first thing a library consumer reads when they receive a verification token — still describes itself as `"most recent evaluated checkpoint"`. This is the only reachable docstring for `last_governance_version()` from rustdoc, and it contradicts the naming convention the other two sites now enforce.~~

**Resolution:** Accessor docstring rewritten to:

```rust
/// The version of the most recent governance evaluation, if any.
/// Versions at or before this are sealed by governance_policy.
```

Matches the wording round 6 #3 settled on for the sibling repository method. `"most recent"` preserved (part of the deferred #142 semantic question — don't touch), `"sealed by governance_policy"` preserved (role-named effect), `"evaluated checkpoint"` → `"governance evaluation"` (role-named). The three companion sites (trait docstring at `verification.rs:22`, repo method at `repository.rs:269-270`, public accessor at `event.rs:338-342`) now read in the same vocabulary.

---

## Low Priority

### ~~2. Internal struct field comment for `last_governance_version` in `SelVerifier` — same mechanism-for-role wording as #1~~ — RESOLVED

**File:** `lib/kels/src/types/sad/verification.rs:85-87`

~~```rust~~
~~/// The version of the most recent evaluated checkpoint across all branches.~~
~~/// For divergent chains, this is the minimum across branches (weakest seal).~~
~~last_governance_version: Option<u64>,~~
~~```~~

~~Companion to #1. The struct field backing the accessor has the same mechanism-named doc. A crate-internal reader (who rounds 1–6's sweeps explicitly treated as in-scope — e.g., round 6 #1 fixed a crate-internal docstring in `SadStoreClient`) gets the same wrong vocabulary. The private field name itself is already role-named (`last_governance_version`); only the doc mismatches.~~

**Resolution:** Field doc rewritten to `"The version of the most recent governance evaluation across all branches."` — mirrors the accessor fix from #1. Field name and docstring now agree.

### ~~3. `SadEventVerification::prefix()` accessor docstring says `"The chain prefix"` — same pattern round 6 #5 fixed on `SadEventRepair.event_prefix`~~ — RESOLVED

**File:** `lib/kels/src/types/sad/event.rs:306-309`

~~```rust~~
~~/// The chain prefix.~~
~~pub fn prefix(&self) -> &cesr::Digest256 {~~
~~    &self.tip.prefix~~
~~}~~
~~```~~

~~Round 6 #5 identified and fixed this exact pattern on the sibling field `SadEventRepair.event_prefix`: `/// The chain prefix that was repaired.` → `/// The SEL prefix that was repaired.` The accessor `prefix()` on `SadEventVerification` has the same shape — rustdoc says "chain prefix" for a method on a type named after the SAD Event Log.~~

**Resolution:** `/// The chain prefix.` → `/// The SEL prefix.` Accessor docstring on the SEL verification token now reads in the same vocabulary as the sibling field on `SadEventRepair` (post-round-6).

### ~~4. Module doc of renamed `event.rs` still uses `"Chained records"` header and `"Chain prefix is derived"` — file's primary concept label didn't track the rename~~ — RESOLVED

**File:** `lib/kels/src/types/sad/event.rs:1-10`

~~```rust~~
~~//! SAD (Self-Addressing Data) event types for the replicated SADStore.~~
~~//!~~
~~//! Two layers:~~
~~//! - **SAD objects** — content-addressed JSON blobs stored/retrieved by SAID (MinIO).~~
~~//! - **Chained records** — versioned chains with deterministic prefix discovery and~~
~~//!   policy-based ownership. Each event references content in the SAD store via `content`.~~
~~//!~~
~~//! Chain prefix is derived from v0's `(write_policy SAID, topic)`. Prefix derivation~~
~~//! is fully deterministic: given the inception write_policy SAID and topic, anyone~~
~~//! can compute the chain prefix offline. Write_policy can evolve across versions.~~
~~```~~

~~The file was renamed `pointer.rs` → `event.rs`; the primary type is `SadEvent`; the primary concept is "SAD Event Log". But the module doc still uses `"Chained records"` as the bold-header concept label for the file's primary subject, and the following paragraph repeats `"Chain prefix is derived"` / `"compute the chain prefix offline"`.~~

**Resolution:** Module doc rewritten per the suggested form:

```rust
//! - **SAD events** — versioned event chains with deterministic prefix discovery
//!   and policy-based ownership. Each non-inception event references content in
//!   the SAD object store via `content`.
//!
//! The SEL prefix is derived from v0's `(write_policy SAID, topic)`. Prefix
//! derivation is fully deterministic: given the inception write_policy SAID
//! and topic, anyone can compute the SEL prefix offline. Write_policy can
//! evolve across versions.
```

Lead concept now matches the primary type (`SadEvent`); `"event chains"` preserved as adjective describing structural shape; `"SEL prefix"` matches the vocabulary round-6 #5 settled on for field docs.

### ~~5. Stale `"chain records"` prose across five renamed surfaces — rename updated types but left the prose~~ — RESOLVED

**File:** `lib/kels/src/client/sadstore.rs:4`, `:213`; `services/sadstore/src/handlers.rs:1092`; `services/sadstore/src/repository.rs:319`; `services/sadstore/tests/integration_tests.rs:4`; `docs/design/sadstore.md:62, 129, 133, 145, 146, 178`; `clients/test/scripts/load-sad.sh:2, 124, 191`; `services/gossip/src/bootstrap.rs:155`

~~Nine sites still use `"chain records"` or `"chain record"` prose where the renamed type is now `SadEvent`.~~

**Resolution:** `"chain records"` / `"chain record"` → `"SAD events"` / `"SAD event"` at all originally-listed sites, plus five additional matches surfaced by the post-fix confirmation grep (the sweep-completeness pass round 6 #2 established):

- `lib/kels/src/client/sadstore.rs:4`: `Layer 2 (chain records)` → `Layer 2 (SAD events)`
- `lib/kels/src/client/sadstore.rs:213`: `/// Fetch a page of chain records by prefix.` → `/// Fetch a page of SAD events by prefix.`
- `services/sadstore/src/handlers.rs:1092`: `/// Page through existing chain records in a transaction, ...` → `/// Page through existing SAD events in a transaction, ...`
- `services/sadstore/src/repository.rs:319`: `/// Get chain records within an existing transaction.` → `/// Get SAD events within an existing transaction.`
- `services/sadstore/tests/integration_tests.rs:4`: `chain record submission/fetch` → `SAD event submission/fetch`
- `docs/design/sadstore.md:62`: `**Chain records**:` → `**SAD events**:` (additional — Authentication section)
- `docs/design/sadstore.md:129`: `### Chain Records (Layer 2)` → `### SAD Events (Layer 2)` (additional — subsection header)
- `docs/design/sadstore.md:133`: API-table `"Submit chain records ..."` → `"Submit SAD events ..."`
- `docs/design/sadstore.md:145-146`: `Create chain record` / `submit the chain record` → `Create SAD event` / `submit the SAD event`
- `docs/design/sadstore.md:178`: `fetch chain records + content` → `fetch SAD events + content`
- `clients/test/scripts/load-sad.sh:2`: `SAD objects and chain records` → `SAD objects and SAD events` (additional — header comment)
- `clients/test/scripts/load-sad.sh:124`: `Build chain records: v0 ...` → `Build SAD events: v0 ...` (additional — inline comment)
- `clients/test/scripts/load-sad.sh:191`: `chain record submit failed` → `SAD event submit failed` (additional — error message)
- `services/gossip/src/bootstrap.rs:155`: `before chain record sync` → `before SAD event sync` (additional — doc comment)

Post-fix grep for `chain record|Chain record|Chained records` across the tree (excluding `docs/claudit/**`) returns zero hits. `make check` passes cleanly.

---

## Positive Observations

- **Rounds 1–6 cumulative resolutions all hold under cold reading.** Fresh greps for the round-1-through-6 artefacts (`SadPointer`, `sad_pointer`, `SadChain`, `sad_chain`, `checkpoint_policy`, `SadGossipMessage`, `SubmitPointers`, `cp_said`, `cp_version`, `chain_cp_said`, `CHECKPOINT_POLICY_SAID`, `:repair` Redis suffix, `?repair=true` query param, `test_event_kind_`, `test_sad_gossip_message`, `(transfer|verify|forward|fetch|submit|get|list)_sad_event\b` singular, `kels/v1/` non-canonical topics, `SignedSadEvent`, `NotAllowedOnPointer`, `CustodyContext::Pointer`, `\ba event\b`) all return zero hits outside `docs/claudit/**`. The 34 cumulative resolved findings remain fixed; round 7 surfaces 5 new stragglers (1 medium, 4 low) — all confined to prose the rename updated identifiers inside but didn't re-read for role vocabulary.

- **Role/mechanism split holds at every identifier and error string.** `governance_policy` reads as the role, `checkpoint` reads as the mechanism, and no identifier mixes them — `last_governance_version` (role), `MAX_NON_CHECKPOINT_RECORDS` (mechanism), `records_since_checkpoint` (mechanism count), `evaluates_governance()` (role predicate), `"sealed by checkpoint at version N"` (mechanism effect). The round-7 findings are purely about *documentation* drift inside sites that already carry role-named identifiers — fixing them is a find-and-replace, not a rename.

- **`SadEventVerification` accessor surface is the right shape.** The eight accessors (`current_record`, `current_content`, `prefix`, `write_policy`, `topic`, `policy_satisfied`, `last_governance_version`, `establishment_version`) give a library consumer exactly what they need to implement the consumer-side verification protocol, and no more. No getters for internal HashMap state, no re-exposed branch list, no leaky `is_divergent()` on the token. The token is a precise report of "what the verifier confirmed about this chain".

- **`submit_sad_events` handler is one-function auditable.** All eight gates (SAID integrity, prefix uniformity, v0 prefix derivation, custody validation, advisory-lock + dedup, rate limit, per-path verification, establishment/seal checks) live in `services/sadstore/src/handlers.rs:1144-1555`. A reader auditing the authorization model reads the function top to bottom without jumping files; both normal and repair paths share the verify-then-commit + advisory-lock envelope. The inline comment at `handlers.rs:1332-1345` that walks through the repair floor check reads cleanly post-round-3 — role-named variable `gp_version`, mechanism-named error `"sealed by checkpoint at version"` — exactly the split round 3 #3-#5 established.

- **Round-6 `SadStoreClient::submit_sad_events` fix still applies.** The rustdoc at `lib/kels/src/client/sadstore.rs:196-200` correctly describes the KEL-anchoring trust model (no per-record signatures); a library consumer reading the method's rustdoc gets the right mental model. The round-7 finding #5 stragglers in the same file are at the module-level doc (line 4) and the `fetch_sad_events` sibling (line 213), not at the method round 6 fixed.

- **Handler test matrix in `verification.rs` is complete for the R5/R6 defense-in-depth gates.** Five tests (`test_evl_evolution_rejected_does_not_advance_tracked_policy`, `test_evl_rejected_wp_does_not_advance_governance_policy`, `test_est_rejected_wp_does_not_establish_governance_policy`, `test_divergent_est_soft_fail_does_not_poison_other_branch`, `test_multi_step_evolution_rejected_keeps_seed_policy`) pin the soft-fail-blocks-advance invariant on every branch-state field. The divergent-case test explicitly documents the intentional chain-wide-vs-branch-scoped asymmetry on `establishment_version()` — the kind of comment that earns its keep under the project's default-no-comments rule.

- **`SadEventKind` enum is the cleanest form across the rename.** Five variants, three predicate methods (`evaluates_governance`, `is_repair`, `is_inception`), `as_str` / `short_name` / `from_short_name` plus `Display` / `FromStr` impls — the full enum interface fits in 90 lines of `event.rs:19-109`. The serde `rename` attributes use the canonical `kels/sad/v1/events/{icp,upd,est,evl,rpr}` namespace; the `short_name`s are the exact lowercase strings CLI tools and logs emit. A future reader who wants to know "what kinds can a SAD event be" reads one enum and is done.
