# Branch Audit: KELS-133_rename-concepts (Round 6) — 2026-04-22

Branch `KELS-133_rename-concepts` vs `main`: 87 files, 3142 insertions / 2463 deletions. Cold re-read after `/clear`. Focused on areas the prior five rounds touched least: the `SadStoreClient` HTTP client doc surface, the `SadEventRepository` doc comments (the 132-line repository.rs diff), the newly-extracted `clients/cli/src/commands/mail.rs` (288 net new lines), and grammar/identifier stragglers from round-2 fixes that were declared zero-hits in earlier sweeps. Total resolved cumulatively across rounds 1–5: 29.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 1        |
| Low      | 0    | 4        |

Cumulative across rounds 1–6: 34 resolved.

---

## Medium Priority

### ~~1. `SadStoreClient::submit_sad_events` doc comment says "Submit signed SAD records" — same misnomer round 2 #5 fixed in CLI help text~~ — RESOLVED

**File:** `lib/kels/src/client/sadstore.rs:196`

~~```rust~~
~~/// Submit signed SAD records.~~
~~pub async fn submit_sad_events(&self, records: &[crate::SadEvent]) -> Result<(), KelsError> {~~
~~```~~

~~Round 2 finding #5 fixed this exact misnomer in the CLI help text (`"Submit a signed SAD event to a SEL"` → `"Submit a SAD event to a SEL"`), with the rationale that SAD events are not signed at the record level — authorization is via KEL anchoring (each record's SAID must be anchored via ixn in its endorsers' KELs per `write_policy`). The same wrong description survives unchanged in the public client method's docstring at the layer below the CLI. A library consumer reading the rustdoc gets the same misleading message the CLI consumer used to get — the trust model looks like "client supplies a signature; server verifies it" when it is actually "client submits the record; server checks anchoring against KELs of policy endorsers."~~

~~The companion docstring at `lib/kels/src/types/sad/sync.rs:101-102` is correct: `/// HTTP-based sink that submits SAD events to a SADStore service.` — no "signed" qualifier. The straggler is confined to the `SadStoreClient` method.~~

**Resolution:** Docstring rewritten to drop the wrong "signed" qualifier and explicitly call out the trust model:

```rust
/// Submit SAD events to the SADStore.
///
/// Authorization is via KEL anchoring: each record's SAID must be anchored
/// via ixn by `write_policy` endorsers in their KELs. There are no per-record
/// signatures — the server validates anchoring against the endorsers' KELs.
pub async fn submit_sad_events(&self, records: &[crate::SadEvent]) -> Result<(), KelsError> {
```

The rustdoc now matches the CLI help text post round 2 #5 and matches the companion `HttpSadSink::store_page` doc at `sync.rs:101-102`. A library consumer reading `submit_sad_events` rustdoc gets the same correct trust-model description the CLI user gets.

---

## Low Priority

### ~~2. Three `"a event"` grammar errors in Rust doc comments and one shell comment — round 2 #10 declared zero hits but only checked `docs/`~~ — RESOLVED

**File:** `services/sadstore/src/repository.rs:13`, `services/sadstore/src/repository.rs:291`, `lib/kels/src/client/sadstore.rs:258`, `clients/test/scripts/load-sad.sh:6` (plus two additional sites surfaced during the fix sweep)

~~Round 2 finding #10 fixed the `"a event"` grammar slip in `docs/endpoints.md`. Round 2's positive-observation grep claimed `a event` returned zero hits, but the sweep looked at docs only — the same slip recurs in four other places that all post-date the rename:~~

~~All four sit in or next to renamed surfaces (`SadEventRepository::exists`, `SadStoreClient::sad_event_exists`, `SaveBatchResult` doc, `load-sad.sh` post-rename header). The slip looks pre-existing — the old text presumably said `"a record"` or `"a pointer"`, and the in-place rename to `"event"` introduced the grammar error in each spot.~~

**Resolution:** `"a event"` → `"an event"` at all four originally-listed sites. A confirmation grep across the tree (excluding `docs/claudit/**`) surfaced two additional matches in test-helper doc comments that the original audit missed — fixed in the same pass for sweep completeness:

- `services/sadstore/src/repository.rs:13`: `"a event chain"` → `"an event chain"`
- `services/sadstore/src/repository.rs:291`: `"a event"` → `"an event"`
- `lib/kels/src/client/sadstore.rs:258`: `"a event"` → `"an event"`
- `clients/test/scripts/load-sad.sh:6`: `"a event chain"` → `"an event chain"`
- `lib/policy/src/identity_chain.rs:185`: `"on a event (Est kind)"` → `"on an event (Est kind)"` (test helper docstring)
- `lib/kels/src/types/sad/verification.rs:485`: `"on a event (Est kind) and increment"` → `"on an event (Est kind) and increment"` (test helper docstring)

Post-fix grep for `\ba event\b` across the tree (excluding `docs/claudit/**`) returns zero hits.

### ~~3. `SadEventRepository::last_governance_version` has a role-named function with a mechanism-named docstring — same pattern round 5 #3 fixed on the verifier side~~ — RESOLVED

**File:** `services/sadstore/src/repository.rs:269-270`

~~```rust~~
~~/// Get the version of the most recent evaluated checkpoint for a chain.~~
~~/// Returns None if no checkpoint exists.~~
~~pub async fn last_governance_version<Tx: TransactionExecutor>(~~
~~```~~

~~Round 5 finding #3 made the verifier-side docstring at `lib/kels/src/types/sad/verification.rs:22` consistently role-named (`"last checkpoint version"` → `"last governance version"`). The repo-side companion has the same shape — a role-named method (`last_governance_version`) with a mechanism-named docstring (`"most recent evaluated checkpoint"`, `"if no checkpoint exists"`) — and was missed by the round-5 sweep.~~

**Resolution:** Docstring rewritten to:

```rust
/// Get the version of the most recent governance evaluation for a chain.
/// Returns None if no governance evaluation has been recorded.
```

The role-named function (`last_governance_version`) and its docstring now agree. The `"most recent"` wording is preserved verbatim — the min/max semantics question stays deferred to #142 (round 4 #3) and is not this finding's concern. Verifier-side and repo-side `last_governance_version` callsites now read consistently for any reader cross-referencing them.

### ~~4. `lib/kels/src/types/sad/sync.rs:460` test variable `cp` is the same role/mechanism slip round 3 #3 fixed in `identity_chain.rs`~~ — RESOLVED

**File:** `lib/kels/src/types/sad/sync.rs:460-470`

~~Round 3 finding #3 fixed this exact pattern in `lib/policy/src/identity_chain.rs` — `let cp_policy = test_policy("checkpoint");` followed by `event.governance_policy = Some(cp_policy.said);` was renamed to `gp_policy` / `test_policy("governance")`. The companion in `sync.rs`'s divergence-detection test uses the bare two-letter `cp` plus the literal `b"checkpoint-policy"` digest seed for what is, by role, a governance policy.~~

~~This is distinct from the `cp_legit` / `cp_attacker` test variables in `verification.rs` that round 2 explicitly judged intentional (those names document the checkpoint-evaluation intent of the defense-in-depth attack scenarios). The `sync.rs:460` test isn't an attack scenario — it's a generic divergence-detection test whose `cp` variable is just a placeholder digest passed into `governance_policy`. Same shape as the identity_chain pattern round 3 fixed.~~

**Resolution:** `let cp = test_digest(b"checkpoint-policy");` → `let gp = test_digest(b"governance-policy");` at `sync.rs:460`, and the consumer at line 469 updated to `Some(gp)`. Variable name, digest seed string, and consumer slot all carry the role name. The `cp_legit`/`cp_attacker` variables in `verification.rs` were intentionally left alone per round 2's explicit judgment that the mechanism-naming documents the checkpoint-evaluation intent of those attack-scenario tests.

### ~~5. `SadEventRepair.event_prefix` field has a doc comment calling it `"chain prefix"` — field-vs-doc role/mechanism mismatch~~ — RESOLVED

**File:** `lib/kels/src/types/sad/repair.rs:17-18`

~~The field is `event_prefix` — the rename's role-named choice (matching `SadEvent.prefix` and the URL path `/api/v1/sad/events`). The doc comment one line above calls it `"chain prefix"`. A reader seeing `event_prefix: cesr::Digest256` in IDE autocomplete plus the rustdoc `"The chain prefix that was repaired"` gets two different mental models for the same slot — exactly the friction the rename set out to eliminate.~~

**Resolution:** `/// The chain prefix that was repaired.` → `/// The SEL prefix that was repaired.` Field name and rustdoc now describe the slot in the same vocabulary. The sibling field doc on line 26 (`/// A page of chain repairs.`) and the variant doc on line 8 (`/// Multiple repairs to the same chain are`) were intentionally left alone — those describe structural nature (a SEL is a chain), not a typed field, so they're defensible per the same reading round 2 #4 used to preserve `cp_legit`/`cp_attacker`.

---

## Positive Observations

- **Rounds 1–5 cumulative resolutions all hold under cold reading.** Fresh greps for `SadPointer`, `sad_pointer`, `SadChain`, `sad_chain`, `checkpoint_policy`, `SadGossipMessage`, `SubmitPointers`, `cp_said`, `cp_version`, `chain_cp_said`, `CHECKPOINT_POLICY_SAID`, `:repair` Redis suffix, `?repair=true` query param, `test_event_kind_`, `test_sad_gossip_message`, `(transfer|verify|forward|fetch|submit|get|list)_sad_event\b` (singular), and the `kels/v1/` non-canonical test topics all return zero hits outside `docs/claudit/**`. The 29 cumulative resolved findings remain fixed; round 6 surfaced 5 new stragglers (1 medium, 4 low) — all in surfaces the prior rounds didn't touch — plus two additional `"a event"` matches surfaced by the round-6 confirmation grep, all now resolved. Cumulative across rounds 1–6: 34 resolved.

- **`make` passes cleanly post round-6 fixes.** All workspace crates compile (`Finished dev profile in 38.34s`); no warnings introduced. Test suites pass across the modified crates — `lib/kels` tests cover the renamed `gp` / `governance-policy` divergence-detection path, `services/sadstore` tests cover `SadEventRepository::last_governance_version` (now role-named docstring) and the `truncate_and_replace` repair path, and the docstring-only edits to `SadStoreClient::submit_sad_events`, `SadEventRepair.event_prefix`, and the four `"a event"` grammar fixes are non-functional changes.

- **`SadStoreClient`'s public surface is uniform after round 5's `sel_` vs `sad_events` split.** The eight Layer-2 methods (`submit_sad_events`, `fetch_sad_events`, `sad_event_exists`, `verify_sad_events`, `fetch_sel_effective_said`, `fetch_sel_prefixes`, `fetch_sel_repairs`, `fetch_sel_repair_events`) reading top-to-bottom in `lib/kels/src/client/sadstore.rs:194-367` give a clear two-tier API: event-batch operations vs SEL-as-a-whole operations. The HTTP path strings (`/api/v1/sad/events`, `/api/v1/sad/events/fetch`, `/api/v1/sad/events/effective-said`, `/api/v1/sad/events/exists`, `/api/v1/sad/events/prefixes`, `/api/v1/sad/events/repairs`, `/api/v1/sad/events/repairs/records`) are correspondingly uniform — every Layer-2 endpoint sits under `/sad/events/`. The straggler at line 196 (finding #1) is a single doc comment inside an otherwise clean module.

- **`SadEventRepository::truncate_and_replace` has a precise inline comment justifying its layered design.** `services/sadstore/src/repository.rs:148-151` reads: `"write_policy evolution is tracked by the verifier's branch state across versions; no consistency check at the repo layer — callers must verify via SelVerifier (the handler does this with PolicyChecker after truncate_and_replace)."` This is exactly the kind of non-obvious invariant that earns a comment under the project's "default to no comments" rule — a future maintainer looking at the repo layer would otherwise assume the missing check is a bug.

- **`mail.rs` is a clean extraction from `exchange.rs` — task-level boundary now explicit.** The four functions `cmd_mail_send`, `cmd_mail_inbox`, `cmd_mail_fetch`, `cmd_mail_ack` (`clients/cli/src/commands/mail.rs:13-288`) operate strictly at the ESSR-messaging layer: each one takes a recipient/sender prefix and either dispatches an envelope or queries the mail service. No SAD Event Log construction logic, no policy machinery, no key publication code — those all live in `exchange.rs` where they belong. The shared `exchange_write_policy` / `kem_key_path` / `load_decap_key` helpers were correctly relocated to `helpers.rs` in round 1, so `mail.rs` gets them via `crate::helpers::*` without reaching back into `exchange.rs`.

- **`SadEvent::validate_structure` matrix is complete and one-spot auditable.** `lib/kels/src/types/sad/event.rs:201-258` enumerates the per-kind invariants for all five `SadEventKind` variants (`Icp`, `Est`, `Upd`, `Evl`, `Rpr`) — version constraint, required fields, forbidden fields — with a single consistent shape for each branch. The inline notes on `Icp` (`governance_policy is optional (non-discoverable chains may declare at v0)`) and `Evl` (`write_policy optional — present = policy evolution, absent = pure checkpoint`) capture the edge-case semantics directly next to the structural rules they qualify. A reader auditing what fields a given kind requires never needs to leave this match block.

- **Round 5's `transfer_sad_event(s)` plural rename held under fresh sync.rs reading.** The private core function `transfer_sad_events` (sync.rs:151) — which round 5 #2 renamed from singular — reads as the SAD analog of `transfer_key_events`. The two public entry points `verify_sad_events` (line 355) and `forward_sad_events` (line 378) match `verify_key_events` / `forward_key_events` exactly. The internal helper `send_divergent_sad_events` (line 287) was already plural pre-rename. Naming parity with KEL-side infrastructure is now complete in this module.

- **Round 5's accessor-list symmetry claim survives a recount.** `SadEventVerification` at `lib/kels/src/types/sad/event.rs:296-358` exposes exactly eight accessors: `current_record`, `current_content`, `prefix`, `write_policy`, `topic`, `policy_satisfied`, `last_governance_version`, `establishment_version`. Both `docs/design/sadstore.md:92` and `docs/design/sad-events.md:119` (post round-5 #1 fix) enumerate the same eight in the same order. The two design docs and the struct now agree.
