# Branch Audit: KELS-133_rename-concepts (Round 15) — 2026-04-23

Branch `KELS-133_rename-concepts` vs `main`. Cold re-read after `/clear` surfaced three surfaces rounds 1–14 never reached: the `"cp"` abbreviation (shorthand for "checkpoint") in `lib/kels/src/types/sad/verification.rs` that round 14's `checkpoint` → `evaluation` concept sweep left behind; the `RejectAdvanceChecker` inline-test impl in `lib/policy/src/identity_chain.rs` that round 13 #1's resolution wrongly claimed was `_: &SadEvent` unnamed (actually `record: &SadEvent`); and one correctness issue — `last_governance_version` min-vs-max semantics — noticed while re-reading `verification.rs:310-315` (the pre-existing chain-wide `.min()` collapsed to the earliest Evl version instead of the most recent). Rounds 1–14 cumulatively resolved 95 findings. Round 15 surfaces 6 new findings; all 6 resolved in this round via one correctness fix + prose/shorthand sweeps across 4 files.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 2        |
| Low      | 0    | 4        |

Cumulative across rounds 1–15: **101 resolved.** Round 15 surfaced 6 new findings; all 6 resolved in this round. Finding #1 is a correctness fix (the min-vs-max bug was pre-existing on `main` from commit `280079f`, 2026-04-21, KELS-131); the user elected to fix it under this branch since `verification.rs` was already open for the rename sweep. Per-branch `last_governance_version` tracking now lands alongside a chain-wide min-across-branches reduction at `finish()`, plus a new regression test. Findings #2–#6 are prose / comment / test-label / test-binding drift from the rename sweep. Post-fix `make` (fmt, deny, clippy, test, build) passes cleanly — all 40 test suites green including the new `test_last_governance_version_advances_past_first_evl_on_linear_chain`.

---

## Medium Priority

### ~~1. `last_governance_version` never advances past the first Evl in linear chains — `existing.min(event.version)` should be `max`~~ — RESOLVED

**File:** `lib/kels/src/types/sad/verification.rs:47-61, 74-92, 310-347, 413-460` + new regression test at `:1519-1554`

~~`flush_generation` processes generations in ascending version order, so at every Evl/Rpr call after the first `existing <= event.version` — meaning `existing.min(event.version) == existing`. In a linear chain with multiple Evl events (e.g., `v0 Icp → v1 Est → v2 Evl → v3 Upd → v4 Evl`), `last_governance_version` is set to `Some(2)` and then never advances. The docstring on the `SelVerifier` field (`:85-87`) and on the public getter (`event.rs:340-341`) both describe this as **"The version of the most recent governance evaluation"**, which is the opposite of what the code computes.~~

**Resolution:** Option 2 applied per user direction — per-branch tracking + chain-wide min reduction at `finish()`.

- **`SadBranchState`** (`:47-61`): added field `last_governance_version: Option<u64>` with rustdoc: *"Version of the most recent governance evaluation (Evl or Rpr) on this branch that passed both the governance check and the soft write_policy check. `None` until the first authorized evaluation. Monotonically advances (max) within a branch."*
- **`SelVerifier`** (`:74-92`): removed the chain-wide `last_governance_version: Option<u64>` field. Removed the corresponding `None` initializer in `new()` at `:94-106`.
- **Icp arm** (`:183-193`): branch initializer now carries `last_governance_version: None`.
- **Est arm** (`:264-288`): inherits `branch.last_governance_version` unchanged (Est doesn't evaluate).
- **Evl/Rpr arm** (`:289-341`): computes `new_last_gov_version` per-branch with `existing.max(event.version)`, gated on `write_policy_satisfied` (defense-in-depth — soft wp-fail blocks the seal advance). If soft-failed, inherits `branch.last_governance_version`.
- **Upd arm** (`:342-360`): inherits `branch.last_governance_version` unchanged.
- **Tuple reshape**: the per-arm return tuple grew from `(governance_policy, events_since_evaluation, tracked_write_policy)` to `(..., last_governance_version)`; all four arms + the closing `new_branches.insert(...)` at `:366-375` thread the new value.
- **`finish()`** (`:413-460`): computes chain-wide `last_governance_version` as `min` across tip branches' `last_governance_version` values via `reduce` — `None` on any branch collapses the chain-wide value to `None` (weakest seal). Threaded into `SadEventVerification::new(...)` at `:466`.
- **Regression test** `test_last_governance_version_advances_past_first_evl_on_linear_chain` (`:1519-1554`): processes `v0 Icp → v1 Est → v2 Evl → v3 Upd → v4 Evl` under `AlwaysPassChecker` and asserts `last_governance_version == Some(4)`. Pre-fix this would have returned `Some(2)` (the first Evl's version), catching any regression.

**Verification:** `make` green — all 40 test suites pass including the new regression, existing tests `test_last_governance_version_tracked` (Some(2) for single Evl at v2), `test_last_governance_version_none_without_evaluation` (None when no Evl), `test_evl_rejected_wp_does_not_advance_governance_policy` (None when wp soft-fails), `test_divergent_est_soft_fail_does_not_poison_other_branch` (None for divergent Est-only chain), and `test_rpr_evaluates_governance_policy` (Some(1) for Rpr at v1).

**Pre-existence note:** `git blame main -- lib/kels/src/types/sad/verification.rs` shows the `existing.min(record.version)` line originated from commit `280079f` (KELS-131, 2026-04-21) on `main`, pre-branch. User elected to fix here while `verification.rs` was open for the round-14/15 rename sweep rather than routing through a separate PR. Close upstream issue #142 when this branch merges; no separate issue remains.

### ~~2. `cp` abbreviation (shorthand for "checkpoint") pervades `verification.rs` test module + one live comment + four live variable bindings — round 14 `checkpoint` → `evaluation` sweep left it behind~~ — RESOLVED

**File:** `lib/kels/src/types/sad/verification.rs` (throughout — Category A + B in the Evl/Rpr + Est arms; Category C in the test module)

**Resolution:** All three categories swept.

- **Category A (live code bindings, 4 sites):** `new_cp` → `new_gp` at the Est arm (`:276, 287`) and at the Evl/Rpr arm (`:318, 330`). The rename landed naturally as part of the finding #1 tuple reshape — both `new_gp` and `new_last_gov_version` are now threaded through the same tuple expansion.
- **Category B (live comment, 1 site):** `:307` `"authorized by the cp check that just passed"` → `"authorized by the governance check that just passed"`. Matches the canonical `evaluates_governance()` method name.
- **Category C (test module, ~30 sites):**
  - `let cp = test_digest(b"evaluation-policy")` at `:493, 520, 715, 770, 1045, 1537` → `let gp = ...` (6 sites). Downstream `governance_policy: cp` / `Some(cp)` all swept to `gp`.
  - `let cp1 = ...`, `cp_attacker = ...` in `test_evl_rejected_wp_does_not_advance_governance_policy` (`:808-812`) → `gp1 = ...`, `gp_attacker = ...`. Downstream `governance_policy: cp1` → `gp1` and `v1.governance_policy = Some(cp_attacker)` → `Some(gp_attacker)`.
  - `let cp_attacker = ...`, `let cp_legit = ...` in `test_est_rejected_wp_does_not_establish_governance_policy` (`:863-865`) and `test_divergent_est_soft_fail_does_not_poison_other_branch` (`:902-904`) → `gp_attacker`, `gp_legit`.
  - `AcceptLegitEstChecker { legit_cp: cp_legit }` (`:926, 935, 942`) → `{ legit_gp: gp_legit }`. Struct field rename + constructor + body access `self.legit_cp` → `self.legit_gp` all swept in lockstep.
  - `let v0_no_cp = ...; let v0_with_cp = ...;` (`:1365-1367`) → `v0_no_gp`, `v0_with_gp`.
  - Test digest labels `b"another-cp"` (`:1422`) → `b"another-gp"`; `b"rpr-cp"` (`:1484`) → `b"rpr-gp"`.
  - Assertion message at `:888` `"did not establish cp"` → `"did not establish governance_policy"` (canonical form matching the error text at `:417`).
  - Inline test comments across the `test_evl_rejected_wp_does_not_advance_governance_policy` / `test_divergent_est_soft_fail_does_not_poison_other_branch` / Est-soft-fail bodies: `"cp check"` → `"governance check"`; `"tracked cp"` → `"tracked gp"`; `"v1 cp advance"` → `"v1 gp advance"`; `"hard cp check"` → `"hard governance check"`; `"per-branch cp stayed None"` → `"per-branch governance_policy stayed None"`; `.expect("...tracked cp should still be cp1...")` → `.expect("...tracked gp should still be gp1...")`.

**Verification:** `grep -n '\bcp\b\|cp_attacker\|cp_legit\|legit_cp\|new_cp\|tracked_cp' lib/kels/src/types/sad/verification.rs` returns zero hits post-sweep (the only lingering substring is `Icp` / `icp` kind name, which is correct — that's the event kind enum variant). Full `make` green.

---

## Low Priority

### ~~3. `identity_chain.rs` — `RejectAdvanceChecker` test impl uses `record: &SadEvent` + rustdocs use "record" for SadEvents + one `cp` comment~~ — RESOLVED

**File:** `lib/policy/src/identity_chain.rs:22-26, 50-53, 56, 142, 145, 219, 297`

**Resolution:** All sites swept.

- `:22-26` rustdoc on `create()`: `"follow the inception with an \`Est\` record at v1"` → `"with an \`Est\` event at v1"`.
- `:50-53` rustdoc on `advance()`: `"The produced record is an \`Evl\`"` → `"The produced event is an \`Evl\`"`; `"the soft check on every v1+ record"` → `"the soft check on every v1+ event"`.
- `:56-57` rustdoc on `advance()`: `"or a v0 declaration on the inception record"` → `"or a v0 declaration on the inception event"`.
- `:142` `RejectAdvanceChecker::satisfies` param `record: &SadEvent,` → `event: &SadEvent,`.
- `:145` body `Ok(record.kind == SadEventKind::Est)` → `Ok(event.kind == SadEventKind::Est)`.
- `:219` test comment: `"prove the produced Evl record passes verifier evaluation"` → `"prove the produced Evl event passes verifier evaluation"`.
- `:297` test comment: `"so the R6 Est-arm gate permits the cp advance"` → `"so the R6 Est-arm gate permits the governance_policy advance"`.

**Verification:** `grep -nE '\brecord\b|\brecords\b' lib/policy/src/identity_chain.rs` returns zero hits. Round 13 #1's incorrect "all-unnamed" claim about this file is now actually true — the one named param (`RejectAdvanceChecker::satisfies`) has been renamed to `event`. Full `make` green.

### ~~4. `event.rs:356` — `"establish cp"` in public rustdoc on `SadEventVerification::establishment_version`~~ — RESOLVED

**File:** `lib/kels/src/types/sad/event.rs:353-357`

**Resolution:** Public rustdoc swept: `"another branch's Est did establish cp at that version"` → `"another branch's Est did establish governance_policy at that version"`. Matches the canonical `governance_policy` naming used throughout the file and the `"has no governance_policy established"` error text.

### ~~5. `SadStoreClient::as_sad_source` rustdoc says "chain endpoint", asymmetric with round-14-updated `as_sad_sink` rustdoc "events endpoint"~~ — RESOLVED

**File:** `lib/kels/src/client/sadstore.rs:39`

**Resolution:** Rustdoc at `:39` swept: `/// Create an \`HttpSadSource\` for this client's chain endpoint.` → `/// Create an \`HttpSadSource\` for this client's events endpoint.` The `as_sad_source` / `as_sad_sink` pair now reads symmetrically, both anchored on the canonical `"events endpoint"` form introduced by round 14 #1.

### ~~6. `clients/test/scripts/test-sadstore.sh` — "repair record" in test output strings~~ — RESOLVED

**File:** `clients/test/scripts/test-sadstore.sh:471, 473, 475`

**Resolution:** Three labels swept:
- `:471` `"Repair: node-a tip is repair record"` → `"Repair: node-a tip is repair event"` (the tip is an Rpr SadEvent).
- `:473` comment `"# Verify repair audit record exists"` → `"# Verify repair audit entry exists"` (the table is `sel_repair_events`; "entry" reads cleanly without overloading "event").
- `:475` `"Repair: audit record created"` → `"Repair: audit entry created"` (same rationale).

---

## Positive Observations

- **Round 15 resolves all 6 of its own findings.** Cumulative across rounds 1–15: **101 resolved findings.** Full `make` passes (fmt, deny, clippy, test, build) after the combined correctness fix + prose sweeps. Post-fix `git grep -nE '\bcp\b|cp_attacker|cp_legit|legit_cp|new_cp|tracked_cp' lib/kels/src/types/sad/verification.rs` returns zero hits (only `Icp` / `icp` kind-name substrings remain, which are intentional). `git grep -nE '\brecord\b|\brecords\b' lib/policy/src/identity_chain.rs` returns zero hits.

- **The finding-#1 fix is behavior-preserving for existing tests.** All pre-existing `last_governance_version` assertions continue to pass under the new per-branch + chain-wide-min architecture: `test_last_governance_version_tracked` (Some(2) for single Evl at v2), `test_last_governance_version_none_without_evaluation` (None when no Evl), `test_evl_rejected_wp_does_not_advance_governance_policy` (None when wp soft-fails on both v1 and v2), `test_divergent_est_soft_fail_does_not_poison_other_branch` (None for divergent Est-only chain — Est doesn't evaluate), `test_rpr_evaluates_governance_policy` (Some(1) for Rpr at v1). The new regression test `test_last_governance_version_advances_past_first_evl_on_linear_chain` is the only assertion whose truth flipped — it would have returned Some(2) pre-fix, now correctly returns Some(4).

- **Chain-wide reduction semantics: min across tip branches, `None` is absorbing.** `finish()` uses `.reduce(|acc, v| match (acc, v) { (Some(a), Some(b)) => Some(a.min(b)), _ => None }).flatten()`. For linear chains this collapses to the single branch's per-branch value (most recent Evl). For divergent chains with two tip branches A (last_gov=v3) and B (last_gov=v5), returns Some(3) — the weakest seal. If either branch is `None` (e.g., one branch has no Evl yet), the chain-wide value is `None` — no seal. This matches the docstring `"For divergent chains, this is the minimum across branches (weakest seal)"` and preserves the repair-floor safety property that `repository.rs:107-114` relies on.

- **Round 14's 18 resolutions continue to hold.** `git grep -iE 'sad_record|SadRecord|sad_pointer|SadPointer|chain_prefix|CHAIN_PREFIX|preload_sad_records|sad_event_repair_records|SadEventRepairRecord|repairs/records|MAX_NON_\w*RECORDS|ARCHIVED_RECORDS_TABLE|max_records|record_count|json_signed_records|MAX_NON_CHECKPOINT'` excluding `docs/claudit/**` still returns **zero** hits. Every type, route, SQL table, env var, function-signature-level identifier from rounds 1–14 is clean.

- **The `checkpoint` → `evaluation` concept rename is now fully complete, including the `cp` shorthand residue.** `git grep -i checkpoint -- ':!docs/claudit/**'` returns zero matches, and the informal `cp` abbreviation is also fully swept per finding #2. The round 14 #10 concept sweep, plus round 15 #2's shorthand sweep, together cover every surface — identifiers, variables, comments, test labels, assertion messages, and docs.

- **Round 14's rescission of the count-noun preservation continues to hold.** The rule "anything that is an event should be called an event" is uniformly applied to SadEvent-bearing surfaces. Non-SadEvent references (`PeerRecord`, `RecoveryRecord`, `RaftLogAuditRecord`, `PeerHistory.records`, `StorageError::DuplicateRecord`, `record_read_policy` for Layer 1 SAD objects) remain preserved — they aren't SadEvents.

- **Finding #1's fix is self-contained within `lib/kels/src/types/sad/verification.rs` + one new test.** No change to `repository.rs`, `event.rs` (except the finding #4 docstring tweak), `handlers.rs`, or the public `SadEventVerification` API. The public getter `SadEventVerification::last_governance_version()` preserves its signature `pub fn last_governance_version(&self) -> Option<u64>` — only the internal computation path changed. Downstream consumers (`repository.rs:107-114`, `handlers.rs:1305, 1448`) are unaffected at the type level and now see the semantically correct "most recent" value for linear chains.

- **Round 15 combined delivered 1 correctness fix + ~50 prose/shorthand edits across 4 files.** `lib/kels/src/types/sad/verification.rs` (correctness fix + ~30 `cp`→`gp` sweeps + new regression test), `lib/policy/src/identity_chain.rs` (~8 sweeps + param rename), `lib/kels/src/types/sad/event.rs` (1 rustdoc line), `lib/kels/src/client/sadstore.rs` (1 rustdoc line), `clients/test/scripts/test-sadstore.sh` (3 labels). The combined diff compiles clean, passes clippy, passes all 40 test suites, and adds one new regression test that guards against the finding-#1 bug reappearing.
