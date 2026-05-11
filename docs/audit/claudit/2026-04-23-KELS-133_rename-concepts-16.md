# Branch Audit: KELS-133_rename-concepts (Round 16) — 2026-04-23

Branch `KELS-133_rename-concepts` vs `main`: 120 files, 5476 insertions / 3284 deletions. No code commits since round 15 (`git log 4688a85..HEAD` empty; working tree clean). Cold re-read after `/clear`, focused on three surfaces rounds 1–15 didn't reach: (1) the 8 `cp` shorthand sites in `lib/kels/src/types/mod.rs` test module that round 15 #2's `cp`→`gp` sweep didn't touch (round 15 #2 was scoped to `verification.rs` + `identity_chain.rs`); (2) the user-visible error string `"Empty SAD event chain"` at `verification.rs:418` that drifts from the canonical `"SAD Event Log"` form used 4 lines below at `:435` and at `handlers.rs:1563, 1588`; (3) the `AGENTS.md:59` SAD Event Log glossary entry's `"Each record links to previous via SAID"` that drifts from the parallel KEL entry at `:43` (`"Each event links to the previous via SAID"`). Rounds 1–15 cumulatively resolved 101 findings.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 0        |
| Low      | 0    | 3        |

Cumulative across rounds 1–15: **101 resolved.** Round 16 surfaces 3 new findings, all low-priority prose/shorthand drift that rounds 14 and 15's concept sweeps didn't reach. No correctness or security concerns; no Medium or High findings. Diminishing returns has clearly set in — each finding is a ≤10-line edit, and the unscoped-surface pool is now effectively empty: tree-wide greps for `SadPointer`, `SadChain`, `sad_pointer`, `sad_chain`, `checkpoint` (as a noun), `SadEventRepairRecord`, `MAX_NON_\w*RECORDS`, `ARCHIVED_RECORDS_TABLE`, `max_records`, `record_count`, `json_signed_records`, `repairs/records` outside `docs/claudit/**` return zero hits. Remaining `\brecord\b` / `\brecords\b` hits in non-claudit paths are all preserved per the round-14 rule (non-SadEvent domain types — `PeerRecord`, `RecoveryRecord`, `RaftLogAuditRecord`, `PeerHistory.records`, `StorageError::DuplicateRecord` — plus verb forms `"it records"`, `"record as stale"`, `state.record()`).

---

## Low Priority

### ~~1. `lib/kels/src/types/mod.rs` — 8 `cp` shorthand sites in the validate_structure test module that round 15 #2's sweep didn't reach~~ — RESOLVED

**File:** `lib/kels/src/types/mod.rs:1427, 1434, 1481, 1492, 1515, 1538, 1582, 1602`

~~Round 15 #2 swept `cp` (shorthand for "checkpoint") → `gp` (shorthand for "governance_policy") across `lib/kels/src/types/sad/verification.rs` — ~30 sites including `let cp = test_digest(b"evaluation-policy")` bindings, struct field `legit_cp`, test-digest labels `b"checkpoint-policy"` / `b"another-cp"` / `b"rpr-cp"`, and live-code bindings `new_cp` in the Evl/Rpr arm. The sweep was explicitly scoped to `verification.rs`. The `validate_structure` test module at `lib/kels/src/types/mod.rs:1380–1617` uses the same shorthand but wasn't scoped:~~

~~- `:1427` `let cp = cesr::Digest256::blake3_256(b"cp");` — both the binding name and the digest label carry `cp`.~~
~~- `:1434` `Some(cp),` — downstream use of the binding in `SadEvent::create(..., Some(cp))`.~~
~~- `:1481, 1492, 1515, 1538, 1602` — five `event.governance_policy = Some(cesr::Digest256::blake3_256(b"cp"));` sites across the Est / Upd / Rpr validate-structure tests.~~
~~- `:1582` `event.governance_policy = Some(cesr::Digest256::blake3_256(b"new-cp"));` — matches the `b"new-checkpoint-policy"` → `b"new-evaluation-policy"` pattern in round 14 #10's digest-label sweep and round 15 #2's `b"another-cp"` / `b"rpr-cp"` sweep.~~

**Resolution:** All 8 sites swept to the canonical round 15 #2 form. Binding at `:1427` renamed `let cp = ...` → `let gp = ...`; digest label `b"cp"` → `b"gp"` at the binding; downstream `Some(cp)` at `:1434` → `Some(gp)`. Five `event.governance_policy = Some(cesr::Digest256::blake3_256(b"cp"));` sites at `:1481, 1492, 1515, 1538, 1602` swept to `b"gp"`. Site at `:1582` `b"new-cp"` → `b"new-gp"`. Post-fix `git grep -nE '\bcp\b|b"cp"|b"new-cp"' -- ':!docs/claudit/**'` returns zero hits outside the `Icp`/`icp` enum-kind substrings. `make check` green.

### ~~2. `lib/kels/src/types/sad/verification.rs:418` — user-visible `"Empty SAD event chain"` drifts from canonical `"SAD Event Log"` form~~ — RESOLVED

**File:** `lib/kels/src/types/sad/verification.rs:418`

~~Inside `finish()`, when no events have been processed, the verifier returns:~~

~~```rust~~
~~return Err(KelsError::VerificationFailed(~~
~~    "Empty SAD event chain".into(),~~
~~));~~
~~```~~

~~Four lines below at `:434-436` the same function uses the canonical form: `"SAD Event Log has no governance_policy established — Icp or Est must declare one"`. And the corresponding HTTP response strings at `services/sadstore/src/handlers.rs:1563, 1588` both use `"SAD Event Log not found"` (round 12 #3's canonical error-string rubric). The `"Empty SAD event chain"` string is the sole outlier.~~

**Resolution:** Swept the one site at `:418` to `"Empty SAD Event Log"` — matching the canonical form used 4 lines below at `:435` and in `handlers.rs:1563, 1588`. No test asserts on the exact error text. `make check` green.

### ~~3. `AGENTS.md:59` — SAD Event Log glossary entry drifts from the parallel KEL entry at `:43`~~ — RESOLVED

**File:** `AGENTS.md:59`

~~The KEL entry at `:43` reads: "Each event links to the previous via SAID." The SAD Event Log entry at `:59` read: "Each record links to previous via SAID" — drifting on both `record` vs `event` (round 14 rule) and the dropped definite article `the` (parallel KEL entry has it).~~

**Resolution:** Swept `:59` to read `"Each event links to the previous via SAID and is authorized by \`write_policy\`."` — exactly matching the `:43` form. Doc-only change; no `make` needed for this finding (covered by the finding #1/#2 run).

---

## Positive Observations

- **Round 15's six resolutions all hold under cold reading.** `git grep -nE '\bcp\b|cp_attacker|cp_legit|legit_cp|new_cp|tracked_cp|cp_policy|cp1' lib/ services/ clients/` outside `docs/claudit/**` returns exactly the 7 sites in `lib/kels/src/types/mod.rs` flagged in finding #1 — no other files carry the shorthand. Round 15's `verification.rs` + `identity_chain.rs` scope held perfectly. The `lib/kels/src/types/mod.rs` site is the only remaining `cp` shorthand surface.

- **Round 15 #1's `last_governance_version` per-branch + chain-wide-min architecture is stable.** `git blame lib/kels/src/types/sad/verification.rs` on the regression test `test_last_governance_version_advances_past_first_evl_on_linear_chain` (`:1519-1554`) confirms the fix landed as claimed; the regression test currently asserts `Some(4)` for the v0 Icp → v1 Est → v2 Evl → v3 Upd → v4 Evl chain under AlwaysPassChecker. The existing `last_governance_version_tracked` / `last_governance_version_none_without_evaluation` / `rpr_evaluates_governance_policy` / `divergent_est_soft_fail_does_not_poison_other_branch` tests continue to assert the per-branch + chain-wide-min semantics.

- **Round 14's 18 resolutions continue to hold.** Tree-wide `git grep -iE 'sad_record|SadRecord|sad_pointer|SadPointer|chain_prefix|CHAIN_PREFIX|preload_sad_records|sad_event_repair_records|SadEventRepairRecord|repairs/records|MAX_NON_\w*RECORDS|ARCHIVED_RECORDS_TABLE|max_records|record_count|json_signed_records'` outside `docs/claudit/**` returns **zero** hits. Every type, route, SQL table, env var, function-signature-level identifier from rounds 1–14 remains clean.

- **The `checkpoint` → `evaluation` concept rename + `cp` → `gp` shorthand sweep is now one step from complete.** Tree-wide `git grep -i checkpoint -- ':!docs/claudit/**'` returns zero matches. The shorthand `cp` lingers only in the 7 sites in `lib/kels/src/types/mod.rs` flagged in finding #1; rounds 14 and 15 already swept the same shorthand pattern in `verification.rs` + `identity_chain.rs`. After finding #1 lands, `git grep -nE '\bcp\b' -- ':!docs/claudit/**'` will return zero hits outside the `Icp` / `icp` enum-kind substrings.

- **Rule "anything that is an event should be called an event" is uniformly applied across code and SQL, with `AGENTS.md:59` the sole remaining prose outlier.** Tree-wide `git grep '\brecord\b\|\brecords\b' -- ':!docs/claudit/**' ':!*.md'` returns only: `RecoveryRecord` / `RaftLogAuditRecord` / `PeerRecord` / `PeerHistory.records` / `StorageError::DuplicateRecord` type references, verb forms (`"it records"`, `"record as stale"`, `state.record()`), and `clients/cli/src/main.rs:175` `/// Include audit records in response` (which refers to RecoveryRecord audit entries — a KEL concept, not SadEvent). Finding #3 is the last `record` → `event` sweep target in project-level prose. Design/architecture docs (`docs/design/sad-events.md`, `sadstore.md`, `endpoints.md`) were thoroughly swept in round 14.

- **User-visible error strings are consistent aside from `verification.rs:418` (finding #2).** `git grep -E '"(Empty |No )?SAD' -- lib/ services/` returns 5 hits: 4 use the canonical `"SAD Event Log ..."` form, 1 uses the pre-rename `"Empty SAD event chain"`. Round 12 #3 (canonical `"SAD Event Log not found"` at `handlers.rs`) and round 14 rule establish the form; finding #2's outlier is the sole remaining drift.

- **Round 16 findings are diminishing-returns tail without semantic risk.** All three are ≤10 lines of edits, all in test / doc / error-string surfaces, and all are identical-pattern follow-ons to rounds already landed (finding #1 → round 15 #2 pattern; finding #2 → round 12 #3 pattern; finding #3 → round 14 rule). No new rubric introduced. The round-by-round file-sweep pattern has reached the `types/mod.rs` test module + one stray error string + one AGENTS.md line; the code-style/identifier surface for KELS-133 is effectively sealed.

- **Working tree and `make` state remain green from round 15.** `git status` clean, no uncommitted changes. The round-15 commit (`4688a85 claudit 15`) was the last code change. No new correctness or security-relevant code paths have been introduced since round 15's `last_governance_version` min→max fix, so the fix's guarantees (per-branch max tracking, chain-wide min reduction at `finish()`, `None`-absorbing semantics for divergent branches with no Evl) remain the operative behavior.
