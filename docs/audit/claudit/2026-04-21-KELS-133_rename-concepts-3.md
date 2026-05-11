# Branch Audit: KELS-133_rename-concepts (Round 3) — 2026-04-21

Branch `KELS-133_rename-concepts` vs `main`: ~85 files, ~2642 insertions / 2374 deletions. Round 1 resolved 7 findings; Round 2 resolved 11. Round 3 focus: the primary `docs/design/sadstore.md` and `docs/design/sad-events.md` design docs (not yet deeply scanned in earlier rounds), plus test-function names and Rust/shell identifiers that kept mechanism-naming for slots that hold role-named data. Total resolved (cumulative across rounds 1–2): 18.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 2        |
| Low      | 0    | 5        |

---

## Medium Priority

### ~~1. `docs/design/sadstore.md` still describes the removed `?repair=true` query param and `repair: true` gossip flag~~ — RESOLVED

**File:** `docs/design/sadstore.md:74`, `84`, `133`

~~Round 1's positive observations captured the removal of the `repair: bool` field from `SadAnnouncement::Event` and the `:repair` Redis suffix. Round 2 findings #1 and #3 cleaned up the stale descriptions in `docs/endpoints.md` and `docs/gossip.md`. But the primary SADStore design doc — the thing the `AGENTS.md` architecture section points operators at for "full design" — still describes both removed things as current behaviour:~~

- ~~Line 74: `The chain owner repairs divergence by submitting a replacement batch with ?repair=true:` — the handler has no `?repair=true` path (see `services/sadstore/src/handlers.rs:1298`: `is_repair = new_records.iter().any(|r| r.kind.is_repair())` — it auto-detects from Rpr records in the batch).~~
- ~~Line 84: `When a repair succeeds, the SADStore publishes a gossip message with repair: true. Peer nodes that receive this announcement forward the repaired chain to their local SADStore with ?repair=true, replacing their divergent state.` — both artefacts (the `repair: true` field on `SadAnnouncement::Event` and the `?repair=true` query param) no longer exist.~~
- ~~Line 133: `POST | /api/v1/sad/events | Submit chain records; ?repair=true to repair divergent chain` — same stale query param in the API table.~~

**Resolution:**
- Line 74 rewritten to `The chain owner repairs divergence by submitting a batch that includes a Rpr record. The handler auto-detects Rpr records and takes the repair path:`.
- Line 84 rewritten to `When a repair succeeds, the SADStore publishes the new effective SAID to Redis. Peer gossip nodes fetch the full chain from origin and submit to their local SADStore; the receiving handler auto-detects repair from Rpr records in the submitted batch and takes the repair path, replacing their divergent state.`
- Line 133 API-table entry now reads `Submit chain records (repair auto-detected from Rpr records in the batch)`.

Post-fix grep for `\?repair=|repair: true` across the tree (excluding `docs/claudit/**`) returns zero hits.

### ~~2. `docs/design/sad-events.md` still describes the removed `:repair` Redis suffix~~ — RESOLVED

**File:** `docs/design/sad-events.md:96`, `149`

~~Companion stragglers to finding #1 — the main SEL security-model doc still references the removed `:repair` pub/sub suffix:~~

- ~~Line 96 (Gossip Propagation section): `When a repair succeeds, SADStore publishes {prefix}:{effective_said}:repair to Redis.`~~
- ~~Line 149 (Repair submission handler flow step 9): `Commit, publish to Redis with :repair suffix`~~

~~Round 2 finding #3 flagged the identical stale phrasing in `docs/gossip.md` and fixed it.~~

**Resolution:** Line 96 now reads `{prefix}:{effective_said}` (no suffix). Line 149 now reads `Commit, publish to Redis` (no `with :repair suffix` tail). Post-fix grep for `:repair` across the tree (excluding `docs/claudit/**`) returns zero hits.

---

## Low Priority

### ~~3. `cp_policy` variable name in `identity_chain.rs` tests holds a governance_policy~~ — RESOLVED

**File:** `lib/policy/src/identity_chain.rs:187`, `201`, `249`, `275`-`278`, `282`

~~Two test helpers declare `let cp_policy = test_policy("checkpoint");` then assign `event.governance_policy = Some(cp_policy.said);`. Same pattern round 2 finding #8 fixed in shell scripts. A slot that holds what is by role a `governance_policy` is named after the mechanism.~~

**Resolution:** 
- `cp_policy` → `gp_policy` at both sites (and the `test_policy("checkpoint")` string changed to `test_policy("governance")` so the policy expression itself no longer carries mechanism-naming).
- Local variables `v1_cp` / `v1_cp_rebuilt` in two test functions renamed to `v1_gp` / `v1_gp_rebuilt`.
- Comments at `:201` and `:275` (`Create a v1 with checkpoint so the chain passes verification` / `Add a v1 with checkpoint so verification passes`) updated to `...with governance_policy declared...`.

### ~~4. `last_cp_version` / `cp_version` in the SADStore handler and repository hold a `last_governance_version` result~~ — RESOLVED

**File:** `services/sadstore/src/handlers.rs:1302`, `1310`, `1333-1341`; `services/sadstore/src/repository.rs:108-113`

~~Handler variable named by mechanism ("cp") but holding data the repo/verifier surfaces by role (`last_governance_version`). Sibling round-2 finding #8 flagged this exact pattern in shell and got uniform renames.~~

**Resolution:**
- `services/sadstore/src/handlers.rs:1302`: `last_cp_version` → `last_gp_version`.
- `services/sadstore/src/handlers.rs:1310` warn message: `"Failed to query last checkpoint version"` → `"Failed to query last governance version"` (the log line names the source-of-truth method, not the mechanism effect).
- `services/sadstore/src/handlers.rs:1333-1341`: `cp_version` → `gp_version` in both the `if let` pattern and the format-string arg.
- `services/sadstore/src/repository.rs:108-113`: `cp_version` → `gp_version` in both the `if let` and the format arg.

User-facing error string `"sealed by checkpoint at version N"` preserved — that sentence is a mechanism-level effect (the seal is what the checkpoint mechanism produces), which is correct under the role/mechanism split.

### ~~5. `chain_cp_said` / `$cp` / `--arg cp` in `load-sad.sh` — straggler from round-2's shell rename~~ — RESOLVED

**File:** `clients/test/scripts/load-sad.sh:149-160`

~~Round 2 finding #8 renamed the same pattern in `test-sadstore.sh` and `test-common.sh`; the scan missed this sibling in `load-sad.sh`.~~

**Resolution:** `chain_cp_said` → `chain_gp_said`, and the `--arg cp "$chain_cp_said"` / `$cp` consumer pair → `--arg gp "$chain_gp_said"` / `$gp`. Post-fix grep for `chain_cp_said|CP_SAID|--arg cp "` across the tree returns zero hits.

### ~~6. Test function names in `lib/kels/src/types/mod.rs` and `services/gossip/src/types/sad.rs` still use old type names~~ — RESOLVED

**File:** `lib/kels/src/types/mod.rs` (14 functions) and `services/gossip/src/types/sad.rs:38`

~~The rename changed `EventKind` → `KeyEventKind` and `SadGossipMessage` → `SadAnnouncement`, but the cargo-test function names that exercise those types still referenced the old names.~~

**Resolution:**
- All 14 `test_event_kind_*` functions in `lib/kels/src/types/mod.rs` renamed to `test_key_event_kind_*` (the first four that round 3 identified, plus ten more predicate/parse/serialization tests in the lower half of the same file — `test_event_kind_as_str`, `_display`, `_from_str`, `_from_str_rejects_short_names`, `_from_str_rejects_uppercase`, `_from_str_invalid`, `_from_short_name`, `_from_short_name_rejects_uppercase`, `_from_short_name_rejects_versioned`, `_from_short_name_rejects_invalid`, `_is_inception`, `_decommissions`, `_reveals_rotation_key`, `_reveals_recovery_key`).
- `test_sad_gossip_message_serialization` → `test_sad_announcement_serialization`.
- Post-fix grep for `test_event_kind_|test_sad_gossip_message` returns zero hits.

### ~~7. Inline example in `docs/design/sad-events.md` uses `cp_said` identifier~~ — RESOLVED

**File:** `docs/design/sad-events.md:200`

~~Divergence/repair shape diagram: `v0  kind=icp  governance_policy=cp_said`. Inconsistent with the role-naming direction and round-2 shell-var renames.~~

**Resolution:** `governance_policy=cp_said` → `governance_policy=gp_said`. Post-fix grep for `cp_said` across the tree returns zero hits.

---

## Post-Resolution Verification

- `make` completes cleanly: `Finished dev profile ... in 14.47s`. All workspace crates compile; no new warnings introduced by the renames.
- `make test` continues to pass — the renamed test functions still route through cargo-test's default `*` filter.
- Combined grep across `cp_policy|cp_said|cp_version|last_cp_version|chain_cp_said|\?repair=|repair: true|:repair|test_event_kind_|test_sad_gossip_message` (excluding `docs/claudit/**`) returns zero hits.
- User-facing sealed-by-checkpoint error strings preserved — the role/mechanism split is now consistently applied: role-named variables hold role-typed data; mechanism-named strings describe mechanism effects.

## Positive Observations

- **Design docs converge on `SadAnnouncement { Object, Event }` wire type.** `docs/design/sadstore.md:154-158` already showed the clean three-field enum after removing the `repair` flag and renaming `chain_prefix` → `prefix`. With findings #1 and #2 fixed, every prose description across `sadstore.md`, `sad-events.md`, `gossip.md`, and `endpoints.md` now agrees with the actual wire type — no reader will be led to look for a removed field or a stripped suffix.

- **Governance / checkpoint role/mechanism split is preserved in user-facing error strings.** The error `"Cannot repair at version N — sealed by checkpoint at version M"` in `services/sadstore/src/repository.rs:111-114` and `services/sadstore/src/handlers.rs:1339-1343` correctly uses "checkpoint" for the mechanism (what does the sealing) while the role-scoped `governance_policy` appears in the adjacent comment and the warn log (now `"Failed to query last governance version"` after finding #4's fix). This is exactly the role/mechanism split the branch set out to establish, applied inside a single function.

- **`SadEvent::validate_structure` gives precise per-kind field rules in a single match.** `lib/kels/src/types/sad/event.rs:201-258` is a compact, auditable spec for what each record kind requires/forbids. The inline comment at Evl (`write_policy optional — present = policy evolution, absent = pure checkpoint`) captures the semantics that the verifier relies on at runtime.

- **Rounds 1–2 resolutions all still stick.** A fresh grep for the round-2 artefacts (`SignedSadEvent`, `maxRecordsPerPointerPerDay`, `SadGossipMessage` in code, `:repair` in `sync.rs`, `"signed SAD event"` help text, `test_sad_submit_pointer_*`, `CHECKPOINT_POLICY_SAID`, `"checkpoint policies"` TODO, `a event`) returns zero hits outside `docs/claudit/**` — including after round 3's batch of follow-up renames. Nothing regressed.

- **Identity-chain test helpers now uniformly role-named.** `lib/policy/src/identity_chain.rs:185-192` (`add_governance_declaration`) reads `let gp_policy = test_policy("governance"); event.governance_policy = Some(gp_policy.said);` — helper function name, local variable name, policy-expression label, and field assignment all carry the `governance`/`governance_policy` role name. Mechanism-naming (`checkpoint`) is now reserved for evaluation-flow elements (`evaluates_governance()`, `records_since_checkpoint`, `MAX_NON_CHECKPOINT_RECORDS`) — the split is clean.

- **SQL migration is fully consistent with the rename.** `services/sadstore/migrations/0001_initial.sql` uses `sad_events` / `sad_event_archives` / `sad_event_repairs` / `sad_event_repair_records` throughout, with FK references (`repair_said → sad_event_repairs(said)`, `event_said → sad_event_archives(said)`) correctly following the parent-table renames.
