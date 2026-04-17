# Branch Audit: KELS-122_pointer-checkpoints (Round 1) — 2026-04-17

~1500 lines across 15 files. Checkpoint policy for bounded pointer chain divergence: verifier enforcement, divergence acceptance in save_batch, divergence-aware gossip sync, test restoration.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 2        |
| Medium   | 0    | 4        |
| Low      | 0    | 3        |

---

## High Priority

### ~~1. Verifier allows checkpoint_policy declaration on non-checkpoint records without evaluation~~ — RESOLVED

**File:** `lib/kels/src/types/sad/verification.rs:261-276`

~~In the v1+ `flush_generation()` non-checkpoint path, a record can declare `checkpoint_policy` for the first time (when `branch.checkpoint_policy.is_none()`) without being a checkpoint. This establishes the checkpoint policy on the branch without the PolicyChecker ever evaluating it — the record only goes through `write_policy` authorization. An attacker who satisfies `write_policy` but not the intended `checkpoint_policy` could set the `checkpoint_policy` to their own controlled policy, defeating the bound.~~

**Resolution:** Being addressed in the other review context. The verifier-side fix requires `is_checkpoint == Some(true)` for the first `checkpoint_policy` declaration. Additionally, the handler's repair path now requires `records[0].is_checkpoint == Some(true)`, ensuring repairs require checkpoint_policy satisfaction (`services/sadstore/src/handlers.rs:1268-1272`).

### ~~2. save_batch version collision query over-fetches entire version range~~ — RESOLVED

**File:** `services/sadstore/src/repository.rs:78-93`

~~The occupied-versions query uses `gte(min_version)` + `lte(max_version)` which fetches **all existing records** in the version range, not just those at colliding versions. The query materializes full `SadPointer` rows when only versions are needed.~~

**Resolution:** Replaced with `ColumnQuery` using `fetch_column_i64` on the transaction — selects only the `version` column with an `IN` filter using `Value::Ints`. Required adding `Value::Ints(Vec<i64>)` variant, `fetch_column_i64` to `TransactionExecutor` trait, and Postgres implementation in verifiable-storage-rs.

---

## Medium Priority

### ~~3. Verifier checkpoint policy evolution evaluates against previous policy but accepts even on failure~~ — RESOLVED

**File:** `lib/kels/src/types/sad/verification.rs:239-245`

~~When a checkpoint record changes `checkpoint_policy`, the verifier evaluates the record against the **previous** (tracked) policy. If the evaluation fails, `policy_satisfied` is set to `false` — but processing continues. The new policy is still recorded going forward. This means a failed checkpoint policy evolution is a soft failure, not a structural error.~~

**Resolution:** Checkpoint policy evaluation failure is now a structural error (`return Err(KelsError::VerificationFailed(...))`). Additionally, the first checkpoint declaration (where `branch.checkpoint_policy.is_none()`) no longer calls `PolicyChecker::satisfies` — there's no prior commitment to verify against.

### ~~4. Scenario 5 submits v0 alone without checkpoint_policy — verifier will reject at finish()~~ — RESOLVED

**File:** `clients/test/scripts/test-sadstore.sh:270-274`

~~Scenario 5 submits v0 alone, then fetches the chain and asserts 1 pointer. But the verifier's `finish()` requires at least one branch to have `checkpoint_policy`. A v0 without `checkpoint_policy` submitted alone will fail at `finish()`.~~

**Resolution:** Scenario 5 now submits [v0, v1] as an inception batch, where v1 declares `checkpointPolicy`. v1 does not need `isCheckpoint: true` — the first declaration is just a declaration, not an evaluated checkpoint.

### ~~5. build_checkpoint_policy uses same expression as write_policy~~ — RESOLVED

**File:** `clients/test/scripts/lib/test-common.sh:106-116`

~~`build_checkpoint_policy` creates a policy with `endorse($kel_prefix)` — the same single-endorser expression typically used for `write_policy`. In a real deployment, `checkpoint_policy` should have a **higher threshold** than `write_policy`.~~

**Resolution:** Added TODO comment noting that production checkpoint policies should use higher thresholds. Acceptable for testing — structural enforcement (counter bound, policy evaluation) is tested independently.

### ~~6. Held-back record in transfer_sad_pointer may cause off-by-one in verification~~ — RESOLVED

**File:** `lib/kels/src/types/sad/sync.rs:211-225`

~~When `has_more` is true, the last record is popped off for held-back. The interaction between held-back records and the generation buffer hasn't been explicitly tested.~~

**Resolution:** Added `test_divergence_detection_at_page_boundary` test in `lib/kels/src/types/sad/sync.rs` using in-memory `VecSadSource` and `CollectingSink`. Verifies that two records at the same version split across pages (page_size=3, 4 records) are correctly detected and both forwarded.

---

## Low Priority

### ~~7. Unnecessary `use std::collections::HashSet` inline in save_batch~~ — RESOLVED

**File:** `services/sadstore/src/repository.rs:66,80`

~~The code uses `std::collections::HashSet` inline twice rather than importing it at the top of the file. This is inconsistent with CLAUDE.md's import style.~~

**Resolution:** Moved to `use std::collections::HashSet;` in the import block at file top.

### ~~8. `MAX_NON_CHECKPOINT_RECORDS` not used outside verifier~~ — RESOLVED

**File:** `lib/kels/src/lib.rs:134-137`

~~The constant is `pub` and exported at the crate root, but only used in `verification.rs`.~~

**Resolution:** No change needed — it's a reasonable public constant for the security bound. Acceptable as-is.

### ~~9. `SubmitPointersResponse` lacks `#[must_use]` unlike `SubmitEventsResponse`~~ — RESOLVED

**File:** `lib/kels/src/types/sad/request.rs:44-51`

~~The KEL's `SubmitEventsResponse` has `#[must_use]` but `SubmitPointersResponse` doesn't.~~

**Resolution:** Added `#[must_use = "SubmitPointersResponse.applied must be checked — records may be rejected"]`.

---

## Positive Observations

- **Divergence-aware gossip sync mirrors the proven KEL pattern.** The held-back record strategy, two-phase divergence detection, and `send_divergent_sad_pointers` chain separation via `previous` tracing are a faithful adaptation of `transfer_key_events` to the simpler pointer chain model (no recovery/contest). The simplification is well-judged.

- **Policy-based checkpoints are a clean design.** Using existing `PolicyChecker` infrastructure instead of nonce-based secret management eliminates an entire category of key management complexity. The `checkpoint_policy` / `is_checkpoint` fields compose naturally with the existing write_policy evaluation flow.

- **`SaveBatchResult` enum with `diverged_at_version` gives callers actionable information.** The handler can communicate divergence state in the `SubmitPointersResponse`, matching the KEL's `SubmitEventsResponse` pattern.

- **Page size clamping on `get_sad_pointer` closes a real gap.** The checkpoint invariant depends on bounded page sizes for page-by-page verification. This was missing and is now consistent with the repair endpoints.

- **Shell test infrastructure reuse is solid.** `build_checkpoint_policy` in `test-common.sh` follows the existing `compute_said`/`compute_prefix` pattern, and the checkpoint fields are correctly integrated into both `load-sad.sh` and `test-sadstore.sh` without breaking the existing test structure.

- **HttpSadSink 409 handling is correctly layered.** The sink swallows 409 Conflict (chain already divergent), while `send_divergent_sad_pointers` propagates all other errors via `?`. This means network failures surface but expected divergence-already-exists responses don't. Clean separation of concerns.
