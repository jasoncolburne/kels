# Branch Audit: KELS-122_pointer-checkpoints (Round 2) — 2026-04-17

~1100 lines across 16 files. Second review pass focusing on transfer logic correctness, divergence detection completeness, and checkpoint policy establishment semantics. Round 1 had 9 findings, all resolved.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 1        |
| Low      | 0    | 2        |

---

## Medium Priority

### ~~1. Held-back record at divergence transition bypasses verifier~~ — RESOLVED

**File:** `lib/kels/src/types/sad/sync.rs:211-253`

~~When `transfer_sad_pointer` detects divergence on a page that also has a held-back record, the held-back record is popped from `records` at line 213 (before `verify_page` at line 223), then pushed directly into `post_divergence` at line 252 without ever passing through the verifier. On subsequent collection-mode iterations, fetched records ARE verified (line 205-206), but the held-back record from the divergence-transition page is already in `post_divergence` unverified.~~

**Resolution:** Added `verifier.verify_page(std::slice::from_ref(&held))` before pushing the held-back record into `post_divergence` at the divergence transition point.

---

## Low Priority

### ~~2. `save_batch` does not detect within-batch version collisions~~ — RESOLVED

**File:** `services/sadstore/src/repository.rs:80-97`

~~The `occupied_versions` set is computed once from existing DB records before any batch inserts. If the batch itself contains two records at the same version (e.g., a divergent pair [v2_a, v2_b]), both pass the `occupied_versions.contains` check (neither version was in the DB) and are inserted. The function returns `SaveBatchResult::Accepted` even though the chain is now divergent.~~

**Resolution:** Added `occupied_versions.insert(record.version)` after each successful insert in the loop. Within-batch version collisions now hit the existing collision check and return `DivergenceCreated`.

### ~~3. `send_divergent_sad_pointers` drops all shorter-branch records beyond the fork~~ — RESOLVED

**File:** `lib/kels/src/types/sad/sync.rs:351-354`

~~Only `shorter.first()` is sent to the sink. Any records at higher versions on the shorter branch (e.g., v3_b, v4_b appended before divergence was detected) are silently dropped.~~

**Resolution:** The shorter branch is always exactly one record by invariant — the batch truncation in `save_batch` freezes the chain immediately on divergence, preventing extensions past the fork point. Added a comment documenting this invariant.

---

## Positive Observations

- **Checkpoint bound math is precisely aligned with page size.** `MAX_NON_CHECKPOINT_RECORDS = MINIMUM_PAGE_SIZE - 1 = 63` leaves exactly one slot for the checkpoint record in each page. The test `test_checkpoint_overdue_at_64` validates the boundary precisely — 63 non-checkpoint records pass, 64 fails. The comment at `lib/kels/src/lib.rs:133-136` explains the derivation clearly.

- **Checkpoint policy evolution is a structural error, not a soft failure.** Unlike write_policy authorization (which sets `policy_satisfied = false` and continues), checkpoint policy failure returns `Err(KelsError::VerificationFailed(...))` immediately. This is the right call — checkpoint_policy is a security bound that the verifier must enforce unconditionally, not a consumer-side authorization decision.

- **The inception batch pattern ([v0, v1]) is a sound mitigation for checkpoint_policy squatting.** By declaring checkpoint_policy on v1 in the same atomic submission as v0, the legitimate owner prevents anyone else from racing to set checkpoint_policy first. The shell tests consistently use this pattern (scenarios 5, 7, and `load-sad.sh`).

- **Repair path now requires checkpoint.** The handler's `records[0].is_checkpoint.unwrap_or(false)` check at `services/sadstore/src/handlers.rs:1268` ensures repair submissions satisfy checkpoint_policy (a higher bar than write_policy). This closes the gap where an attacker with only write_policy access could repair a chain to their advantage.

- **`SubmitPointersResponse` mirrors KEL response pattern cleanly.** The `#[must_use]` annotation on the response type and the structured `diverged_at` / `applied` fields give callers actionable information without ambiguity. The handler correctly populates `diverged_at` from `SaveBatchResult::DivergenceCreated`.

- **Test coverage for checkpoint edge cases is thorough.** Nine new checkpoint-specific tests in `verification.rs` cover: v0 with/without checkpoint, first declaration at v1, overdue at boundary, valid cycle through 65 records, policy evolution on checkpoint vs non-checkpoint, is_checkpoint without policy, no-checkpoint chain rejection, and prefix determinism with checkpoint fields.
