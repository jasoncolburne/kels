# Branch Audit: KELS-113_identity-pointers (Round 3) — 2026-04-16

Branch `KELS-113_identity-pointers` vs `main`: ~1078 insertions, 192 deletions across 19 files. Focus on handler-level duplication, API surface, and edge cases in the transactional verify-then-extend flow.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 1        |
| Low      | 0    | 1        |

Prior rounds: 10 findings, all resolved.

---

## Medium Priority

### ~~1. Duplicated pagination loop in handler normal and repair paths~~ — RESOLVED

**Files:** `services/sadstore/src/handlers.rs:1238-1275` (repair) and `services/sadstore/src/handlers.rs:1302-1339` (normal)

~~Both paths have ~35 lines of nearly identical pagination logic: initialize `since`, loop calling `get_stored_in`, break on empty, update cursor, call `verify_page`, break on short page. The only difference is the error message string ("repair" vs "existing"). A bug fix to cursor handling or page-boundary logic must be replicated in both blocks.~~

**Resolution:** Extracted `verify_existing_chain()` helper function that encapsulates the pagination loop. Both paths now call it and handle the rollback on error.

---

## Low Priority

### ~~2. Redundant `+ 'a` lifetime bound on `PolicyChecker` trait object~~ — RESOLVED

**File:** `lib/kels/src/types/sad/verification.rs:70`

~~`checker: &'a (dyn PolicyChecker + 'a)` — the explicit `+ 'a` is the default for `&'a dyn Trait` per Rust's lifetime elision rules. `&'a dyn PolicyChecker` is equivalent and more idiomatic.~~

**Resolution:** Changed to `checker: &'a dyn PolicyChecker`.

---

## Positive Observations

- **`read_policy` removal from `SignedSadFetchRequest` is safe.** The server looks up the record's readPolicy from the SAID-verified custody record — the client-side declaration was redundant since the server is authoritative about which policy governs a record. Removing it simplifies the API without weakening security.

- **Transactional verify-then-extend is sound.** The handler's flow (begin tx → advisory lock → verify/write → commit, with rollback on any failure) eliminates the TOCTOU window. The repair path correctly writes first (within tx), then verifies the resulting chain — a verification failure rolls back the truncation and archival cleanly since all side effects are SQL-only (no MinIO).

- **`save_batch` divergence check complements verifier.** The verifier allows divergent chains to verify structurally (tracking multiple branches), while `save_batch` enforces the "frozen chain" policy at the database level. These are separate concerns at different layers — structural validity vs. operational policy — correctly layered.

- **Shell script anchoring order is correct.** `load-sad.sh` anchors each version's SAID in the KEL sequentially before batched submission. Since the server re-verifies the entire chain with policy checks on submit, the anchoring must precede submission, not individual record construction. The sequential anchor → batch submit pattern is correct.

- **`cmd_exchange_lookup_key` correctly skips policy upload.** Lookup only needs the policy SAID to compute the chain prefix — no server-side policy object required. Read paths don't trigger writes.
