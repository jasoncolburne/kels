# Branch Audit: Streaming Verification — 2026-02-27

Automated audit of `kels-52_paginate-kels-requests` branch changes vs `main`. Scope: `git diff main` across all files.

Last reviewed: 2026-03-01

## Summary

| Area | Open | Resolved |
|------|------|----------|
| `lib/kels` (core library) | 5 | 7 |
| Services (`kels`, `identity`, `registry`, `gossip`) | 2 | 3 |
| Clients (`kels-cli`, `kels-ffi`) | 2 | 2 |
| Docs | 0 | 1 |

---

## High Priority

### ~~1. Silent skip on missing public key in `from_branch_tip`/`resume`~~ RESOLVED

Extracted into `branch_state_from_tip()` which returns `KelsError::InvalidKel` on missing public key. Both `from_branch_tip()` and `resume()` call this, failing secure.

### ~~2. Dead anchor-checking code in `verify_inception`~~ RESOLVED

The `event.is_interaction()` check has been removed from `verify_inception()`.

### ~~3. CLI `cmd_get` ignores `has_more`~~ RESOLVED

`cmd_get` now loops through all pages, accumulating events while `has_more` is true.

### ~~4. FFI `kels_status` silent verification failure~~ RESOLVED

Now sets `result.status = KelsStatus::Error` with an error message instead of returning "unknown".

### ~~5. `build_page_bytes` `has_more` always false~~ RESOLVED

Not a bug — `build_page_bytes` is only called for cached full KELs (≤ 512 events). `has_more` is legitimately always false. Single call site, correct by design.

### ~~6. No-op `.gte("serial", 0u64)` filter~~ RESOLVED

Removed. `LockedKelTransaction::load()` now uses offset/limit pagination without the no-op filter.

### ~~7. `ensure_own_kel_synced` single-page limitation~~ RESOLVED

Now implements multi-page loop with `has_more` check.

---

## Medium Priority

### 8. Obfuscated emptiness check — OPEN

**File**: `lib/kels/src/types/verifier.rs:348`

`!new_branches.values().any(|_| true)` should be `new_branches.is_empty()`.

### 9. Operator precedence ambiguity in `completed_verification` — OPEN

**File**: `lib/kels/src/types/verifier.rs:677`

`if !has_more || truncated > 0 && advanced == 0` — add explicit parentheses around the `&&` clause.

### 10. `establishment_kinds()` tautological filter — OPEN

**File**: `lib/kels/src/types/events.rs`

Array omits `Ixn`, then filters by `is_establishment()`. Filter always passes. Either include `Ixn` (so the filter does something) or remove the filter.

### 11. `truncate_incomplete_generation` limitation undocumented — OPEN

**File**: `lib/kels/src/types/verifier.rs`

Cannot detect incomplete generations at the linear-to-divergent transition (both serials have count 1). The verifier handles this via held-back events in `transfer_key_events`, but the limitation of `truncate_incomplete_generation` itself should be documented.

### 12. `PagedKelSource` contract undocumented / `sync_and_verify` lacks held-back protection — OPEN

**File**: `lib/kels/src/types/verifier.rs`

`transfer_key_events` solves page-boundary divergent pair splitting via held-back events. But the older `sync_and_verify` (still present, line 708) lacks this protection. Also, `PagedKelSource` trait doesn't document its contract (ordering, complete generations, `has_more` semantics).

### 13. `verify_anchor` re-verifies full KEL on every call — OPEN

**File**: `lib/kels/src/client/registry.rs`

Clones all cached events and runs full `KelVerifier` from scratch each call. Should cache the `Verification` and only recompute when events change or when different anchors need checking.

### 14. Duplicated "eagerly sync KEL to Raft" calls — OPEN (low)

**File**: `services/kels-registry/src/handlers.rs`

Three handlers call `ensure_own_kel_synced(&state).await` before their main logic. The function itself is extracted (not duplicated), but the pattern could be middleware. Low priority — calling a function three times is not true duplication.

### ~~15. `SubmitKeyEvents` state machine has two code paths~~ RESOLVED

Dead in-memory code path removed. The `apply()` match arm now logs an error and rejects if reached (meaning `member_kel_repo` was not configured — a misconfiguration). Production always uses the DB-backed `apply_submit_key_events` path.

### ~~16. Wrong env var in docs~~ RESOLVED

`KELS_MAX_PAGES_PER_KEL` is correct. The audit originally suggested `KELS_MAX_VERIFICATION_PAGES` but the code confirms `KELS_MAX_PAGES_PER_KEL`.

---

## Low Priority

### ~~17. `MemoryStore` duplicated across test modules~~ RESOLVED

Now a single implementation in `lib/kels/src/store/mod.rs`.

### 18. `create_test_events` duplicated — OPEN

**Files**: `lib/kels/src/store/mod.rs`, `lib/kels/src/store/file.rs`

Identical test helper in two modules. Could consolidate.

### ~~19. Branch reconstruction duplicated in `from_branch_tip` and `resume`~~ RESOLVED

Extracted into shared `branch_state_from_tip()` helper.

### ~~20. Poisoned lock handling inconsistent between test MemoryStores~~ RESOLVED

Single `MemoryStore` remaining — consistency guaranteed.

### 21. Duplicated verify+status display pattern in CLI — OPEN

**File**: `clients/kels-cli/src/main.rs`

`cmd_get()` has two blocks (audit vs non-audit) with identical status display logic. Extract a helper.

### 22. Duplicated pagination loop in CLI — OPEN

**File**: `clients/kels-cli/src/main.rs`

Three near-identical pagination loops (`cmd_get`, `cmd_dev_dump_kel`, `cmd_adversary_inject`).

### 23. Duplicated paginated KEL verification loop in services — PARTIALLY RESOLVED

Main instances replaced with `verify_key_events()` / `forward_key_events()` wrappers. One inline `verify_page()` call remains in `handlers.rs:528` that doesn't use the wrapper.

### 24. Duplicated signed-event assembly pattern — OPEN

**File**: `services/kels/src/repository.rs`

5 instances of the same fetch-signatures-then-zip-with-events pattern. Extract an `assemble_signed_events()` helper.
