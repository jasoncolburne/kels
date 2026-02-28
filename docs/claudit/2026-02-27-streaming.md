# Branch Audit: Streaming Verification — 2026-02-27

Automated audit of `kels-52_paginate-kels-requests` branch changes vs `main`. Scope: `git diff main` across all files.

## Summary

| Area | High | Medium | Low |
|------|------|--------|-----|
| `lib/kels` (core library) | 2 | 6 | 4 |
| Services (`kels`, `identity`, `registry`, `gossip`) | 5 | 3 | 2 |
| Clients (`kels-cli`, `kels-ffi`) | 2 | 0 | 2 |
| Docs | 0 | 1 | 0 |

---

## High Priority

### 1. Silent skip on missing public key in `from_branch_tip`/`resume`

**Affected file**: `lib/kels/src/types/verifier.rs`

Both `KelVerifier::from_branch_tip()` and `KelVerifier::resume()` silently skip branches where `establishment_tip.event.public_key` is `None`. This produces a verifier with empty branches but a non-zero `last_verified_serial`, causing confusing "expected serial 0" errors on subsequent `verify_page()` calls. Should error per fail-secure.

### 2. Dead anchor-checking code in `verify_inception`

**Affected file**: `lib/kels/src/types/verifier.rs`

`verify_inception()` contains an `event.is_interaction()` anchor check that can never be true — inception events are never interactions. The equivalent logic already exists in `verify_generation()`.

### 3. CLI `cmd_get` ignores `has_more`

**Affected file**: `clients/kels-cli/src/main.rs`

`cmd_get` fetches one page from the server and discards the `has_more` flag, silently truncating KELs larger than 512 events.

### 4. FFI `kels_status` silent verification failure

**Affected file**: `lib/kels-ffi/src/lib.rs`

`kels_status` returns "unknown" status when verification fails instead of propagating the error to callers.

### 5. `build_page_bytes` `has_more` always false

**Affected file**: `services/kels/src/handlers.rs`

The `has_more` parameter to `build_page_bytes` is always `false` at all call sites — dead parameter.

### 6. No-op `.gte("serial", 0u64)` filter

**Affected file**: `services/identity/src/handlers.rs`

`LockedKelTransaction::load()` includes `.gte("serial", 0u64)` which matches all rows. No-op filter.

### 7. `ensure_own_kel_synced` single-page limitation

**Affected file**: `services/kels-registry/src/federation/mod.rs`

Fetches only one page (512 events) from the identity service. Long-lived registries with many rotations could exceed this.

---

## Medium Priority

### 8. Obfuscated emptiness check

**Affected file**: `lib/kels/src/types/verifier.rs`

`!new_branches.values().any(|_| true)` should be `new_branches.is_empty()`.

### 9. Operator precedence ambiguity in `completed_verification`

**Affected file**: `lib/kels/src/types/verifier.rs`

`if !has_more || truncated > 0 && advanced == 0` relies on `&&` binding tighter than `||`. Should add explicit parentheses.

### 10. `establishment_kinds()` filter is tautologically true

**Affected file**: `lib/kels/src/types/events.rs`

The array omits `Ixn`, then filters by `is_establishment()` (which is `!Ixn`). Filter always passes. Include `Ixn` so the filter actually filters.

### 11. `truncate_incomplete_generation` limitation undocumented

**Affected file**: `lib/kels/src/types/verifier.rs`

Cannot detect incomplete generations at the linear-to-divergent transition (both serials have count 1). The verifier handles this correctly by deferring branch detection, but the limitation should be documented.

### 12. `sync_and_verify` missing truncation / `PagedKelSource` contract undocumented

**Affected file**: `lib/kels/src/types/verifier.rs`

`sync_and_verify` doesn't call `truncate_incomplete_generation()`. This is correct if `PagedKelSource` guarantees complete generations, but that contract is not documented.

### 13. `verify_anchor` re-verifies full KEL on every call

**Affected file**: `lib/kels/src/client/registry.rs`

Clones all cached events and runs full `KelVerifier` from scratch on each anchor check. Performance concern for frequent anchor verification.

### 14. Duplicated "eagerly sync KEL to Raft" blocks

**Affected file**: `services/kels-registry/src/handlers.rs`

`admin_vote_proposal` duplicates the sync-to-Raft pattern that `ensure_own_kel_synced` encapsulates.

### 15. `SubmitKeyEvents` state machine has two code paths with different semantics

**Affected file**: `services/kels-registry/src/federation/state_machine.rs`

`SubmitKeyEvents` handler has two code paths (first submission vs subsequent) with subtly different verification and storage semantics.

### 16. Wrong env var in docs

**Affected file**: `docs/endpoints.md`

References `KELS_MAX_PAGES_PER_KEL` — should be `KELS_MAX_VERIFICATION_PAGES`.

---

## Low Priority

### 17. `MemoryStore` duplicated across test modules

**Affected files**: `lib/kels/src/store/mod.rs`, `lib/kels/src/types/verifier.rs`

Two separate test `MemoryStore` implementations with identical pagination logic.

### 18. `create_test_events` duplicated

**Affected files**: `lib/kels/src/store/mod.rs`, `lib/kels/src/store/file.rs`

Identical test helper in two modules.

### 19. Branch reconstruction duplicated in `from_branch_tip` and `resume`

**Affected file**: `lib/kels/src/types/verifier.rs`

Same `BranchState` construction from `BranchTip` pattern in both methods. Could extract a shared helper.

### 20. Poisoned lock handling inconsistent between test MemoryStores

**Affected files**: `lib/kels/src/store/mod.rs` (swallows), `lib/kels/src/types/verifier.rs` (panics)

### 21. Duplicated verify+status display pattern in CLI

**Affected file**: `clients/kels-cli/src/main.rs`

Multiple commands repeat the same verify-then-display-status sequence.

### 22. Duplicated pagination loop in CLI

**Affected file**: `clients/kels-cli/src/main.rs`

Same page-fetching loop pattern repeated across commands.

### 23. Duplicated paginated KEL verification loop in services

**Affected files**: `services/kels-registry/src/handlers.rs` (2 instances), `services/kels-gossip/src/hsm_signer.rs`

Three instances of the same paginated-verification-via-`KelVerifier` loop.

### 24. Duplicated signed-event assembly pattern

**Affected file**: `services/kels/src/repository.rs`

4+ instances of the same row-to-`SignedKeyEvent` assembly pattern.
