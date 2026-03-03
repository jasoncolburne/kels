# Security Invariant

The database cannot be trusted — it may have been altered. All operations on KEL data fall into three categories:

## Operation Categories

### 1. Serving

Returning data to a client or peer. **No verification needed** — the receiver is responsible for verifying what they get.

Examples: `GET /api/kels/kel/:prefix`, `get_effective_said`, `get_key_events`

### 2. Consuming

Using data for security decisions (anchoring, key extraction, divergence routing, merge decisions). **MUST verify the full KEL first.** The only way to access consumed data is through `Verification`, which can only be obtained via `KelVerifier::into_verification()`. This eliminates TOCTOU vulnerabilities — verification and data access happen in the same pass.

Examples: peer signature verification (`verify_signature_with_ctx`), anchor checking, submit handler routing decisions

### 3. Resolving

Comparing state to decide whether to sync. A wrong answer triggers an unnecessary sync (which itself verifies), not a security hole. Standalone functions are acceptable here without full verification.

Examples: `effective_tail_said` endpoint, anti-entropy comparison, `should_add_rot_with_recover()`

## `Verification` as Proof of Verification

Functions that consume KEL data accept `&Verification` as a parameter. Having a `Verification` proves the KEL was verified. `Verification` fields are private with no public constructor — the only way to obtain one is through `KelVerifier`.

## Merge Verification

When merging new events into an existing KEL (submit handler), first verify the entire existing KEL in the DB using `KelVerifier` with paginated reads under an advisory lock. Call `into_verification()` to get a trusted context (don't re-query the DB — use the verified data). Then use that context to verify the new incoming events.

## Inline Anchor Checking

Register SAIDs to check with `KelVerifier::check_anchors()` before the walk. The verifier checks anchors as it iterates through events. Results are available via `Verification::anchored_saids()`. No separate DB queries for anchoring.

## Advisory Locking

All verify-then-write paths hold PostgreSQL advisory locks for the duration of both verification and write. The `PageLoader` trait enables this — `KelTransaction` and `LockedKelTransaction` implement `PageLoader` by reading under the advisory lock, then the same transaction is used for the write. This eliminates time-of-check-to-time-of-use vulnerabilities.
