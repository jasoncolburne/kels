# Streaming Verification Architecture

This document describes the verification architecture used by KELS to validate Key Event Logs without loading entire KELs into memory.

## Design Motivation

A KEL can be arbitrarily large (thousands of events). Loading an entire KEL into memory creates an unbounded resource consumption vector. The streaming verification architecture processes events page by page, maintaining only the cryptographic state needed to continue verification.

## Core Components

### KelVerifier

The sole verification mechanism for KELs. Walks forward through events, tracking per-branch cryptographic state.

**State:**
- `branches: HashMap<String, BranchState>` — per-branch state keyed by tip SAID
- `last_verified_serial` — current position in the chain
- `diverged_at_serial` — where divergence was first detected
- `is_contested` — whether a contest event was seen
- `queried_saids` / `anchored_saids` — inline anchor checking

**Constructors:**
- `new(prefix)` — from inception. Full verification of untrusted KELs.
- `resume(prefix, &KelVerification)` — continue from a verified `KelVerification` token. Used for appending events to a known-good KEL.
- `from_branch_tip(prefix, &BranchTip)` — resume from a specific branch. Used in divergence/recovery paths.

**Processing:** Events are processed in **generations** (all events at a given serial). `verify_page()` groups events by serial, then calls `verify_generation()` for each group. On divergence (more events than expected branches at a serial), the verifier forks `BranchState` — each new event is matched to its branch via the `previous` pointer.

### KelVerification (proof-of-verification token)

`KelVerifier::into_verification()` produces a `KelVerification` — the proof that a KEL was verified. This is the ONLY way to access verified KEL state.

**Fields (all private):**
- `prefix` — the KEL prefix
- `branch_tips: Vec<BranchTip>` — one per branch (1 = linear, N = divergent)
- `is_contested` — whether the KEL is permanently frozen
- `diverged_at_serial` — where divergence occurs
- `anchored_saids` / `queried_saids` — anchor checking results

**Key invariant:** `KelVerification` has no public constructor. The only way to obtain one is through `KelVerifier::into_verification()` or `completed_verification()`. Functions that consume KEL data accept `&KelVerification` to prove the KEL was verified. This eliminates TOCTOU vulnerabilities — verification and data access happen in the same pass.

### BranchTip

Correlates a chain head with its last establishment event:

```
BranchTip {
    tip: SignedKeyEvent,              // latest event on this branch
    establishment_tip: SignedKeyEvent, // last establishment event (provides signing key)
}
```

Non-divergent KELs have one `BranchTip`. Divergent KELs have one per branch.

### PageLoader Trait

Generic trait for loading pages of signed key events. Decouples the verification logic from the storage backend.

Implementations:
- `KelStorePageLoader` — wraps a `KelStore` reference
- `KelTransaction` — reads under a PostgreSQL advisory lock (for verify-then-write paths)
- `LockedKelTransaction` — identity service's advisory-locked transaction wrapper

### completed_verification()

Guard function: pages through a `PageLoader` with `KelVerifier`, calling `truncate_incomplete_generation()` at page boundaries. Returns a trusted `KelVerification` token.

Parameters: `loader`, `prefix`, `page_size`, `max_pages`, `anchors`

The `max_pages` parameter prevents resource exhaustion (default 64 pages = ~2K events). Configurable via `KELS_MAX_VERIFICATION_PAGES`.

### truncate_incomplete_generation()

Safety mechanism for page boundaries. When events at a divergent serial span two pages, the last generation on a page may be incomplete (not all events at that serial are present). This function detects and truncates incomplete trailing generations so they're re-fetched on the next page.

## Operation Categories

All operations on KEL data fall into three categories:

### 1. Serving

Returning data to a client or peer. **No verification needed** — the receiver is responsible for verifying what they get.

Examples: `GET /api/v1/kels/kel/:prefix`, `get_effective_said`, `get_key_events`

### 2. Consuming

Using KEL data for security decisions (anchoring, key extraction, divergence routing, merge decisions). **MUST verify the full KEL first.** The only way to access consumed data is through `KelVerification`, which can only be obtained via `KelVerifier::into_verification()`.

Examples: peer signature verification (`verify_signature`), anchor checking, submit handler routing decisions

### 3. Resolving

Comparing state to decide whether to sync. A wrong answer triggers an unnecessary sync (which itself verifies), not a security hole. Standalone functions are acceptable here without full verification.

Examples: `effective_tail_said` endpoint, anti-entropy comparison, `should_add_rot_with_recover()`

## Inline Anchor Checking

Register SAIDs to check with `verifier.check_anchors(saids)` before starting the walk. As the verifier processes events, it checks each event's `anchor` field against the queried SAIDs. Anchors must be valid CESR digests (Blake3-256, 44-char base64url). Results are available on the `KelVerification` token via `is_said_anchored()` and `anchors_all_saids()`.

This replaces separate DB queries for anchoring — verification and anchor checking happen in a single pass.

## Advisory Locking for TOCTOU Elimination

Verify-then-write paths (submit handler, identity rotation) hold PostgreSQL advisory locks for the duration of both verification and write. The `PageLoader` trait enables this: `KelTransaction` and `LockedKelTransaction` implement `PageLoader` by reading under the advisory lock, then the same transaction is used for the write.

This eliminates time-of-check-to-time-of-use vulnerabilities: the DB state cannot change between verification and the subsequent write.

## DB Trust Model

The database cannot be trusted — it may have been altered (see `docs/protocol-attack-surface.md` for the DB compromise + key compromise attack vector). All consuming operations verify the full KEL before using the data.

With a replicated deployment (recommended), gossip anti-entropy detects and reconciles DB tampering across nodes. Single-node deployments accept the risk of undetected DB compromise.
