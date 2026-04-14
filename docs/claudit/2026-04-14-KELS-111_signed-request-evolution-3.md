# Branch Audit: KELS-111_signed-request-evolution (Round 3) — 2026-04-14

Branch `KELS-111_signed-request-evolution` vs `main`: 24 files changed, +781/-380 lines. Multi-signer `SignedRequest`, SAID-based signatures, `SelfAddressed` payloads, `created_at` replaces `timestamp`, base64 encoding switched to URL-safe no-pad. All 8 findings from rounds 1-2 are resolved.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 1        |
| Low      | 0    | 1        |

---

## High Priority

(none)

---

## Medium Priority

### ~~1. `refresh_verified_peers` called per unknown prefix in the signer loop~~ — RESOLVED

**File:** `services/kels/src/handlers.rs:700-706`, `services/sadstore/src/handlers.rs:266-272`

~~In the old single-signer code, `refresh_verified_peers` was called at most once per request. The multi-signer loop now calls it for every unknown prefix: if an attacker submits N fake prefixes not in the Redis cache, the handler makes N HTTP round-trips to the registry to refresh the peer list. Each refresh fetches the full peer list from every registry URL, so this is O(N * R) HTTP calls per request (where R is the number of registry URLs).~~

~~This is a specific amplification vector beyond the general TODO(#105) note. The TODO covers filtering by policy before iterating, but even with policy filtering, calling refresh inside the loop is wasteful — a single refresh populates the cache for all peers.~~

**Resolution:** Hoisted refresh outside the loop in both handlers. A pre-scan checks if any prefix is unknown; if so, `refresh_verified_peers` is called once. The main verification loop then skips unknown prefixes with a simple `continue`.

---

## Low Priority

### ~~2. `MOCK_SAID` and `MOCK_PREFIX` share the same value in test scripts~~ — RESOLVED

**File:** `clients/test/scripts/test-bootstrap.sh:24-25`, `clients/test/scripts/test-kel-consistency.sh:44-45`, `clients/test/scripts/test-sad-consistency.sh:33-34`, `clients/test/scripts/test-sadstore.sh:25-26`

~~Both `MOCK_SAID` and `MOCK_PREFIX` are set to `KAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`. Since test endpoints skip auth, this works, but identical values mean a bug that swaps `said` and `prefix` (or `signatures` key) in the JSON body would not be caught by these tests.~~

**Resolution:** Replaced all MOCK_ constants with descriptive, self-documenting values using the existing project convention: `KMOCK_SAID__...`, `KMOCK_PREFIX__...`, `0CMOCK_SIGNATURE__...`, `NMOCK_NONCE__...`. All values are now distinct and padded to the correct CESR length (44 chars for digests/nonces, 88 for signatures).

---

## Positive Observations

- **Coordinated base64 encoding change.** Switching from `STANDARD` to `URL_SAFE_NO_PAD` in both the exchange client (`client.rs:110`) and the mail handler's `base64_decode` (`handlers.rs:601`) is a clean, complete change with no missed decode sites. URL-safe no-pad is the better choice for CESR-adjacent data.

- **`RemoveRequest.said` renamed to `target_said`.** This avoids confusion with the SAID of the request itself (the `#[said]` field). Clear naming that distinguishes "the SAID of this self-addressed request" from "the SAID of the mail message being removed."

- **`authenticate_request` returns `HashSet` not `AuthResult`.** Removing the `AuthResult` wrapper and returning the verified set directly gives callers full flexibility — `single_signer()` for user endpoints, `is_empty()` for gossip endpoints. Cleaner than a struct that only carried `establishment_serial`.

- **`sender_serial` removal is well-documented.** The comment at `handlers.rs:322-323` explains the security rationale for removing the check — `SignedRequest` authentication proves current key, and the recipient independently verifies via `open()`. This prevents future maintainers from re-adding the check.

- **CLAUDE.md additions are precise and actionable.** The `create()` vs `new()` guidance and the SAID-signing convention are written as unambiguous rules with clear exceptions, not vague suggestions. This will prevent the most common misuse patterns.

- **Identity client signing comment explains the `as_ref()` vs `qb64b()` divergence.** At `identity.rs:207-208`, the comment explains why `as_ref()` is used instead of the usual `qb64b()` — the identity sign endpoint takes `&str`, not `&[u8]`. Both produce identical bytes. This prevents a future maintainer from "fixing" it to match the other callers.
