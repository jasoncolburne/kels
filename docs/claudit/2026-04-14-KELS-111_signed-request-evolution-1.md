# Branch Audit: KELS-111_signed-request-evolution (Round 1) — 2026-04-14

Branch `KELS-111_signed-request-evolution` vs `main`: 22 files changed, +598/-381 lines. Multi-signer `SignedRequest`, SAID-based signatures, `SelfAddressed` bound on payloads, `created_at` replaces `timestamp`.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 1        |
| Medium   | 0    | 2        |
| Low      | 0    | 2        |

---

## High Priority

### ~~1. `verify_signatures` calls `verify_said()` redundantly per signer~~ — RESOLVED

**File:** `lib/kels/src/types/auth.rs:49-51, 69-83`

~~`verify_one()` calls `self.payload.verify_said()` on every invocation. When `verify_signatures()` iterates N signers, the SAID is recomputed and verified N times — once per signer. SAID verification is a Blake3 hash + JSON serialization of the payload, which for large payloads (e.g., `ReplicateRequest` containing a full `MailMessage`) is non-trivial.~~

~~More importantly, if `verify_said()` fails, it fails identically for all signers (it's a property of the payload, not the signer). Calling it once before the loop would be both correct and efficient.~~

**Resolution:** Extracted signature-only verification into private `verify_signature_only()`. `verify_one()` still checks SAID for standalone callers. `verify_signatures()` checks SAID once upfront and returns empty set on failure, then uses `verify_signature_only()` for the per-signer loop.

---

## Medium Priority

### ~~2. `authenticate_request` in mail fails hard on any KEL verification failure~~ — RESOLVED

**File:** `services/mail/src/handlers.rs:188-201`

~~In the multi-signer loop, if *any* signer's KEL verification fails (e.g., KELS service unreachable for that prefix), the entire request is rejected with `403 Forbidden`. This is inconsistent with the design intent of `verify_signatures()` which silently excludes unverified signers and lets callers check the threshold.~~

~~The sadstore handler has the same pattern (line 274-282). The kels handler does too (line 707-715).~~

**Resolution:** Changed all three handlers (mail, sadstore, kels) to `continue` on KEL verification failure instead of returning an error. Unverifiable signers are skipped; the `verified.is_empty()` check after the loop catches the case where no signers verify at all.

### ~~3. Nonce type mismatch in shell test scripts~~ — RESOLVED

**File:** `clients/test/scripts/test-sadstore.sh:231-233`

~~The static nonces in `test-sadstore.sh` are plain strings like `"test"`, `"test2"`, `"test3"`. `cesr::Nonce256` is a CESR-encoded 256-bit nonce (44 characters with type prefix). If the test endpoints deserialize the `SignedRequest` (which they do — they just skip auth), these nonces will fail to parse as `cesr::Nonce256`.~~

**Resolution:** Added `MOCK_NONCE="NAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"` constant and replaced the plain-string nonces with `${MOCK_NONCE}`.

---

## Low Priority

### ~~4. Unused `SelfAddressed` import in `lib/exchange/src/client.rs`~~ — RESOLVED

**File:** `lib/exchange/src/client.rs:6`

~~`use verifiable_storage::SelfAddressed;` is imported but never used directly — `create()` and `get_said()` are called on concrete types that already have the trait in scope via their derive.~~

**Resolution:** False positive. The import is required for `get_said()` trait method resolution on the concrete types. Clippy does not flag it as unused. No change needed.

### ~~5. Comment says `new()` but code uses `create()` in tamper test~~ — RESOLVED

**File:** `lib/kels/src/types/auth.rs:345`

~~Comment says `"Deliberately use new() + derive_said() so we can mutate after to simulate tampering"` but the code actually uses `TestPayload::create(...)`. The comment is stale from an earlier iteration.~~

**Resolution:** Updated comment to: `"Create normally, then mutate after to simulate tampering"`.

---

## Positive Observations

- **SAID verification in `verify_one` is fail-secure.** Verifying the payload SAID before checking the signature ensures tampered payloads are caught even if an attacker somehow produces a valid signature over the original SAID. Defense in depth.

- **`verify_signatures` returns `HashSet` not `Result`.** This design correctly separates "which signatures are valid" from "is the set sufficient" — callers make the threshold decision, and partial verification is a first-class result rather than an error.

- **`single_signer` consolidated into `lib/kels`.** Having one implementation with `KelsError` that each service maps to its own error type eliminates the risk of inconsistent validation logic across services.

- **`created_at` via `#[created_at]` attribute.** Using the `SelfAddressed` derive's auto-timestamping instead of manual `Utc::now().timestamp()` eliminates an entire class of caller mistakes (wrong clock, forgotten timestamp, stale timestamp from reused structs).

- **Request type consolidation.** Moving `ReplicateRequest` and `RemoveRequest` from duplicate definitions in the exchange client and mail handler into the canonical `mail.rs` module eliminates a maintenance hazard where the two copies could drift.

- **Comprehensive test coverage for the new verification API.** Five tests cover: divergent KEL rejection, valid single-signer, multi-signer round-trip, partial invalid signatures, and SAID tamper detection. These directly exercise the security-critical code paths.
