# Branch Audit: KELS-111_signed-request-evolution (Round 2) — 2026-04-14

Branch `KELS-111_signed-request-evolution` vs `main`: 23 files changed, +708/-380 lines. Multi-signer `SignedRequest`, SAID-based signatures, `SelfAddressed` payloads, `created_at` replaces `timestamp`. All 5 findings from round 1 are resolved.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 2        |
| Low      | 0    | 1        |

---

## High Priority

(none)

---

## Medium Priority

### ~~1. Unbounded signature count enables per-request DoS amplification~~ — RESOLVED

**File:** `services/mail/src/handlers.rs:183-199`, `services/kels/src/handlers.rs:696-721`, `services/sadstore/src/handlers.rs:262-288`

~~All three authentication loops iterate over `signed_request.signatures.keys()` without bounding the count. An attacker can include many fake prefixes in a single request, each triggering KEL verification HTTP calls or registry refreshes. Amplification went from O(1) to O(N) per request.~~

**Resolution:** Added `TODO(#105)` comments at all three authentication loops. The actual fix — filtering signatures down to only prefixes referenced by the applicable policy before iterating — lands with custody/access control in KELS-105. A hard cap was intentionally not added now to avoid an arbitrary limit that the policy system will replace.

### ~~2. Removed `sender_serial` ESSR envelope check in `send_mail`~~ — RESOLVED

**File:** `services/mail/src/handlers.rs:326`

~~The previous code verified that the ESSR envelope's `sender_serial` matched the sender's current establishment event serial. This was removed in the multi-signer refactor.~~

**Resolution:** Removal is intentional. `SignedRequest` authentication already proves the sender holds the current key. The recipient independently verifies the envelope signature against the `sender_serial` via `open()`. Added a comment at the former check location documenting this rationale.

---

## Low Priority

### ~~3. Identity handler uses `verify_signatures` + `single_signer` where `verify_one` suffices~~ — RESOLVED

**File:** `services/identity/src/handlers.rs:306-310`

~~The identity `manage_kel` handler builds a `HashMap` with a single entry and calls `verify_signatures` + `single_signer` instead of using `verify_one` directly.~~

**Resolution:** Pattern is deliberate. `verify_one` includes `verify_said()` per call, while `verify_signatures` deduplicates the SAID check (once upfront). Using `verify_one` directly would bypass that optimization and set a bad precedent for future multi-signer endpoints. No change needed.

---

## Positive Observations

- **SAID-based signing eliminates serialization ambiguity.** Signing `payload.get_said().qb64b()` instead of serialized JSON removes an entire class of canonicalization bugs. Different serializers producing different JSON byte orders would previously produce different signatures; now they all produce the same SAID.

- **`SelfAddressed` bound on `SignedRequest<T>` is enforced at the type level.** The `T: SelfAddressed` bound on the struct means you can't construct a `SignedRequest` with a payload that doesn't have a SAID — compile-time prevention rather than runtime checks.

- **`verify_signatures` correctly separates verification from policy.** Returning `HashSet<Digest256>` lets callers apply different policies (single signer, threshold, any-of) without the verification code knowing about them. The mail handlers use `single_signer()` for user endpoints and `verified.is_empty()` for gossip endpoints — clean separation.

- **Request type consolidation into `lib/exchange/src/mail.rs`.** Moving `ReplicateRequest` and `RemoveRequest` from inline definitions in the mail handler to the shared exchange library eliminates duplicate type definitions and makes the types available to the client.

- **Shell test scripts use proper CESR mock values.** `MOCK_SAID`, `MOCK_NONCE`, etc. are valid CESR-encoded values with correct type prefixes, preventing deserialization failures at test endpoints.

- **`verify_signature_only` private helper avoids redundant SAID checks.** The separation between `verify_one` (checks SAID + signature) and `verify_signature_only` (signature only) means `verify_signatures` pays the SAID cost once, not per-signer.
