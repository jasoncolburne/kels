# Branch Audit: KELS-111_signed-request-evolution (Round 4) — 2026-04-14

Branch `KELS-111_signed-request-evolution` vs `main`: 25 files changed, +856/-380 lines. Multi-signer `SignedRequest`, SAID-based signatures, `SelfAddressed` payloads, `created_at` replaces `timestamp`, base64 URL-safe no-pad, hoisted peer refresh, distinct mock CESR values. All 10 findings from rounds 1-3 are resolved.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 0        |
| Low      | 0    | 0        |

---

## High Priority

(none)

---

## Medium Priority

(none)

---

## Low Priority

(none)

---

## Positive Observations

- **Type-level enforcement of `SelfAddressed` on `SignedRequest<T>`.** The `T: SelfAddressed` bound on the struct itself (not just the impl block) means you cannot construct a `SignedRequest` wrapping a payload that lacks a SAID. This is a compile-time guarantee that eliminates the risk of signing raw JSON — the bound propagates through all handler function signatures, client code, and test code.

- **Clean separation between `verify_one`, `verify_signature_only`, and `verify_signatures`.** The public API offers two entry points: `verify_one` for single-signer callers (checks SAID + signature) and `verify_signatures` for multi-signer callers (checks SAID once, then iterates). The private `verify_signature_only` avoids the redundant SAID check per signer without exposing an unsafe API that skips SAID verification.

- **Consistent authentication pattern across all three services.** The kels, sadstore, and mail handlers all follow the same structure: pre-scan for unknown prefixes, refresh peer cache at most once, build verifications map, call `verify_signatures`, check for empty set. This consistency reduces the risk of one service diverging from the security model.

- **`single_signer()` as a library function.** Extracting this into `lib/kels` means all services share one implementation and one error path for the "expected exactly one signer" check. The `#[allow(clippy::expect_used)]` is correctly scoped to the function, and the `.expect()` is provably safe (guarded by the `len() != 1` early return).

- **Shell test mock values are now type-aware and distinct.** `KMOCK_SAID__...`, `KMOCK_PREFIX__...`, `0CMOCK_SIGNATURE__...`, `NMOCK_NONCE__...` — each uses the correct CESR type prefix (`K` for Blake3-256 digest, `0C` for signature, `N` for nonce) and all values are distinct from each other, preventing accidental field-swap bugs in test JSON bodies.

- **CLAUDE.md additions codify the two most important conventions.** The `create()` vs `new()` guidance and the SAID-signing convention are written as unambiguous rules with clear exceptions. These are the two patterns most likely to be misapplied by future contributors, and having them in CLAUDE.md ensures they're enforced from the start of any new conversation.
