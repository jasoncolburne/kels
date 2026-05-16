# Branch Audit: Credentials (Round 6) — 2026-03-15

Sixth-pass audit of `credentials` branch changes vs `main`. Scope: full `lib/kels-creds` crate (~4.5K lines across 12 source files) plus changes to `lib/kels`. Diff: ~6.9K lines across 29 files. Focus: verification correctness, constraint enforcement, edge cases.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 1        |
| Low      | 0    | 2        |

All 42 findings from rounds 1–5 remain resolved.

---

## Medium Priority

### ~~1. Edge verification does not enforce the `edge.issuer` or `edge.delegated` constraints~~ — RESOLVED

**File:** `lib/kels-creds/src/verification.rs:224-339`

~~`verify_edges` looks up the referenced credential by `edge.credential` SAID and verifies its integrity, but never checks that the fetched credential's `issuer` matches the `edge.issuer` value. An edge declaring `issuer: Some("EAlice...")` would pass verification even if the actual referenced credential was issued by `"EBob..."`. Additionally, the `edge.delegated` field was declared but never checked during verification.~~

**Resolution:** Three enforcement checks added to `verify_edges`:
1. **`edge.issuer` constraint** (lines 274-283) — if the edge declares an expected issuer, the actual credential's issuer must match or verification fails.
2. **`edge.delegated` constraint** (lines 297-333) — when `delegated: Some(true)`, verifies the issuer's KEL has a `dip` inception (`delegating_prefix` must be present), then verifies the delegating prefix's KEL anchors the issuer's prefix.
3. **`delegating_prefix` propagated** — added to `CredentialVerification` (populated from `KelVerification` after issuer KEL verification) so edge delegation checks can access it without a redundant KEL verification pass.

---

## Low Priority

### ~~2. Edge `delegated` field is declared but never used during verification~~ — RESOLVED

**Files:** `lib/kels-creds/src/edge.rs:22`, `lib/kels-creds/src/verification.rs:297-333`

~~`Edge` has a `pub delegated: Option<bool>` field, but no verification code reads or acts on it.~~

**Resolution:** Resolved as part of finding 1. When `edge.delegated == Some(true)`, `verify_edges` now checks that the issuer's KEL inception is a `dip` and that the delegating prefix's KEL anchors the issuer prefix.

### ~~3. Redundant `.ok_or_else()` on `path.last()` in `navigate_to_field`~~ — RESOLVED

**File:** `lib/kels-creds/src/disclosure.rs:272`

~~`navigate_to_field` returns early with an error if `path.is_empty()` (line 258), so `path.last()` at line 273 can never be `None`. The `.ok_or_else(...)` is dead code.~~

**Resolution:** Replaced with direct indexing `&path[path.len() - 1]`, safe because the empty-path guard on line 257 ensures the slice is non-empty.

---

## Positive Observations

- **All 42 findings from rounds 1–5 are resolved.** The codebase has been through thorough iterative refinement.
- **Edge constraint enforcement is now complete.** `edge.issuer`, `edge.schema`, and `edge.delegated` are all verified during edge credential verification. Delegation verification checks three things: the issuer's KEL has a `dip` inception, a `delegating_prefix` exists, and the delegating prefix's KEL anchors the issuer's prefix.
- **Schema-aware compaction/expansion is well-designed.** Walking the schema alongside the value ensures only intended fields are compacted, and the batch-fetch pattern in `expand_object_with_schema` avoids N+1 store lookups.
- **The verification depth model is sound.** Circular edge references are cryptographically impossible (SAID includes all content), so the `remaining_depth` counter is sufficient — no visited-set needed.
- **Typed and JSON API paths share validation.** Both `Credential::create` and `json_api::create` funnel through `validate_credential_report`, eliminating divergence risk between the two creation paths.
- **`delegating_prefix` propagation avoids redundant KEL verification.** By capturing it from the issuer's `KelVerification` and surfacing it on `CredentialVerification`, the delegation check only needs one additional KEL verification (the delegator's), not a re-verification of the issuer's.
