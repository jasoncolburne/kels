# Branch Audit: KELS-89_scoped-expects (Round 3) — 2026-04-08

Branch `KELS-89_scoped-expects` vs `main`. ~265 diff lines (excluding claudit docs) across 14 source files. All 8 findings from rounds 1-2 are resolved.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 1        |
| Medium   | 0    | 1        |
| Low      | 0    | 1        |

---

## High Priority

### ~~1. `kels_init` NULL algorithm is now a hard error but Swift client defaults to `nil`~~ — RESOLVED

**File:** `lib/ffi/src/lib.rs:385-392`, `clients/ios/Sources/KelsCore/KelsClient.swift:19-22`

~~The Swift client declares `signingAlgorithm: String? = nil` and `recoveryAlgorithm: String? = nil` as default parameters. When callers omit these, Swift passes null pointers to the FFI. Before this branch, `parse_algorithm` silently defaulted to `MlDsa65`. Now, `parse_algorithm_option` returns `None` for null, and `kels_init` returns null with "Invalid or missing signing algorithm."~~

~~This is a **breaking API change** for all Swift callers that rely on the default `nil` behavior — `KelsClient(kelsURL: url, keyNamespace: ns)` will now throw instead of succeeding. The doc comment on `kels_init` (lines 339-341) still says "NULL defaults to secp256r1", compounding the confusion.~~

**Resolution:** Updated Swift client to use `String = "secp256r1"` (non-optional with explicit default) instead of `String? = nil` for both algorithm parameters. Updated `kels_init` doc comment to say "Required. Returns NULL on error if absent or unrecognized."

---

## Medium Priority

### ~~2. `decode_stale_value` malformed else-branch still uses `retries: 0, not_before: 0` (fail-open)~~ — RESOLVED

**File:** `services/gossip/src/sync.rs:1000-1004`

~~The round 2 fix correctly addressed parse failures within the 3-part format (defaulting to `u64::MAX` and `MAX_STALE_RETRIES`). However, the `else` branch for completely malformed entries (less than 3 colon-separated parts) still uses `(value.to_string(), 0, 0)` — retries=0 and not_before=0, which means immediate retry with no backoff. This is the same fail-open pattern that was fixed for the inner parse failures. A truly corrupted entry would trigger immediate unbounded retries.~~

**Resolution:** Changed else-branch to `(value.to_string(), MAX_STALE_RETRIES, 0)` — malformed entries are due immediately but at max retries, so they get cleaned up on the next drain cycle rather than retried indefinitely.

---

## Low Priority

### ~~3. `kels_init` doc comment says "NULL defaults to secp256r1" but NULL is now an error~~ — RESOLVED

**File:** `lib/ffi/src/lib.rs:339-342`

~~The doc comment still reads:~~
- ~~`signing_algorithm` — `NULL defaults to "secp256r1"`~~
- ~~`recovery_algorithm` — `NULL defaults to "secp256r1"`~~

~~This is stale after the change to reject NULL. Even if finding #1 is resolved by updating the Swift client (option b), the doc comment needs updating to reflect the new behavior.~~

**Resolution:** Updated doc comment to say "Required. Returns NULL on error if absent or unrecognized." (fixed as part of finding #1).

---

## Positive Observations

- **Clean resolution of all prior findings.** All 8 findings across rounds 1-2 (4 medium, 4 low) have been resolved, including the `Duration::MAX` fail-secure fix, `read_error_body` encapsulation, and `decode_stale_value` inner-parse defaults.

- **`read_error_body` is a well-designed helper.** Both implementations (kels-core and exchange) correctly preserve the HTTP status code when `resp.text()` fails, which was the key information being lost by `unwrap_or_default`. The `pub(crate)` scoping is correct.

- **Credential FFI error handling is improved.** The `kels_credential_build` change properly separates the `from_str` parse from the outer `to_string` serialization, giving distinct error messages for each failure mode rather than silently producing `Value::Null`.

- **Consistent `#[allow(clippy::expect_used)]` placement.** The per-site allows on truly infallible operations (`UNIX_EPOCH`, `postcard` on known struct, `ENCAP_KEY_KIND`) are well-justified with descriptive panic messages, while the crate-level allow in bench avoids annotation clutter.

- **`parse_pubsub_message` is a model simplification.** The `split_once` replacement is shorter, more correct (rejects colon-less messages), and has proper test coverage for both `None` and empty-SAID cases.

- **Fail-secure defaults are applied consistently.** Clock skew → `Duration::MAX` (forces rotation), missing divergent field → error (not silent false), stale parse failures → `u64::MAX`/`MAX_STALE_RETRIES` (skip/cleanup rather than immediate retry). The branch demonstrates a systematic approach to the fail-secure principle.
