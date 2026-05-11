# Branch Audit: KELS-89_scoped-expects (Round 2) — 2026-04-08

Branch `KELS-89_scoped-expects` vs `main`. ~272 diff lines (excluding claudit doc) across 15 source files. Audit of `unwrap_or` → `expect`/error-propagation changes. All 5 findings from round 1 are resolved.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 1        |
| Low      | 0    | 2        |

---

## Medium Priority

### ~~1. `read_error_body` in `kels-core` is `pub` but should be `pub(crate)`~~ — RESOLVED

**File:** `lib/kels/src/error.rs:187` and `lib/kels/src/lib.rs:76`

~~`read_error_body` is exported as a public item from `kels-core` (`pub use error::{KelsError, read_error_body}`). This is an internal HTTP client helper — the only callers are `client/sadstore.rs` and `types/sad/sync.rs`, both within `kels-core`. The exchange crate has its own separate `read_error_body` (correctly `pub(crate)`). Exporting this from `kels-core`'s public API leaks an implementation detail and ties the public surface to `reqwest::Response`.~~

**Resolution:** Changed to `pub(crate)` in `error.rs` and removed from the `pub use` re-export in `lib.rs`.

---

## Low Priority

### ~~2. Comment on `parse_algorithm_option` says `None` = "keep current" but callers treat `None` as hard error~~ — RESOLVED

**File:** `lib/ffi/src/lib.rs:300`

~~The comment on the `_ => None` arm says `// null, empty, or unrecognized = keep current`, but after the round 1 fix, callers in `kels_init` (lines 385-392) treat `None` as a hard failure ("Invalid or missing signing/recovery algorithm"). The comment is now misleading — `None` no longer means "keep current," it means "invalid."~~

**Resolution:** Updated comment to `// null, empty, or unrecognized = invalid`.

### ~~3. `decode_stale_value` defaults to `0` on parse failure — fail-open for backoff~~ — RESOLVED

**File:** `services/gossip/src/sync.rs:982-998`

~~When `not_before` fails to parse, it defaults to `0`, meaning the entry is immediately due for retry (since `now >= 0` is always true). When `retries` fails to parse, it defaults to `0`, resetting the exponential backoff counter. Both are fail-open behaviors — a corrupted Redis entry would cause immediate unbounded retries. This is a gossip anti-entropy path (not a security decision path), so the blast radius is limited to unnecessary sync traffic, but it could amplify load during Redis corruption.~~

**Resolution:** Changed `not_before` default to `u64::MAX` (entry is never due, effectively skipped) and `retries` default to `MAX_STALE_RETRIES` (cleaned up on next attempt rather than infinite retries).

---

## Positive Observations

- **Clean resolution of all round 1 findings.** All 5 findings (3 medium, 2 low) from round 1 have been addressed. The `read_error_body` helper pattern, `Duration::MAX` fail-secure default, crate-level `#![allow]`, and `divergent` field validation are all solid fixes.

- **Consistent `read_error_body` pattern across crates.** Both `kels-core` and `kels-exchange` implement the same pattern but tailored to their respective error types (`KelsError::ServerError` vs `MailClientError::Http`), preserving HTTP status context that `unwrap_or_default` was losing.

- **`split_once` is the right primitive.** The `parse_pubsub_message` simplification from 4 lines to `message.split_once(':')` is textbook — it's more correct (rejects colon-less messages) and the tests are updated to cover both the `None` and empty-SAID cases.

- **Appropriate `#[allow(clippy::expect_used)]` scoping.** The `expect` annotations are well-placed: crate-level in bench (panicking is fine for a load testing tool), per-site in libraries for truly infallible operations (`getrandom`, `postcard` on a known struct, `UNIX_EPOCH`), and avoided entirely in FFI and runtime service code.

- **`kels_init` algorithm validation is now fail-secure.** Previously, passing `NULL` or an unrecognized algorithm string silently defaulted to ML-DSA-65. Now it returns null with a clear error message, preventing callers from accidentally running with an unexpected algorithm.

- **`ENCAP_KEY_KIND` fallback removed.** The old `unwrap_or_else(|_| CString::new(...).unwrap_or_default())` was a double-fallback that could produce an empty string if both `CString::new` calls failed. The new `expect` is correct — `ENCAP_KEY_KIND` is a compile-time constant with no null bytes.
