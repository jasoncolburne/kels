# Branch Audit: KELS-89_scoped-expects (Round 1) — 2026-04-08

Branch `KELS-89_scoped-expects` vs `main`. ~440 diff lines across 12 files. Audit of `unwrap_or` → `expect`/error-propagation changes per issue #89.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 3        |
| Low      | 0    | 2        |

---

## Medium Priority

### ~~1. `parse_algorithm` is now a trivial wrapper around `parse_algorithm_option`~~ — RESOLVED

**File:** `lib/ffi/src/lib.rs:304-306`

~~`parse_algorithm` now just calls `parse_algorithm_option` and returns the result unchanged. This adds an unnecessary indirection layer. Consider inlining — replace the two `parse_algorithm(...)` calls in `kels_init` with `parse_algorithm_option(...)` and remove `parse_algorithm` entirely.~~

**Resolution:** Removed `parse_algorithm` wrapper. Callers in `kels_init` now call `parse_algorithm_option` directly.

### ~~2. `resp.text().await?` loses HTTP status code context in error paths~~ — RESOLVED

**Files:** `lib/exchange/src/client.rs`, `lib/kels/src/client/sadstore.rs`, `lib/kels/src/types/sad/sync.rs`

~~When `resp.text().await` fails (e.g., connection reset mid-body), the `?` operator converts it to `KelsError::HttpError` / `MailClientError::Request`, losing the fact that the server returned an error status code (4xx/5xx). The previous code (`unwrap_or_default`) lost the body text but preserved the `ServerError`/`Http` variant with the status code.~~

**Resolution:** Added `read_error_body` helpers: `lib/kels/src/error.rs` for `KelsError` (uses `map_err` to wrap body-read failure with HTTP status in `ServerError` variant) and `lib/exchange/src/client.rs` for `MailClientError` (returns `(StatusCode, String)` tuple, wrapping body-read failure in `Http` variant). All call sites updated.

### ~~3. Clock skew handling defaults to `Duration::ZERO` (fail-open for rotation)~~ — RESOLVED

**File:** `services/identity/src/server.rs:628-633`

~~When clock skew is detected (latest binding timestamp in the future), the age defaults to `Duration::ZERO`, which means `age > rotation_interval()` returns `false` — i.e., "don't rotate." Per CLAUDE.md's fail-secure principle, the safe default when timing is unknown would be to rotate (return `Duration::MAX` or equivalent). The warning log is good, but the behavior is still fail-open for the rotation decision.~~

**Resolution:** Changed to `Duration::MAX` with updated warning message: "Clock skew detected: latest binding timestamp is in the future, forcing rotation". Now fail-secure — clock skew triggers rotation.

---

## Low Priority

### ~~4. Redundant `#[allow(clippy::expect_used)]` placement in bench~~ — RESOLVED

**File:** `clients/bench/src/main.rs:202-204`

~~The `#[allow(clippy::expect_used)]` on line 202 is placed before a `let` binding. This works, but the bench crate's `Cargo.toml` already has `expect_used = "deny"`, so the allow is necessary. However, the bench crate could arguably use a crate-level `#![allow(clippy::expect_used)]` since panicking in a benchmark tool is always acceptable, avoiding per-site annotations.~~

**Resolution:** Added `#![allow(clippy::expect_used)]` at crate level in `clients/bench/src/main.rs` and removed both per-site annotations.

### ~~5. `kels_client/kels.rs:294` — `divergent` field defaults to `false` (not addressed)~~ — RESOLVED

**File:** `lib/kels/src/client/kels.rs:291-294`

~~The `divergent` field from the effective SAID response still uses `.unwrap_or(false)`. If the JSON response doesn't contain the `divergent` field or it's not a boolean, the client silently assumes "not divergent." In a security context, unknown divergence status could arguably be treated as divergent (fail-secure).~~

**Resolution:** Now returns `KelsError::HttpError("missing or invalid 'divergent' field in effective SAID response")` when the field is absent or not a boolean.

---

## Positive Observations

- **Systematic audit with clear categorization.** The branch correctly distinguishes between legitimate defaults (query params, config values, Option semantics) and bug-masking patterns, leaving ~50+ legitimate uses untouched.

- **Fail-secure `parse_pubsub_message` simplification.** Replacing 4 lines with `message.split_once(':')` is both more idiomatic and more correct — a colon-less message is now properly rejected as malformed rather than silently producing an empty SAID.

- **FFI safety preserved.** The FFI changes correctly avoid `expect`/`panic` across FFI boundaries, using `set_last_error` + null-return patterns instead. The `parse_algorithm` change properly validates crypto algorithm selection at init time.

- **Startup vs runtime distinction.** The branch correctly uses `expect` for startup-only code (HSM_SLOT parse, getrandom, ENCAP_KEY_KIND) while using error propagation for runtime service code, following the principle that services should not crash during normal operation.

- **Good test coverage for behavior change.** The `parse_pubsub_message` behavior change (colon-less messages now return `None`) is accompanied by a new test `test_parse_pubsub_no_colon_returns_none`, and the existing test was updated to test the `"prefix:"` case explicitly.

- **Warning logs for soft failures.** The `decode_stale_value` parse errors and identity clock skew detection now emit `warn!` logs, making previously-silent failures observable without crashing the service.
