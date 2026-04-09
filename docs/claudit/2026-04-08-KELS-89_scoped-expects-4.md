# Branch Audit: KELS-89_scoped-expects (Round 4) — 2026-04-08

Branch `KELS-89_scoped-expects` vs `main`. ~340 diff lines (excluding claudit docs) across 15 source files. All 11 findings from rounds 1-3 are resolved. No new findings.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 0        |
| Low      | 0    | 0        |

---

No open findings. All 11 findings from rounds 1-3 (1 high, 5 medium, 5 low) have been resolved.

---

## Positive Observations

- **Complete resolution of all prior findings.** All 11 findings across 3 audit rounds have been addressed — including the high-priority Swift API breaking change (round 3), the fail-secure defaults for clock skew and stale entry parsing (rounds 1-2), and the `read_error_body` encapsulation fix (round 2).

- **`read_error_body` preserves status context without over-engineering.** Both implementations (kels-core and exchange) are minimal — just capture the status before consuming the response, and wrap body-read failures with the status. No unnecessary abstraction or shared trait despite the similar pattern across crates.

- **Consistent fail-secure defaults throughout.** Clock skew → `Duration::MAX` (forces rotation), missing divergent field → hard error, stale `not_before` parse failure → `u64::MAX` (skip), stale `retries` parse failure → `MAX_STALE_RETRIES` (cleanup), malformed stale entry → `MAX_STALE_RETRIES` (cleanup). Every ambiguous case defaults to the restrictive behavior.

- **Clean `#[allow(clippy::expect_used)]` discipline.** Crate-level in bench (where panics are acceptable), per-site with descriptive messages for truly infallible operations (`UNIX_EPOCH`, `getrandom`, `ENCAP_KEY_KIND`, `postcard` on known struct), and completely avoided in FFI and runtime service code. The allow annotations serve as documentation of invariants.

- **Swift client API is now explicit.** Changing from `String? = nil` to `String = "secp256r1"` is the right resolution — the default is visible in the API signature, no null pointer crosses the FFI boundary, and callers who want a different algorithm must specify it explicitly.

- **`decode_stale_value` is well-structured for debugging.** The per-field `match` with `warn!` logs that include the full entry value makes Redis corruption immediately diagnosable from logs, while the fail-secure defaults prevent cascading load amplification.
