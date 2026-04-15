# Branch Audit: KELS-118_consolidate-compaction-and-expansion (Round 2) — 2026-04-14

Post-fix review after all round 1 findings were resolved. 4 files changed, ~439 additions, ~208 deletions. Focus: correctness of shared primitives, behavioral fidelity of callers, error propagation paths.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 0        |
| Low      | 0    | 0        |

All 4 findings from round 1 were resolved. No new issues found in round 2.

---

## Positive Observations

- **`?` propagation inside let-chains is correct.** `expand_at_path` uses `sad_store.load(&digest).await?` inside an `if let ... &&` chain. The `?` correctly propagates store errors out of the function while letting `Ok(None)` (SAID not in store) fall through to `Ok(false)`. This is a subtle but correct use of the pattern.

- **Caller-side state management is consistent.** Both sadstore and creds callers manage `ExpansionState` (or lack thereof) independently. Sadstore checks `state.can_expand()` before calling the shared `expand_at_path` and records afterward, matching the old inline behavior exactly. Creds doesn't need rate-limiting since it's schema-bounded, so it correctly omits state tracking entirely.

- **Double-borrow avoidance via `.to_string()` in `expand_at_path`.** The `target.as_str().map(|s| s.to_string())` allocates a String copy of the SAID before later mutating `*target = expanded`. This is necessary because the `&str` borrow from `target` would conflict with the `*target =` assignment. The clone is minimal (44 bytes) and correct.

- **`compact_at_path` return type difference between shared and creds is intentional.** The shared `compact_at_path` returns `bool` (no error conditions in heuristic compaction), while the creds-local `compact_at_path` returns `Result` (validates schema constraints). Each caller layers its own error policy atop the shared primitives, keeping the shared layer policy-free.

- **`ExpandRecursive` in sadstore correctly handles the budget-exhausted case.** If `state.can_expand()` is false, `kels_core::expand_at_path` is short-circuited. The subsequent `expand_recursive` call on the unexpanded value is harmless — it checks `can_expand()` at entry and returns immediately.

- **`navigate_to_value_mut` with empty path returning `Some(value)` is the right choice.** It makes the function composable — callers can use it uniformly without special-casing the root. The path-specific functions (`expand_at_path`, `compact_at_path`) explicitly guard against empty paths where root-level operations don't make sense.
