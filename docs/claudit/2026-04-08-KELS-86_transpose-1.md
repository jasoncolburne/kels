# Branch Audit: KELS-86_transpose (Round 1) — 2026-04-08

Branch `KELS-86_transpose` vs `main`: 2 commits, 5 files changed (~78 lines). Refactors `match Option { Some(Ok) => Ok(Some), Some(Err) => Err, None => Ok(None) }` patterns to `.transpose()` across 4 source files.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 0        |
| Low      | 0    | 0        |

No issues found. All findings from the prior round 1 audit (performed on main with these changes uncommitted) remain unchanged — 0 open findings.

---

## Positive Observations

- **Correct `.transpose()` usage in FFI.** `lib/ffi/src/lib.rs:479-489` properly collapses the `Some(Ok)/Some(Err)/None` three-arm match into `Ok/Err` via `.transpose()`, preserving the FFI error path (`set_last_error` + null return). The `d` binding is now `Option<Digest>` directly.

- **Policy one-liner.** `lib/policy/src/policy.rs:93` replaces a 4-line match with `self.poison.as_ref().map(|expr| parse(expr)).transpose()`. The `as_ref()` correctly avoids moving out of `self.poison`.

- **Consistent handler refactor.** Both `services/kels/src/handlers.rs:797-801` and `services/sadstore/src/handlers.rs:159-167` apply the identical pattern. The turbofish `serde_json::from_str::<kels_core::Peer>` correctly compensates for the removed type annotation on the `let peer` binding.

- **Provably equivalent transformations.** All four changes are mechanical — same types, same error paths, same return values. No behavioral change.

- **Appropriate scope restraint.** Other `Ok(Some(...))` / `Ok(None)` patterns in the codebase (cache, merge, keys) were correctly left untouched where side effects, async calls, or error-variant-specific logic prevent a simple `.transpose()`.

- **Clean commit history.** The refactor is a single focused commit (`ffa3991`) with a clear message, followed by the audit doc commit.
