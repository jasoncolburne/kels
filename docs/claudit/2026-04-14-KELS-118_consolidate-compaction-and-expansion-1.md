# Branch Audit: KELS-118_consolidate-compaction-and-expansion (Round 1) — 2026-04-14

Consolidation of compaction/expansion tree walk primitives into `lib/kels/src/sad.rs`. 4 files changed, ~367 additions, ~208 deletions. Focus: correctness of behavioral changes during refactor, API contract fidelity.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 1        |
| Medium   | 0    | 2        |
| Low      | 0    | 1        |

---

## High Priority

### ~~1. `expand_or_error` rejects already-expanded fields — behavioral regression~~ — RESOLVED

**File:** `lib/creds/src/disclosure.rs:108-121`

~~The old `expand_at_path` in creds was tolerant of non-SAID values at the target path — if the value was already an object (already expanded), the `if let Some(said_str) = current.as_str()` guard silently fell through and the function returned `Ok(())`. The new `expand_or_error` converts `Ok(false)` from the shared primitive into an error unconditionally.~~

~~This breaks disclosure expressions where a recursive expand is followed by an explicit expand on a field that was already expanded by the recursive step.~~

**Resolution:** `expand_or_error` now only errors if `navigate_to_value_mut` returns `None` (path doesn't exist). Already-expanded fields (objects, non-SAID strings) are tolerated as silent success, matching the original behavior.

---

## Medium Priority

### ~~2. Error message specificity lost in `expand_or_error`~~ — RESOLVED

**File:** `lib/creds/src/disclosure.rs:114-121`

~~The old creds `expand_at_path` produced distinct errors for "field not found" (`InvalidDisclosure`) vs. "SAID not in store" (`ExpansionError`) with the specific SAID value in the message. The new `expand_or_error` conflates all failure modes into one generic message.~~

**Resolution:** Fix #1 separates path-not-found (error) from everything else (silent success). The remaining `Ok(false)` cases (already expanded, non-SAID string, SAID not in store) are all tolerated — no error message needed for them.

### ~~3. `compact_at_path` doc comment claims `Result<bool>` but returns `bool`~~ — RESOLVED

**File:** `lib/kels/src/sad.rs:94-97`

~~The doc comment says "Returns `Ok(true)` if the value was compacted, `Ok(false)` if the target has no `said` field or the path doesn't exist." But the actual return type is `bool`, not `Result<bool>`.~~

**Resolution:** Doc comment updated to say `true`/`false` instead of `Ok(true)`/`Ok(false)`.

---

## Low Priority

### ~~4. `test_expand_at_path_success` silently passes on invalid digest~~ — RESOLVED

**File:** `lib/kels/src/sad.rs:208-224`

~~The test uses `if let Ok(d) = digest { ... }` which means the entire test body is skipped if `Digest256::from_qb64` fails on the hardcoded string.~~

**Resolution:** Replaced `if let Ok(d) = digest` with `let d = digest.unwrap()` so the test fails loudly on SAID parsing regression.

---

## Positive Observations

- **Clean separation of concerns.** The shared primitives in `sad.rs` are genuinely policy-free — they navigate, expand, compact without deciding *which* fields to act on. The heuristic wildcard walk (`expand_recursive`) correctly stayed in sadstore, and schema-driven expansion stayed in creds. This keeps the shared layer thin and trustworthy.

- **`ExpansionState` caller-managed pattern.** Moving state management out of `expand_at_path` and into the caller (`apply_tokens`) is a good design — the shared primitive doesn't dictate rate-limiting policy, and each caller can implement its own (creds doesn't need one, sadstore does).

- **`compact_at_path` return type is honest.** Returning `bool` rather than `Result<bool>` is the right call — there are no error conditions in the compact path, only "did it find a said field." The callers then layer their own error policy.

- **Net code reduction despite new tests.** ~160 lines removed from the two consumer files, replaced by ~180 lines in the shared module (including comprehensive unit tests). The test coverage in `sad.rs` is better than what the extracted code originally had.

- **Import hygiene.** The `MAX_EXPANSIONS` constant correctly moved to test-only imports in sadstore when it turned out the production code no longer referenced it directly.
