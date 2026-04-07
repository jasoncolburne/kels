---
name: fix-claudit-issues
description: Fix issues in the current claudit, in docs/claudit/.
disable-model-invocation: true
---

# Fix Claudit Issues

Fix specific open findings from the most recent claudit audit file on the current branch.

## Input

Issue numbers in the form: `1,3,5-7` (comma-separated, with optional ranges).

## Procedure

1. **Find the latest claudit file** — Get the current branch name from `git branch --show-current`. List files in `docs/claudit/` matching `*-<branch>-*.md`, sort by counter, and read the highest-numbered one.

2. **Parse the issue spec** — Expand the argument into a list of issue numbers (e.g., `1,3,5-7` → `[1, 3, 5, 6, 7]`).

3. **Validate** — For each requested issue number, confirm it exists in the claudit file and is currently **open** (not struck through / marked RESOLVED). If any requested issue is already resolved or does not exist, stop and ask the user for clarification before proceeding.

4. **Fix each issue** — For each open issue, in order:
   - Read the finding description, file path, and line numbers from the claudit file.
   - Read the relevant source file(s) to understand the context.
   - Implement the fix as described in the finding's "Suggested fix" (or an equivalent correct fix if the suggestion is incomplete).
   - Only run `make check` after fixing **all** specified issues — do not run it between individual fixes.

5. **Verify** — Run `make check` once to confirm the fixes compile. If there are errors, fix them and re-check.

6. **Resolve the claudit file** — Update the claudit file:
   - For each fixed issue, apply the standard resolution format: strike through the title (`### ~~N. Title~~ — RESOLVED`), strike through the original description, and add a `**Resolution:**` line describing what was done.
   - Update the summary table (decrement Open counts, increment Resolved counts for the appropriate priority levels).

## Rules

- Do NOT fix issues that weren't requested.
- Do NOT create new claudit files — update the existing one in place.
- Only run `make` when Rust source files were modified. Skip it for documentation-only or shell-script-only fixes.
- If a fix requires design decisions not covered by the finding's description, stop and ask the user.
