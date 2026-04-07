---
name: summarize-claudit-issues
description: Summarize issues in the current claudit, in docs/claudit/.
disable-model-invocation: true
---

# Summarize Claudit Issues

Summarize all findings from claudit audit files for the current branch, grouped by status.

## Input

No arguments required.

## Procedure

1. **Find claudit files** — Get the current branch name from `git branch --show-current`. List all files in `docs/claudit/` matching `*-<branch>-*.md`, sorted by counter.

2. **Read all files** — Read each claudit file and extract all findings (number, title, priority, file path, and whether it is open or resolved).

3. **Output summary** — Print a summary to the user (do NOT write a file) in this format:

```
## Claudit Summary: <branch> (<N> rounds)

### Open (<count>)

| # | Priority | Title | File | Round |
|---|----------|-------|------|-------|
| 3 | Medium   | ...   | ...  | 5     |

### Resolved (<count>)

| # | Priority | Title | Round Found | Round Resolved |
|---|----------|-------|-------------|----------------|
| 1 | High     | ...   | 2           | 3              |
```

If there are no open issues, say so. If there are no resolved issues, say so.

## Rules

- Read-only — do not modify any files.
- Keep the output concise. Titles should be short (truncate if needed). Do not include full descriptions or suggested fixes.
- "Round Found" is the round where the finding first appeared. "Round Resolved" is the round where it was marked resolved. If resolved in the same round it was found, both columns show the same round number.
