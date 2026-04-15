---
name: claudit
description: Perform a thorough code audit of the current branch vs main, writing findings to docs/claudit/.
disable-model-invocation: true
---

# Claudit — Branch Audit

Perform a thorough code review of the current branch's changes against `main`.

## Input

No arguments required. The branch name and counter are determined automatically.

## Procedure

0. **Branch check** — Get the current branch name from `git branch --show-current`. If the branch is `main`, **stop immediately** and tell the user: "Claudit audits compare against main — running on main itself would produce an empty diff. Please switch to a feature branch first." Do not proceed.

1. **Preparation** — Read CLAUDE.md for project context. Read existing files in `docs/claudit/` to understand prior audit history and resolved findings for this branch.

2. **Gather the diff** — Run `git diff main` and `git diff main --stat`. Note the approximate line count and files changed.

3. **Read source files** — Read all changed/new source files in full (not just the diff hunks). Understanding surrounding context is critical for finding issues the diff alone won't reveal.

4. **Audit** — Review for:
   - **Correctness** — logic errors, off-by-one, missing error handling, invariant violations
   - **Security** — injection, TOCTOU, information disclosure, fail-open vs fail-secure, unbounded recursion/allocation
   - **Performance** — unnecessary allocations, N+1 patterns, missing batching, redundant computation
   - **API design** — inconsistent interfaces, missing validation, confusing semantics, encapsulation violations
   - **Style** — import ordering (per CLAUDE.md), hardcoded strings that should use enums, `pub` vs `pub(crate)` violations

   Focus on **new findings** not covered in prior claudit rounds. Check whether prior open findings are still open or have been resolved.

5. **Classify findings** by priority:
   - **High** — correctness or security bugs that could cause wrong behavior, data loss, or security vulnerabilities
   - **Medium** — design issues, performance problems, or gaps that could cause subtle bugs
   - **Low** — style issues, minor inefficiencies, documentation gaps, encapsulation concerns

## Output format

Determine the output filename:
1. Get the current branch name from `git branch --show-current`.
2. List existing files in `docs/claudit/` matching `*-<branch>-*.md` to find the highest counter. If none exist, the counter is `1`. Otherwise increment the highest by 1.
3. Write to `docs/claudit/<YYYY-MM-DD>-<branch>-<counter>.md`.

Use this exact structure:

```markdown
# Branch Audit: <Branch Name> (Round N) — <YYYY-MM-DD>

<One-line scope description: branch name, diff size, file count, focus areas.>

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | X    | Y        |
| Medium   | X    | Y        |
| Low      | X    | Y        |

---

## High Priority

### 1. <Finding title>

**File:** `path/to/file.rs:line-range`

<Description of the issue. Be specific about what's wrong and why it matters.>

**Suggested fix:** <Concrete suggestion, not vague.>

### ~~2. <Resolved finding title>~~ — RESOLVED

**File:** `path/to/file.rs:line-range`

~~<Original description, struck through.>~~

**Resolution:** <What was done to fix it.>

---

## Medium Priority

<Same pattern as above.>

---

## Low Priority

<Same pattern as above.>

---

## Positive Observations

- **<Observation title>.** <Why it's good — be specific about the design decision or implementation quality.>
```

## Rules

- Number findings sequentially across all priority levels (don't restart numbering per section).
- Open findings get a plain `### N. Title`. Resolved findings get `### ~~N. Title~~ — RESOLVED`.
- Include file paths with line numbers where applicable.
- Include 4-6 positive observations — acknowledge good design decisions, not just problems.
- **Each round is a clean document with only new findings.** Resolved findings are updated inline in their original document (strikethrough + resolution note), NOT carried forward into new round documents. A new round document should only contain new findings discovered in that round. The summary table at the top of each document reflects that document's findings only.
- Do NOT fix any issues — this is a read-only audit. The user will decide what to fix.
- If the branch has had prior claudit rounds, note the total resolved findings count in the summary.
