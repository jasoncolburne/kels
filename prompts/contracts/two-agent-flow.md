# Two-Agent Flow

The user relays between a **design agent** and an **implementation agent**. The user reviews and course-corrects both.

- Design agent: analyzes issues, records decisions on the issue, writes short prompts for the implementor, reviews plans and diffs.
- Implementation agent: produces a plan before implementing, then codes exactly what the approved plan describes and reports changes.
- The implementor has no memory across sessions. The GitHub issue is the durable spec; prompts are short relay messages that point at it.

## Sequence

1. User gives the design agent an issue.
2. Design agent reads code/docs, surfaces scope decisions, and **updates the issue** so it reflects the current spec (body edit pre-implementation, comment once commits are landing).
3. Design agent writes a **short kickoff prompt** asking the implementor to read the issue and produce a plan.
4. User relays the kickoff. Implementor returns a plan.
5. Design agent reviews the plan. Iterate via **short steering prompts** — one concern per prompt.
6. Once the plan is approved, implementor executes and returns a diff.
7. Design agent reviews the diff. Iterate until correct.
