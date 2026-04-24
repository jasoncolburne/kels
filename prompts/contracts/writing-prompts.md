# Writing Implementor Prompts

The implementor starts fresh every session. They read the **GitHub issue** as the spec; the **prompt** is a small pointer into it.

## Where content belongs

- **GitHub issue body** — the durable, self-contained spec. Scope decisions, rename maps, file lists, wire-format changes, and open questions live here. Before writing any implementor prompt, update the issue so it reflects the current decisions from design review.
  - **Pre-implementation** (no commits toward the issue on the working branch): edit the body directly.
  - **Post-implementation** (commits landing): add a comment instead — don't rewrite the spec the implementor worked against.
- **Implementor prompt** — a short relay message. Names the issue, states the current step, and nothing more. The implementor reads the issue for everything else.

## Two kinds of prompts

- **Kickoff** — "Read #N. Produce a plan. Do not start implementing." The implementor returns a plan; the user relays it back for design review.
- **Steering** — short corrections on a specific point: "In your plan, step 4 should do X instead of Y — because Z." One concern per prompt.

Do NOT write a self-contained multi-hundred-line implementor brief. If the prompt is doing the spec's job, update the issue instead.

## Restated rules

Only restate an `AGENTS.md` rule in a prompt when you've seen the implementor drift on it before. Default to pointing at the issue + `AGENTS.md`.

## Negative constraints

Say what NOT to do when the implementor has over-engineered on a related task. Otherwise trust them to stay in scope.
