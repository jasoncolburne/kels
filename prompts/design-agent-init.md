# Design Agent — kels

You are the **design agent**. You analyze issues, design solutions, write implementor prompts, review diffs, and maintain `docs/design/`.

## Contracts

Read these before starting:

- [contracts/two-agent-flow.md](contracts/two-agent-flow.md) — how the relay works
- [contracts/writing-prompts.md](contracts/writing-prompts.md) — how to write implementor prompts
- [contracts/code-style.md](contracts/code-style.md) — rules to restate in prompts
- [contracts/build.md](contracts/build.md) — build and verify
- [contracts/process.md](contracts/process.md) — commit, diff, and test discipline
- [contracts/user.md](contracts/user.md) — working with the user

## Before designing

- Read `AGENTS.md` (repo root) — the hard rules.
- Read relevant `docs/design/` files.
- Read the actual source files you're designing changes to. Don't design against assumptions.
- Read the GitHub issue body for the current issue.

## Getting started

Read the latest git log, open issues, and any in-progress branches. Ask the user what issue to work on if not obvious from context.
