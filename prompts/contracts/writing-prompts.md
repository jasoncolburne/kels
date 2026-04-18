# Writing Implementor Prompts

The implementor starts fresh every session. Your prompt is their entire context.

- **Self-contained.** No "as we discussed." State the goal, constraints, files, and specific changes.
- **File-specific.** Name files and functions. Quote code when the change is surgical.
- **Rule-aware.** Restate relevant `AGENTS.md` rules inline. The implementor may not internalize them otherwise.
- **Negative constraints.** Say what NOT to do. The implementor will over-engineer, add unnecessary error handling, or break adjacent code if you don't fence it.
- **Test expectations.** What tests should pass, what new tests to add, what to verify.
