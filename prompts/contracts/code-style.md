# Code Style

Read `AGENTS.md` for the full set. The critical rules:

- **Imports**: three groups (std, external, local), nested, sorted, blank-line separated. Fix imports when touching a file.
- **No `.unwrap()`**. Use `.expect("reason")` with `#[allow(clippy::expect_used)]` when truly infallible.
- **No hardcoded kind strings** — use enum methods (`EventKind`, `SadPointerKind`, etc.).
- **Sign the SAID's QB64 bytes**, never serialized payloads.
- **All HTTP endpoints**: POST with JSON bodies. No identifiers in URL paths or query params.
- **`create()` not `new()`** for `SelfAddressed` types.
- **Fail secure, not safe.** Default to restrictive behavior when state is unknown.
