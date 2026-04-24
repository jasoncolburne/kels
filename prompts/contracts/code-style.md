# Code Style

Read `AGENTS.md` for the full set. The critical rules:

- **Imports**: three groups (std, external, local), nested, blank-line separated. `rustfmt` handles sorting within groups. Fix grouping when touching a file.
- **No `.unwrap()`**. Use `.expect("reason")` with `#[allow(clippy::expect_used)]` when truly infallible.
- **No hardcoded kind strings** — use enum methods (`KeyEventKind`, `SadEventKind`, etc.).
- **Sign the SAID's QB64 bytes**, never serialized payloads.
- **All HTTP endpoints**: POST with JSON bodies. No identifiers in URL paths or query params.
- **`create()` not `new()`** for `SelfAddressed` types.
- **Fail secure, not safe.** Default to restrictive behavior when state is unknown.
