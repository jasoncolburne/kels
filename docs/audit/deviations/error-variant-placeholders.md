# [Gaps 0/4/5 → Gap 6] error variant placeholders

Gap 6 added the three round-12 variants and swept all placeholder call sites:

- `IncompleteInception(String)` — handler at `services/sadstore/src/handlers.rs::submit_sad_events` returns the real variant (via `err.to_string()` for the HTTP body).
- `BadIdentityBinding(String)` — replaces the Gap-0 `InvalidIel` placeholders in both `AnchoredIelResolver` (lib/kels) and `RepositoryIelResolver` (services/sadstore handlers); also replaces the verifier's `VerificationFailed` site for monotonic-ratchet regression and the unreachable cross-branch divergence case; test fakes updated (`FakeIelResolver` in `lib/kels/src/types/sad/verification.rs` test module); two verifier tests updated to assert `BadIdentityBinding` instead of `InvalidIel` / fragment-only.
- `DecommissionBlockedByDivergence(String)` — replaces Gap-5's `InvalidKel("decommission blocked by divergence …")` placeholder in `SadEventBuilder::decommission` and the unreachable defense-in-depth path in `choose_terminal_anchor`.
- `Display` impl + the test-variants list in `error.rs` were extended with the three new variants. `contest_required_sel` helper already existed (Gap 1).
- `PendingEventsBlockRepair` SEL-side: no SEL call sites exist (already removed when sad_builder.rs was stubbed in Gap 1 and again rebuilt in Gap 5). Variant stays for KEL-side until #152.
