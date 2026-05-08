# [Round-12 review fix → audit + resolver fix on KELS-126] Post-divergence auth-failed Evl: `policy_history` records prior tracked policies, not event-declared values

When a post-IEL-divergence Evl auth-fails (soft path), the IEL verifier records `policy_history[event.said] = (PRIOR auth, PRIOR governance)` — the event payload's declared policies are NOT adopted into branch state (the unauthenticated evolution is rejected from trust). Consumers calling `auth_policy_at(post_div_evl_auth_failed.said)` get the prior tracked policies, not the event's stated values.

This is the verifier's adopted-state view, distinct from the raw event payload. Documented on `auth_policy_at` / `governance_policy_at`'s doc-comment in `lib/kels/src/types/iel/verification.rs` (see "Verifier-view, not raw-event-view"). Consumers must use these accessors rather than reading `event.auth_policy` directly to honor the trust contract.

**Audit (KELS-126, post round-12-third-follow-up commit 2).** A grep of `\.auth_policy` and `\.governance_policy` across `lib/`, `services/`, and `clients/` — excluding test fixtures, IEL-verifier internals that populate `policy_history` (the immune-checks + branch-state initialization at `lib/kels/src/types/iel/verification.rs:428-461`, the Evl evolution path at lines 559-578, and the Cnt/Dec preservation checks at lines 603-614), `IdentityEvent::evl`'s constructor copy (`event.rs:218,219`), and the `auth_policy_at` / `governance_policy_at` accessor implementations themselves — surfaced exactly **one** production consumer that read the raw payload fields directly:

- `services/sadstore/src/iel_resolver.rs::RepositoryIelResolver::resolve_auth_policy_at` (line 160 pre-fix) — returned `Ok(event.auth_policy)` after a `first_divergent_version` query.
- `services/sadstore/src/iel_resolver.rs::RepositoryIelResolver::resolve_governance_policy_at` (line 183 pre-fix) — symmetric.

Both bypassed the verifier-adopted view. Asymmetric with `lib/kels/src/iel_resolver.rs::AnchoredIelResolver` (the in-process kels-core HTTP-source resolver), which already routed through `verification.auth_policy_at(said)` / `verification.governance_policy_at(said)` after a shared `verification_for` walk (`lib/kels/src/iel_resolver.rs:226,251`).

**Fix.** `RepositoryIelResolver` gained a private `verification_for` helper that delegates to `kels_core::verify_identity_events_with_queried` (mirroring `AnchoredIelResolver::verification_for` exactly, including forwarding `self.queried_saids`). `resolve_auth_policy_at` and `resolve_governance_policy_at` now:

1. `fetch_iel_event(identity, iel_event_said)` — chain-integrity check (`BadIdentityBinding` on miss / cross-IEL contamination).
2. `verification_for(identity)` — runs the IEL verifier across the chain through a `RepositoryIelPageSource`; surfaces tampering as a verification error (e.g., `verify_said` Blake3 mismatch).
3. Divergence cutoff via `verification.diverged_at_version()` — `IelDivergent` if `bound.version >= divergence_at` (signal sourced from the verifier's adopted view rather than a separate `first_divergent_version` query).
4. `verification.auth_policy_at(iel_event_said)` / `governance_policy_at(...)` — verifier-adopted lookup; `BadIdentityBinding` if the SAID isn't in `policy_history` (chain integrity breach signal).

The `first_divergent_version` repo query is dropped from the resolver paths — divergence state now sourced from the same verification token that backs the policy lookup, eliminating a TOCTOU window between "is this divergent?" and "what policy applies?".

**Cost.** `resolve_*_at` now runs the IEL verifier per call (was a single repo lookup + divergence query). Same per-call cost as `is_satisfied`. The pre-existing open deviations entry `[Round-12 review fix → pre-production / #152] is_satisfied per-call IEL re-verification` already tracks the cache fix — the same cache will cover `resolve_*_at` once it lands. Not blocking #147 e2e gating.

**Test.** `repository_iel_resolver_resolve_at_detects_tampered_auth_policy` in `services/sadstore/tests/sad_builder_tests.rs` pins the new contract end-to-end:

1. Establishes an IEL chain via `setup_kel_iel_policy`.
2. Calls `resolve_auth_policy_at` on the clean chain — asserts the verifier-adopted result equals the declared `policy.said`.
3. Tampers the `auth_policy` column on the Icp row directly via `sqlx::query` (without recomputing `said`) so the deserialized event mismatches its SAID under `verify_said`.
4. Calls `resolve_auth_policy_at` again — asserts the resolver errors (re-verification catches the tampering) rather than silently returning the bogus value.
5. Symmetric assertion on `resolve_governance_policy_at` to confirm both accessors share the same `verification_for` walk and both fail on the same tampering.

The test exercises the AGENTS.md §Verification Invariant ("the DB cannot be trusted") at the resolver boundary specifically; the parallel SEL/IEL `submit_returns_500_when_existing_*_chain_fails_reverification` integration tests (added under the round-12 third follow-up commit 2) cover the submit-handler-side integrity contract, while this test covers the resolver-side one.

**Verifier-internal sites preserved as-is.** The IEL verifier code itself reads `event.auth_policy` / `event.governance_policy` to populate `policy_history` — that's by design; the verifier IS the authority. Excluded from the audit per the original framing. Tests + event-construction sites also excluded.

No changes to `IelVerification::auth_policy_at` / `governance_policy_at` accessors themselves; no changes to the verifier's policy_history population logic; no changes to the in-process `AnchoredIelResolver` (already correct). Single-resolver fix restoring SEL↔server-side parity.
