# [Gap 0 → Round-12 third follow-up commit 2] `iel_chain_positions` post-divergence walk-back implemented

Both `AnchoredIelResolver` (`lib/kels/src/iel_resolver.rs`) and `RepositoryIelResolver` (`services/sadstore/src/iel_resolver.rs`) now walk `event.previous` from each post-divergence SAID until reaching the event at version `first_divergent_version`; that ancestor's SAID becomes the branch identity. O(K·D) per-batch with no memoization (D≈1–2 in production). Defensive `BadIdentityBinding` on chain-integrity breaches mid-walk (event.previous=None on a non-Icp, version skipping past D, missing ancestor, cross-IEL contamination, step-bound exceeded).

Two events on the same post-divergence branch now share the same `branch_marker` and compare via canonical chain order (`Less` / `Greater`); two events on different branches surface `IelDivergent`. Approximation `branch_marker = Some(event.said)` retired.

`RepositoryIelResolver` extracted from `services/sadstore/src/handlers.rs` into its own pub module so integration tests can drive it directly against the live Postgres-backed IEL repository.

Test coverage:
- `lib/kels/src/iel_resolver.rs` test module — 3 unit tests against a fake `PagedIelSource` (V=D base case, V=D+1 walk, pre-divergence no-marker).
- `services/sadstore/tests/sad_builder_tests.rs::repository_walk_back_different_branches_compares_iel_divergent` — V=D base case against the real IEL repository. The V=D+1 walk case is unit-tested at the AnchoredIelResolver level (same algorithm shape) rather than at the integration level: injecting a V=D+1 event would require bypassing IEL routing (which rejects post-divergence submissions with `ContestRequired`); the integration value-add is small relative to the harness cost.
