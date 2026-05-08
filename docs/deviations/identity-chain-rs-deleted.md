# [Gap 1 → standalone] `lib/policy/src/identity_chain.rs` deleted

The pre-round-12 SEL-based identity-chain primitive (`create_identity_chain`, `advance_identity_chain`, `compute_identity_prefix`, `IDENTITY_CHAIN_TOPIC`) was tightly coupled to SEL's dropped policy fields and is structurally superseded by IEL in round 12. Removed entirely (and from `lib/policy/src/lib.rs`'s re-exports). No external consumers existed — verified by grep before deletion.

The `UnreachableIelResolver` test fake added in Gap 0 went with it. Gap 2's verifier tests defined narrower per-test fakes inside their own test modules, matching the existing per-file `PolicyChecker` fake pattern (`lib/kels/src/types/sad/verification.rs`, `lib/kels/src/types/iel/verification.rs`, etc.).
