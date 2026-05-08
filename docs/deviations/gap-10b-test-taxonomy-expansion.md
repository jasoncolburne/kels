# [Gap 10a → Gap 10b] critical-subset → broader taxonomy

Gap 10a shipped 10 critical tests + the harness; Gap 10b extended to 23 passing tests covering the round-12 plan's prescribed taxonomy minus the 5 sealed-divergent matrix cases (single-node-untestable, see Open section) and the 4 gossip-propagation cases (deferred to deployment-test sweep, see Open section).

Gap 10b additions (13 new tests):
- `compute_sad_event_prefix_uses_identity_and_topic` — pure-Rust contract pin (no harness needed).
- `update_rejects_when_identity_event_unknown_in_iel` — `BadIdentityBinding` (SAID-not-found).
- `update_rejects_when_identity_event_prefix_mismatches_branch_identity` — `BadIdentityBinding` (cross-IEL contamination).
- `update_rejects_when_identity_event_regresses_monotonic_ratchet` — `BadIdentityBinding(monotonic)`.
- `update_rejects_when_bound_iel_event_lives_on_divergent_iel_branch` — HARD `IelDivergent` for Upd.
- `submit_lands_iel_divergent_cnt_chain_becomes_contested_with_policy_unsatisfied` — SOFT `IelDivergent` for Cnt.
- `submit_lands_iel_divergent_dec_chain_becomes_decommissioned_with_policy_unsatisfied` — SOFT `IelDivergent` for Dec.
- `pre_divergence_iel_event_resolves_even_when_iel_is_divergent` — pre-divergence shared event resolves cleanly even on divergent IEL.
- `seal_advances_last_governance_version_and_ratchets`.
- `repair_resolves_divergence_archives_adversary_events`.
- `contest_after_seal_via_algorithmic_trigger` — algorithmic `ContestRequired` (Upd/Sea at version <= seal on linear chain).
- `active_sealed_chain_accepts_dec_terminates_decommissioned` — Dec on linear sealed chain (post-seal-version) lands cleanly, pinning the algorithmic-trigger exclusion for terminal kinds.
- `update_appends_with_identity_event_binding_to_later_iel_evl` — binding to a post-Icp IEL Evl advances the SEL ratchet.

Helpers added: `establish_se_chain`, `evolve_iel`, `create_iel_divergence` (returns the new policies for verifier policy-resolver seeding), `seal_se_chain`, `create_se_divergence`, `verify_chain_with_policies`. The IEL divergence helper differentiates the two competing Evls via fake-endorser SAIDs (Policy::build rejects poison+immune as mutually exclusive).
