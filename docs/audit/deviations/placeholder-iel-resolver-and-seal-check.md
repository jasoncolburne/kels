# [Gap 2 → Gap 4] handler `PlaceholderIelResolver` + repair-seal-check downgrade

Gap 4 replaced both with the round-12 routing matrix:

- `RepositoryIelResolver` (in-process; wraps `Arc<SadStoreRepository>`, reads `iel_events` directly via the repo's pool) supplants the Placeholder at both `SelVerifier::new` sites.
- The `establishment_version` → `last_governance_version` swap is now moot — Gap 4's routing matrix uses `pre_batch_seal` directly (snapshot of `last_governance_version` *before* the verifier sees the new batch) for the sealed/unsealed predicate, the repair-past-seal guard, and the algorithmic-ContestRequired check.
- Pre-batch state snapshot (`is_contested`, `is_decommissioned`, `first_divergent_version`, `last_governance_version`) collected via repo queries before the verifier runs, mirroring the IEL handler's round-11 hygiene.
- Terminal-state gates (`ContestedSel` / `DecommissionedSel` 403s) fire on contested/decommissioned chains regardless of batch contents.
- Inception batch rule enforced before tx-start: any batch with `Icp` must include `Upd` at v1 (deviation: surfaced as a generic `BAD_REQUEST` body fragment "incomplete inception"; Gap 6 swaps to `KelsError::IncompleteInception`).
- Routing matrix per `docs/design/sel/reconciliation.md §Local Submissions Matrix` — `is_repair` / `is_contest` / `is_decommission` / non-terminal each routed against the sealed/unsealed predicate, with `ContestRequired` / `RepairRequired` rejections at the appropriate cells.
- Algorithmic ContestRequired catches linear-sealed-past-version Upd / Sea (uses kind-relevant authorization gating: verifier already ran and returned `policy_satisfied=true` to reach this branch).
- `SadEventRepository::insert_event` added to mirror IEL's; used by the contest / decommission paths to bypass `save_batch`'s divergent-rejection so Cnt can land on a sealed-divergent chain.
