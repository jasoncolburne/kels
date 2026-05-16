# [Gap 0 → Gap 0] `IelChainPosition` shape extended beyond plan's suggestion

Plan suggested `{ version: u64, branch_marker: Option<BranchId> }`. Shipped: `{ version: u64, kind: IdentityEventKind, said: cesr::Digest256, branch_marker: Option<cesr::Digest256> }`.

Added `kind` and `said` because the canonical IEL sort key is `(version ASC, kind sort_priority ASC, said ASC)` — `try_cmp` needs all three to break ties correctly within a version. Plan said "suggested"; this is a reasonable elaboration, not a contradiction. Pinned here as a permanent design choice — the shape is structurally load-bearing for try_cmp determinism, not pending further work.
