# KEL Reconciliation Proof

Exhaustive enumeration of all KEL state × submission type × gossip sync combinations, demonstrating that every case is handled correctly.

## Invariants

All proofs below depend on these invariants:

1. **Proactive ROR compliance**: Every KEL has a recovery-revealing event (`rec`, `ror`, `cnt`, `dec`) at least every `MINIMUM_PAGE_SIZE - 2` (62) non-revealing events. Enforced by the merge engine; the builder auto-inserts `ror` when needed.

2. **Bounded divergence**: An adversary can only fork after the last recovery-revealing event (forking before triggers `ContestRequired`). Combined with invariant 1, divergence spans at most 62 events from the fork point.

3. **Bounded operations**: Recovery batch (`events + rec + rot`) ≤ 64, contest batch (`events + cnt`) ≤ 63, adversary chain to archive ≤ 62. All fit in one page (`MINIMUM_PAGE_SIZE = 64`).

## KEL States

| State | Description |
|-------|-------------|
| **Empty** | No events for this prefix |
| **Normal** | Non-divergent, active |
| **Divergent** | Fork detected, no `rec`/`cnt` yet |
| **Recovering** | Divergent + `RecoveryRecord`, archival in progress |
| **Recovered** | Clean chain after archival complete |
| **Contested** | `cnt` present, permanently frozen |
| **Decommissioned** | `dec` present, permanently frozen |

Note: "Divergent with recovery revealed" means a recovery-revealing event exists on one branch since the divergence point. This is a sub-state of Divergent where only `cnt` is accepted (non-`cnt` submissions return `ContestRequired`).

## Local Submissions

What happens when a client submits events to the merge engine.

| KEL State | ixn/rot | ror | rec/rec+rot | cnt/events+cnt | dec |
|-----------|---------|-----|-------------|----------------|-----|
| **Empty** | Reject (no KEL) | Reject | Reject | Reject | Reject |
| **Normal** | Append ✓ | Append ✓ | Append ✓ (proactive recovery) | Reject (no divergence) | Append ✓ |
| **Divergent** | `RecoverRequired` | `RecoverRequired` | Recovered ✓ (creates `RecoveryRecord`) | `ContestRequired` (no recovery revealed) | `RecoverRequired` |
| **Divergent (recovery revealed)** | `ContestRequired` | `ContestRequired` | `ContestRequired` | Contest ✓ | `ContestRequired` |
| **Recovering** | `RecoverRequired` | `RecoverRequired` | `ContestRequired` (existing `rec` revealed recovery) | Contest ✓ → archival detects and stops | `RecoverRequired` |
| **Recovered** | Same as Normal | Same as Normal | Same as Normal | Reject (no divergence) | Same as Normal |
| **Contested** | `ContestedKel` | `ContestedKel` | `ContestedKel` | `ContestedKel` | `ContestedKel` |
| **Decommissioned** | `KelDecommissioned` | `KelDecommissioned` | `KelDecommissioned` | `KelDecommissioned` | `KelDecommissioned` |

### Batch submissions

The merge engine handles batches atomically:

- **`[events + rec + rot]`**: Owner's chain from the fork point through recovery. At most 64 events (bounded by proactive ROR). Processed as a single overlap or divergent submission.
- **`[events + cnt]`**: Owner's chain from the fork point through contest. At most 63 events. The `cnt` must be last in the batch.
- **`[ror, ixn]`**: Auto-inserted by the builder when an `ixn` would exceed the proactive ROR interval.
- **`[rot] → [ror]`**: The builder upgrades `rot` to `ror` when the proactive ROR interval is due, since `ror` rotates both signing and recovery keys.

## Gossip Sync (transfer_key_events)

When node A syncs a KEL to node B, `transfer_key_events` reads from A and writes to B via `store_page` (which calls the merge engine on B).

### Transfer ordering

For divergent/recovering source KELs, `send_divergent_events` reorders events:

- **Recovered (rec found, no cnt)**: Longer chain first (non-divergent appends), then single fork event from shorter chain (creates divergence), then `rec`(+`rot`) resolves it.
- **Contested (cnt found)**: Skips the recovery path (the `rec` in a contested KEL is part of one branch, not a recovery event). Builds two chains by forward-tracing from the two fork events. Sends the longer chain first as non-divergent appends. If the shorter chain contains a `cnt`, sends the full shorter chain as an atomic batch (the merge engine accepts `[events + cnt]` on divergent KELs). Otherwise sends only the fork event.
- **Unrecovered (no rec, no cnt)**: Longer chain first as non-divergent appends. Only the fork event from the shorter chain is sent (no terminal event to deliver).

### Source → Sink state matrix

Each cell describes what happens when gossip syncs a KEL from a source node (row) to a sink node (column). The source's `transfer_key_events` reads its local KEL and sends events via `store_page` calls to the sink. The sink's merge engine processes the incoming events against whatever state it already has for that prefix.

"Normal (owner)" means the sink has the legitimate owner's non-divergent chain. "Normal (adversary)" means the sink has the adversary's non-divergent chain (submitted to that node before divergence was detected elsewhere).

| Source | Sink: Empty | Sink: Normal (owner) | Sink: Normal (adversary) | Sink: Recovering | Sink: Contested |
|--------|-------------|---------------------|-------------------------|-----------------|----------------|
| **Normal** | Full KEL appended ✓ | Duplicates, no-op ✓ | Overlap → divergence | `RecoverRequired` | `ContestedKel` |
| **Recovered** | Full clean chain ✓ | `rec`+`rot` append ✓ | Overlap → `rec` in batch → `RecoveryRecord` created ✓ | `RecoverRequired` (already recovering) | `ContestedKel` |
| **Recovering** | Reordered: longer chain + fork + `rec`+`rot` ✓ | Adversary events create overlap + recovery ✓ | Owner events arrive, overlap + recovery ✓ | Duplicates ✓ | `ContestedKel` |
| **Contested** | Longer chain + fork (`cnt` last) ✓ | Other chain + `cnt` → contest ✓ | Other chain + `cnt` → contest ✓ | `cnt` arrives → archival detects and stops ✓ | Effective SAIDs match (`hash("contested")`) ✓ |
| **Decommissioned** | Full chain + `dec` ✓ | `dec` appends ✓ | Overlap, `dec` in chain ✓ | `RecoverRequired` | `ContestedKel` |

### Effective SAID convergence

All nodes must eventually agree on the effective SAID for each prefix.

| State | Effective SAID computation | Converges? |
|-------|---------------------------|------------|
| **Normal** | Tip event SAID | ✓ (identical chains after gossip) |
| **Recovering** | Composite hash of sorted tip SAIDs | Temporary divergence during archival; converges after archival completes |
| **Recovered** | Tip event SAID | ✓ (identical clean chains) |
| **Contested** | `hash_tip_saids(&["contested"])` — deterministic | ✓ (same value regardless of archival progress) |
| **Decommissioned** | `dec` event SAID | ✓ (identical chains) |

## Archival

The background recovery task archives adversary events one page per cycle.

### Owner identification

The archival task identifies owner events via:
1. Backward trace from `rec_previous` to the fork point
2. Add `rec` and `rot`-after-`rec` explicitly
3. Forward trace from the last owner event (rot or rec) to include post-recovery events
4. Everything else at or after `diverged_at` is adversary

### Archival during contest

If a `cnt` event is submitted while archival is in progress:
1. Archival task acquires advisory lock
2. Checks for `cnt` in the KEL
3. Verifies the full chain (including `cnt`) via `completed_verification`
4. Transitions `RecoveryRecord` to `Contested` terminal state
5. Archival stops immediately

### Archival bounds

| Metric | Bound | Source |
|--------|-------|--------|
| Adversary events to archive | ≤ 62 | Proactive ROR limits fork distance |
| Events per archival cycle | 1 page (64) | `archive_one_page` batch window |
| Maximum archival cycles | 1 | Adversary chain fits in one page |
| Owner events never archived | ✓ | Owner SAID set includes backward trace + `rec` + `rot` + forward trace |

## Edge Cases

### 1. Adversary `rec` as normal append

The adversary submits `rec` to a non-divergent KEL (normal append, no divergence). This reveals the recovery key. Any future divergence at or after this `rec` requires `cnt` (contest) instead of `rec` (recovery). The owner must contest.

### 2. Multiple adversary injections across nodes

Adversary injects different events to different nodes. When gossip syncs, divergence is created. Only one adversary event is written per overlap (the fork event). Recovery or contest resolves it. All nodes converge after archival completes.

### 3. Owner events archived by adversary's `rec`

If the adversary submitted `rec` (creating a `RecoveryRecord`), archival may remove the owner's events. The owner's builder detects missing events via `find_missing_owner_events` (probes each local event against the server) and resubmits the minimal chain + `cnt` atomically.

### 4. Post-recovery events synced to adversary node

After recovery on node A, new events (e.g., `ixn`) are appended. When synced to node B (which has the adversary chain), the overlap handler creates a `RecoveryRecord`. The archival task's `find_adversary_tip_all_adversary` includes a forward trace from `rot`-after-`rec` to capture post-recovery events in `owner_saids`, preventing them from being archived.

### 5. Contest during active archival

The archival task checks for `cnt` under advisory lock before each cycle. If found, it verifies the full chain and transitions to the `Contested` terminal state. The advisory lock prevents races between contest submission and archival.

### 6. Sink already recovering when source syncs

The sink's KEL is divergent (recovery in progress). Gossip sync submits events → `RecoverRequired`. The sync fails, prefix is re-queued as stale. After archival completes, the next sync attempt succeeds.

### 7. Contested KELs with different archival progress

Different nodes may have archived different amounts of adversary events before the contest arrived. Their event counts and digests differ, but `compute_prefix_effective_said` returns a deterministic `hash_tip_saids(&["contested"])` for any KEL with a `cnt` event. Anti-entropy sees matching SAIDs and does not re-queue.
