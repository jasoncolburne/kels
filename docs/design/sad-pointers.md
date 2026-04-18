# SAD Pointer Chains: Checkpoint Policy and Bounded Divergence

SAD pointer chains are append-only, versioned, policy-governed data chains stored in SADStore. This document covers the security model — checkpoint policy, divergence bounding, sealing, and repair.

For the storage layer, API, gossip replication, and custody model, see [sadstore.md](sadstore.md).

## Threat Model

An adversary who compromises a chain's `write_policy` (e.g., gains access to enough endorsing keys) can author new records that pass write_policy evaluation. Without additional constraints, the adversary can:

1. Fork the chain at any version by submitting a conflicting record
2. Extend their fork indefinitely
3. Fork behind historical records, rewriting effective chain history

`checkpoint_policy` bounds all three. It is a higher-threshold policy that the adversary is assumed unable to satisfy. Checkpoints seal the chain at evaluated points, limiting where forks can occur and how far they can extend.

## Checkpoint Policy Lifecycle

### Declaration

A record declares `checkpoint_policy` by setting the field to a policy SAID. The first declaration is just a commitment — no evaluation occurs. The verifier records the policy on the branch state.

**Rules:**
- v0 (inception) may declare `checkpoint_policy`, but this changes the chain prefix (the prefix is derived from v0's content). Use only when the caller controls prefix computation. For discoverable chains (like exchange keys), v0 must NOT declare checkpoint_policy — it would break `compute_sad_pointer_prefix` determinism.
- If v0 does not declare `checkpoint_policy`, v1 must.
- The first submitted batch of records for a pointer prefix must contain a `checkpoint_policy`.
- The declaring record must NOT set `is_checkpoint`. First declaration is not an evaluated checkpoint.
- `finish()` requires at least one branch to have `checkpoint_policy` established.

### Evaluation

A subsequent record sets `is_checkpoint: true` to be evaluated against the branch's established `checkpoint_policy`. The `PolicyChecker` verifies the record satisfies the tracked policy. On success, `records_since_checkpoint` resets to zero.

**Rules:**
- `is_checkpoint` requires `checkpoint_policy` already established on the branch. Setting `is_checkpoint` on the declaring record is rejected.
- Checkpoint policy evolution (changing `checkpoint_policy` on a checkpoint record) evaluates against the *previous* tracked policy. Failure is a structural error — the higher authority did not approve the transition.
- Non-checkpoint records that change `checkpoint_policy` without `is_checkpoint` are rejected.

### Checkpoint Bound

`MAX_NON_CHECKPOINT_RECORDS = MINIMUM_PAGE_SIZE - 1 = 63`. After 63 non-checkpoint records, the next record must be a checkpoint. This bound ensures:

- An adversary's fork is limited to 63 records before requiring a checkpoint they cannot produce
- Page-by-page verification can always validate checkpoint compliance within a single page

The declaration record (first `checkpoint_policy` without `is_checkpoint`) counts as a non-checkpoint record toward this bound.

## Divergence Model

### Detection

When `save_batch` encounters a version collision (a submitted record's version matches an existing record with a different SAID), it inserts the forking record and returns `DivergenceCreated`. The chain is frozen — no further appends are accepted until repair.

v0 divergence is rejected (inception records are fully deterministic).

### Checkpoint Seal

Evaluated checkpoints seal the chain. `save_batch` rejects version collisions at or before the `last_checkpoint_version`:

```
fork_version <= last_checkpoint_version → rejected
```

The verification token carries `last_checkpoint_version` (computed during verification, not re-queried). For divergent chains with two branches, this is the minimum across branches — the seal is only as strong as the weakest branch.

This means an adversary who compromises `write_policy` can only fork at versions after the last evaluated checkpoint. Combined with the 63-record bound, their fork is bounded: they can produce at most 63 records before needing a checkpoint they cannot satisfy.

### Effective SAID

A chain's gossip-visible identity:
- Non-divergent: the tip record's SAID
- Divergent: `hash_effective_said("divergent:{prefix}")` — synthetic, deterministic, so all nodes agree on the frozen state

## Repair

The chain owner resolves divergence by submitting a replacement batch with `?repair=true` (to be replaced by a `Rep` record kind in #126).

### Mechanics

1. `truncate_and_replace` compares submitted records against existing records by SAID
2. Leading records that match are skipped (deduplication)
3. The first non-matching record's version is the truncation point (`from_version`)
4. Records at `from_version` and above are archived, then deleted
5. New records are inserted

### Authorization

- The repair must include a checkpoint (`is_checkpoint: true`) at or after the divergence point (`from_version`). This proves the repairer can satisfy `checkpoint_policy` — a higher bar than `write_policy`.
- The checkpoint seal applies to repairs: `from_version` must be after `last_checkpoint_version`. You cannot repair behind a seal.
- After truncation, the entire chain is re-verified from scratch.

### Archive and Audit

Displaced records are archived to `sad_pointer_archives`. A `sad_pointer_repairs` audit record is created. Both are queryable via the repair history API. Already-archived records are skipped on re-archival (prevents unique constraint violations from repeated repair propagation).

### Gossip Propagation

When a repair succeeds, SADStore publishes `{prefix}:{effective_said}:repair` to Redis. Peer gossip nodes receive the announcement, fetch the full repaired chain (since=None), and submit with `?repair=true`. The receiving node's `truncate_and_replace` deduplicates leading records and only replaces from the divergence point.

## Verification

`SadChainVerifier` performs incremental, page-by-page verification. It processes records by generation (all records at the same version). A generation can contain 1 record (normal) or 2 records (divergent fork).

### What the verifier checks

- SAID integrity on every record
- Prefix and topic consistency
- Chain linkage (`previous` points to a known branch tip)
- Version monotonicity (each record's version = parent's version + 1)
- `write_policy` authorization via `PolicyChecker` (every v1+ record)
- Checkpoint policy lifecycle (declaration, evaluation, evolution, bound)

### What the verifier tracks

- Per-branch state: tip record, `checkpoint_policy`, `records_since_checkpoint`
- Global: `policy_satisfied` flag, `last_checkpoint_version`

### Verification token

`SadPointerVerification` is the proof-of-verification token. It can only be obtained through the verifier. Accessors: `current_record()`, `current_content()`, `prefix()`, `write_policy()`, `topic()`, `policy_satisfied()`, `last_checkpoint_version()`.

The handler uses `policy_satisfied()` to decide authorization (403 on failure) and `last_checkpoint_version()` as the seal floor for `save_batch`.

## Handler Flow

### Normal submission (non-repair)

1. Acquire advisory lock on chain prefix
2. Deduplicate submitted records against existing SAIDs (IN query on submitted batch only)
3. If all duplicates, return early
4. Verify existing chain via `verify_existing_chain`
5. Verify new (deduped) records via `verify_page`
6. `finish()` — checkpoint policy established, checkpoint bound
7. Check `policy_satisfied()`
8. `save_batch` with `last_checkpoint_version` as seal floor
9. Commit, publish to Redis

### Repair submission

1. Acquire advisory lock on chain prefix
2. Query `last_checkpoint_version` from existing chain (pre-truncation)
3. `truncate_and_replace` — dedup, archive, delete, insert
4. Verify seal: `from_version > last_checkpoint_version`
5. Verify checkpoint at divergence: batch contains `is_checkpoint` at `version >= from_version`
6. Re-verify entire chain from scratch
7. `finish()`, check `policy_satisfied()`
8. Commit, publish to Redis with `:repair` suffix

## Typical Chain Shapes

### Exchange key publication

```
v0  [icp]  write_policy=endorse(kel_prefix), topic=kels/exchange/v1/keys/mlkem
v1  [est]  checkpoint_policy=endorse(kel_prefix), content=key_publication_said
v2  [upd]  content=rotated_key_said
v3  [chk]  is_checkpoint=true, content=another_key_said
```

### Identity chain

```
v0  [icp]  write_policy=policy_a_said, topic=kels/identity/v1/chain, content=None
v1  [est]  checkpoint_policy=policy_a_said, content=None
v2  [upd]  write_policy=policy_b_said (policy evolution), content=None
v3  [chk]  is_checkpoint=true, content=None
```

### Divergence and repair

```
v0  [icp]  checkpoint_policy=cp_said
v1a [upd]  (node-a)                                ← fork
v1b [upd]  (node-b)                                ← fork
    — chain frozen, divergent effective SAID —
v1  [rep]  is_checkpoint=true, content=repaired    ← repair replaces v1a+v1b, seals
```

## Future: Record Kinds (#126)

The implicit record type detection (field combination checks, `?repair=true` query param) will be replaced with an explicit `kind` enum on `SadPointer`:

```
sad/pointer/v1/icp  — Inception
sad/pointer/v1/upd  — Update
sad/pointer/v1/est  — Establish (checkpoint_policy declaration)
sad/pointer/v1/chk  — Checkpoint (evaluated)
sad/pointer/v1/rep  — Repair
```

This makes chains self-documenting and simplifies both verification (match on kind) and the builder API (#126).
