# SAD Event Logs: Governance Policy and Bounded Divergence

SAD Event Logs are append-only, versioned, policy-governed data chains stored in SADStore. This document covers the security model — governance policy, divergence bounding, sealing, and repair.

For the storage layer, API, gossip replication, and custody model, see [sadstore.md](sadstore.md).

## Threat Model

An adversary who compromises a chain's `write_policy` (e.g., gains access to enough endorsing keys) can author new events that pass write_policy evaluation. Without additional constraints, the adversary can:

1. Fork the chain at any version by submitting a conflicting event
2. Extend their fork indefinitely
3. Fork behind historical events, rewriting effective chain history

`governance_policy` bounds all three. It is a higher-threshold policy that the adversary is assumed unable to satisfy. Evaluations seal the chain at evaluated points, limiting where forks can occur and how far they can extend.

## Governance Policy Lifecycle

### Declaration

Governance policy is declared via event kind:
- `Icp` (v0) may optionally carry `governance_policy`, but this changes the SEL prefix. Use only when the caller controls prefix computation. For discoverable chains (like exchange keys), v0 must NOT declare governance_policy.
- `Est` (v1 only) declares `governance_policy` when v0 did not. Est is required at v1 if v0 omitted it.
- The first submitted batch must contain a `governance_policy` (either on v0 or v1).
- `finish()` requires at least one branch to have `governance_policy` established.

### Evaluation

`Evl` and `Rpr` events evaluate against the branch's established `governance_policy`. The `PolicyChecker` verifies the event satisfies the tracked policy. On success, `events_since_evaluation` resets to zero.

**Rules:**
- Evl/Rpr require `governance_policy` already established on the branch.
- Governance policy evolution: Evl events may carry a new `governance_policy` — evaluated against the *previous* tracked policy. Failure is a structural error. Rpr forbids `governance_policy` (to evolve policy after repair, submit a separate Evl afterward).
- `Upd` and `Rpr` must not set `governance_policy` on the event.

### Evaluation Bound

`MAX_NON_EVALUATION_EVENTS = MINIMUM_PAGE_SIZE - 1 = 63`. After 63 non-evaluation events, the next event must be an evaluation (Evl or Rpr). This bound ensures:

- An adversary's fork is limited to 63 events before requiring an evaluation they cannot produce
- Page-by-page verification can always validate evaluation compliance within a single page

Est counts as a non-evaluation event toward this bound.

## Divergence Model

### Detection

When `save_batch` encounters a version collision (a submitted event's version matches an existing event with a different SAID), it inserts the forking event and returns `DivergenceCreated`. The chain is frozen — no further appends are accepted until repair.

v0 divergence is rejected (inception events are fully deterministic).

### Evaluation Seal

Evaluations seal the chain. `save_batch` rejects version collisions at or before the `last_governance_version`:

```
fork_version <= last_governance_version → rejected
```

The verification token carries `last_governance_version` (computed during verification, not re-queried). For divergent chains with two branches, this is the minimum across branches — the seal is only as strong as the weakest branch.

This means an adversary who compromises `write_policy` can only fork at versions after the last evaluation. Combined with the 63-event bound, their fork is bounded: they can produce at most 63 events before needing an evaluation they cannot satisfy.

### Effective SAID

A chain's gossip-visible identity:
- Non-divergent: the tip event's SAID
- Divergent: `hash_effective_said("divergent:{prefix}")` — synthetic, deterministic, so all nodes agree on the frozen state

## Repair

The chain owner resolves divergence by submitting a batch containing a `Rpr` event. The handler auto-detects Rpr events and takes the repair path.

### Mechanics

1. `truncate_and_replace` compares submitted events against existing events by SAID
2. Leading events that match are skipped (deduplication)
3. The first non-matching event's version is the truncation point (`from_version`)
4. Events at `from_version` and above are archived, then deleted
5. New events are inserted

### Authorization

- The repair must include an event with `kind.evaluates_governance()` (Evl or Rpr) at or after `from_version`. The Rpr event itself serves as the evaluation proof — the repairer must satisfy `governance_policy`, a higher bar than `write_policy`.
- The evaluation seal applies: `from_version` must be after `last_governance_version`. You cannot repair behind a seal.
- The establishment seal applies: `from_version` must be after `establishment_version`. The establishment event (v0 with governance_policy or Est at v1) is the policy foundation — it cannot be truncated.
- After truncation, the entire chain is re-verified from scratch.

### Archive and Audit

Displaced events are archived to `sad_event_archives`. A `sad_event_repairs` audit event is created. Both are queryable via the repair history API. Already-archived events are skipped on re-archival (prevents unique constraint violations from repeated repair propagation).

### Gossip Propagation

When a repair succeeds, SADStore publishes `{prefix}:{effective_said}` to Redis. Peer gossip nodes receive the announcement, fetch the full repaired chain (since=None), and submit to the local SADStore. The handler auto-detects Rpr events and takes the repair path. `truncate_and_replace` deduplicates leading events and only replaces from the divergence point.

## Verification

`SelVerifier` performs incremental, page-by-page verification. It processes events by generation (all events at the same version). A generation can contain 1 event (normal) or 2 events (divergent fork).

### What the verifier checks

- SAID integrity on every event
- Prefix and topic consistency
- Chain linkage (`previous` points to a known branch tip)
- Version monotonicity (each event's version = parent's version + 1)
- `write_policy` authorization via `PolicyChecker` (every v1+ event)
- Governance policy lifecycle (declaration, evaluation, evolution, bound)

### What the verifier tracks

- Per-branch state: tip event, `tracked_write_policy`, `governance_policy`, `events_since_evaluation`
- `tracked_write_policy` is seeded from v0 (Icp) and updated when an Evl event carries a new write_policy. Authorization checks on v1+ events use this, not the event's own field.
- Global: `policy_satisfied` flag, `last_governance_version`

### Verification token

`SadEventVerification` is the proof-of-verification token. It can only be obtained through the verifier. Accessors: `current_event()`, `current_content()`, `prefix()`, `write_policy()`, `topic()`, `policy_satisfied()`, `last_governance_version()`, `establishment_version()`. See [sadstore.md](sadstore.md#verification) for the same list in the SADStore layer doc.

The handler uses `policy_satisfied()` to decide authorization (403 on failure) and `last_governance_version()` as the seal floor for `save_batch`.

## Handler Flow

### Normal submission (non-repair)

1. Acquire advisory lock on SEL prefix
2. Deduplicate submitted events against existing SAIDs (IN query on submitted batch only)
3. If all duplicates, return early
4. Verify existing chain via `verify_existing_chain`
5. Verify new (deduped) events via `verify_page`
6. `finish()` — governance policy established, evaluation bound
7. Check `policy_satisfied()`
8. `save_batch` with `last_governance_version` as seal floor
9. Commit, publish to Redis

### Repair submission

Repair is auto-detected: the handler checks if any submitted event has `kind: Rpr`.

1. Acquire advisory lock on SEL prefix
2. Query `last_governance_version` from existing chain (pre-truncation)
3. `truncate_and_replace` — dedup, archive, delete, insert
4. Verify seal: `from_version > last_governance_version`
5. Verify evaluation at divergence: batch contains an event with `kind.evaluates_governance()` (Evl or Rpr) at `version >= from_version`
6. Verify establishment seal: `from_version > establishment_version`
7. Re-verify entire chain from scratch
8. `finish()`, check `policy_satisfied()`
9. Commit, publish to Redis

## Event Kinds

Each `SadEvent` has an explicit `kind: SadEventKind` field:

```
kels/sad/v1/events/icp  — Inception (v0 only)
kels/sad/v1/events/est  — Establish (governance_policy declaration, v1 only)
kels/sad/v1/events/upd  — Update (normal event)
kels/sad/v1/events/evl  — Evaluate (evaluated against governance_policy)
kels/sad/v1/events/rpr  — Repair (resolves divergence, evaluates governance_policy)
```

`validate_structure()` enforces event-level invariants (version constraints, required/forbidden fields per kind). The verifier adds chain-state checks on top: Est rejected when governance_policy already established from v0; Upd/Evl/Rpr rejected when no governance_policy established.

### write_policy per kind

`write_policy` authorizes chain mutations but is only present on events that establish or change it:

- `Icp`: **required** — seeds the SEL prefix (prefix = Blake3 of v0 template with said+prefix blanked).
- `Evl`: **optional** — present means "policy evolution" (evaluated against `governance_policy`, a higher bar). Absent means "pure evaluation, no policy change" — verifier inherits the tracked policy from branch state. Mirrors `governance_policy` semantics on Evl.
- `Est`, `Upd`, `Rpr`: **forbidden**. Est declares governance_policy, not write_policy. Upd is a pure content append. Rpr resolves divergence; to evolve policy after repair, submit a separate Evl afterward.

The verifier's `SadBranchState` tracks the effective `tracked_write_policy` — seeded from v0 (Icp always carries it) and updated whenever an Evl event carries a new write_policy. v1+ advances are authorized against `branch.tracked_write_policy`, not the event's own field. This prevents an adversary who satisfies the current write_policy from replacing the policy via a Upd-style event: policy replacement now requires satisfying the stricter `governance_policy` too.

Rpr carries evaluation semantics implicitly — it evaluates against `governance_policy` just like Evl, resets `events_since_evaluation`, and updates `last_governance_version`. Rpr forbids `governance_policy` on the event; to both repair AND evolve governance_policy, use Rpr to fix divergence, then Evl with the new governance_policy afterward.

## Typical Chain Shapes

### Exchange key publication

```
v0  kind=icp  write_policy=endorse(kel_prefix), topic=kels/sad/v1/keys/mlkem
v1  kind=est  governance_policy=endorse(kel_prefix), content=key_publication_said
v2  kind=upd  content=rotated_key_said                  ← inherits write_policy
v3  kind=evl  content=another_key_said                  ← pure evaluation, no policy change
```

### Identity chain

```
v0  kind=icp  write_policy=policy_a_said, topic=kels/sad/v1/identity/chain, content=None
v1  kind=est  governance_policy=policy_a_said, content=None
v2  kind=evl  write_policy=policy_b_said (policy evolution), content=None
v3  kind=evl  content=None                              ← pure evaluation, unchanged policy
```

### Divergence and repair

```
v0  kind=icp  governance_policy=gp_said
v1a kind=upd  (node-a)                            ← fork
v1b kind=upd  (node-b)                            ← fork
    — chain frozen, divergent effective SAID —
v1  kind=rpr  content=repaired                    ← repair replaces v1a+v1b, evaluates governance_policy
```
