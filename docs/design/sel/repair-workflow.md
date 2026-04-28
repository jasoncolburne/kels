# SEL Repair Workflow

Operator-facing workflow for handling SEL chain transitions — divergence detection, repair, contest, decommission, and gossip propagation. SEL counterpart to [../kel/recovery-workflow.md](../kel/recovery-workflow.md).

## Detection

A chain owner detects abnormal state via two signals:

1. **`flush()` response carries `diverged_at_version: Some(d)`** — the most recent submission either created a fork (owner-caused overlap) or hit a chain that was already divergent and got rejected. The builder records this on its `SelVerification` token; the owner's CLI surfaces a warning.
2. **Effective SAID mismatch** — owner's local view differs from the gossip-published effective SAID. Owner runs `kels-cli sel get <prefix>` and compares against their `SelVerification`'s `effective_tail_said()`; mismatch indicates server-side state has advanced or diverged.

Both signals route to the same recovery action: owner runs `repair`, `contest`, or `decommission` depending on the chain state.

## Trigger

The builder API exposes three terminal-state operations on `SadEventBuilder`:

| Operation | When to use | Signature |
|-----------|-------------|-----------|
| `repair()` | Chain is divergent or owner's tip is behind server's | Bundles pending; appends `Rpr` extending owner's authentic tip |
| `contest()` | Chain is sealed past owner's view (`ContestRequired` returned by submit) | Bundles pending; appends `Cnt`; chain becomes terminal |
| `decommission()` | Owner is ending the chain cleanly (no conflict) | Bundles pending; appends `Dec`; chain becomes terminal |

Each operation runs the same pre-flight (mirrors KEL's `recover` / `contest` / `rotate_recovery`):

- Verify the server's chain via `client.verify_sad_events(prefix, checker)` — defense-in-depth against a buggy/malicious server.
- (Repair) Derive boundary uniformly: `boundary = owner_tip.version`. `Rpr.previous = owner_tip.said`.
- Build the appropriate event extending the bundled-pending tip (or owner's verified tip if pending is empty).
- Submit `[pending..., Rpr/Cnt/Dec]` atomically.

For full algorithmic detail of the discriminator that runs server-side, see [event-log.md §Server-side discriminator](event-log.md#server-side-discriminator).

## CLI Commands

```bash
kels-cli sel repair        --prefix <prefix>     # Resolve divergence; archives adversary events
kels-cli sel contest       --prefix <prefix>     # Terminal contest (when ContestRequired returned)
kels-cli sel decommission  --prefix <prefix>     # Terminal owner-initiated end
kels-cli sel get           <prefix>              # Fetch a SEL from the server (for inspection)
kels-cli sel status        --prefix <prefix>     # Show local chain status (verification token)
kels-cli sel list                                # List local SEL prefixes
```

After `repair` succeeds, the chain is back to Active state and accepts normal `Upd` / `Sea` submissions. After `contest` or `decommission`, the chain is terminal — no further submissions are accepted.

## Gossip Propagation

When `repair`, `contest`, or `decommission` succeeds:

1. SADStore publishes the new effective SAID to Redis (`sel_updates`).
2. Gossip service subscribes, broadcasts an announcement on `kels/sad/v1`.
3. Peers receive the announcement, compare against their local effective SAID for the prefix.
4. Stale peers fetch the full chain from origin via `POST /api/v1/sad/events/fetch` and submit to their local SADStore.
5. Receiving handler observes the `Rpr` / `Cnt` / `Dec` in the batch and routes through the kind-discriminator paths described in [merge.md](merge.md). Archival (for `Rpr`) happens synchronously in the receiver's transaction.

If a peer misses the gossip announcement (e.g., it was offline), the owner can submit the events directly to that peer with the same CLI commands.

## Verification Invariant

The DB cannot be trusted. All SEL operations fall into three categories (mirrors KEL):

1. **Serving** — returning chain data to a client/peer. No verification needed (the consumer verifies).
2. **Consuming** — using chain data for security decisions. Requires a `SelVerification` token.
3. **Resolving** — comparing state to decide whether to sync. Wrong answers trigger unnecessary syncs, not security holes.

Owner's `repair`/`contest`/`decommission` builders run `verify_sad_events` against the server's view as defense-in-depth before extending from `get_owner_tip`. A buggy/malicious server that mis-handles a divergent chain would otherwise be taken at its word; the pre-flight verification ensures the server's chain is structurally and policy-wise sound before owner signs anything that extends it.

## Operator Recovery Workflow

When a chain divergence is observed:

1. Owner inspects: `kels-cli sel status --prefix <prefix>` shows `diverged_at_version: Some(d)`.
2. Owner inspects server: `kels-cli sel get <prefix>` returns the divergent branches.
3. Owner decides:
   - If the seal hasn't advanced past their view → run `repair`. Adversary events archived synchronously.
   - If the seal has advanced past their view (server returned `ContestRequired`) → run `contest`. Chain becomes terminal.
   - If the chain is no longer needed → run `decommission`.
4. Gossip propagates the resolution to all peer nodes.

## References

- [event-log.md](event-log.md) — Chain lifecycle, the discriminator algorithm, evaluation seal and anchor non-poisonability.
- [merge.md](merge.md) — Submit handler routing.
- [reconciliation.md](reconciliation.md) — Multi-node correctness matrix.
- [../sadstore.md](../sadstore.md) — SADStore service architecture and gossip layer.
- [../kel/recovery-workflow.md](../kel/recovery-workflow.md) — KEL counterpart.
