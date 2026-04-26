# Key Events: Per-Kind Reference

Pure structural reference for KEL event kinds, per-kind field rules, and typical chain shapes.

For chain lifecycle (states, divergence, recovery via discriminator, contest, decommission, proactive-ROR invariant), see [event-log.md](event-log.md). For the merge engine that integrates submitted events server-side, see [merge.md](merge.md).

## Event Kinds

| Kind | Topic | Purpose |
|---|---|---|
| `Icp` | `kels/kel/v1/events/icp` | Inception (s0). Seeds prefix derivation. |
| `Dip` | `kels/kel/v1/events/dip` | Delegated inception (s0). Same as `Icp` but anchored by a delegating prefix. |
| `Rot` | `kels/kel/v1/events/rot` | Rotation. Reveals the next signing key (committed by prior `rotation_hash`) and commits a new one. |
| `Ixn` | `kels/kel/v1/events/ixn` | Interaction. Anchors a SAID; does not change keys. |
| `Rec` | `kels/kel/v1/events/rec` | Recovery. Dual-signed; rotates signing + recovery keys; resolves divergence. |
| `Ror` | `kels/kel/v1/events/ror` | Recovery rotation. Dual-signed; pre-emptively rotates both keys (no divergence required). |
| `Dec` | `kels/kel/v1/events/dec` | Decommission. Dual-signed; terminal owner-initiated end. |
| `Cnt` | `kels/kel/v1/events/cnt` | Contest. Dual-signed; terminal due to authority conflict. |

`Rec`, `Ror`, `Dec`, `Cnt` all return `reveals_recovery_key() = true` — each requires dual signatures (signing + recovery). `Rot`, `Ror`, `Rec` return `reveals_rotation_key() = true`.

## Per-Kind Field Rules

`KeyEvent::validate_structure()` enforces these. The verifier and merge engine add chain-state checks on top (e.g., proactive-ROR enforcement; dual-signature verification against prior establishment commitments).

| Kind | serial | previous | public_key | rotation_hash | recovery_key | recovery_hash | anchor | delegating_prefix | authorization |
|---|---|---|---|---|---|---|---|---|---|
| `Icp` | `== 0` | forbidden | **required** | **required** | forbidden | **required** | forbidden | forbidden | n/a |
| `Dip` | `== 0` | forbidden | **required** | **required** | forbidden | **required** | forbidden | **required** | delegator |
| `Rot` | `>= 1` | required | **required** | **required** | forbidden | forbidden | forbidden | forbidden | signing |
| `Ixn` | `>= 1` | required | forbidden | forbidden | forbidden | forbidden | **required** | forbidden | signing |
| `Rec` | `>= 1` | required | **required** | **required** | **required** | **required** | forbidden | forbidden | dual |
| `Ror` | `>= 1` | required | **required** | **required** | **required** | **required** | forbidden | forbidden | dual |
| `Dec` | `>= 1` | required | **required** | forbidden | **required** | forbidden | forbidden | forbidden | dual |
| `Cnt` | `>= 1` | required | **required** | forbidden | **required** | forbidden | forbidden | forbidden | dual |

### Authorization model

The "authorization" column names which signature(s) the verifier requires for the event to be accepted:

- **Icp** is the chain's declarative root. Its acceptance is structural — the SAID covers `public_key`, and the event's "signing" signature is verified against that same `public_key`. The prefix derives from the inception template, so a colliding `Icp` would have a different prefix and therefore belong to a different KEL. Icp *declares* the initial signing key (`public_key`), the next signing-key commitment (`rotation_hash`), and the next recovery-key commitment (`recovery_hash`); subsequent events satisfy what Icp committed.
- **Dip** is also a declarative root, but additionally requires the delegating prefix's KEL to anchor the delegate's prefix via an `ixn` (consumer-side check at the time the delegated KEL is used; see [../policy.md](../policy.md) `Delegate(delegator, delegate)` resolution).
- **Rot** is signed by the new `public_key` it reveals. The verifier checks `Blake3(public_key) == prev_establishment.rotation_hash`, then verifies the signature against `public_key`. `rotation_hash` on `Rot` commits the *next* rotation key.
- **Ixn** is signed by the current active signing key — the `public_key` of the most recent establishment event in the chain (Icp / Dip / Rot / Rec / Ror).
- **Rec / Ror / Dec / Cnt** are dual-signed. The "signing" signature is by the key revealed in `public_key` (preimage of the prior establishment's `rotation_hash`); the "recovery" signature is by the key revealed in `recovery_key` (preimage of the prior establishment's `recovery_hash`). Both signatures must verify, and both digest commitments must match. This is the privileged primitive — exercising both the rotation key and the recovery key together proves dual control.

### Recovery-key revelation

`Rec` / `Ror` / `Dec` / `Cnt` reveal the `recovery_key` field. Once revealed in any event on the chain, that recovery key is "spent" — future divergent events must be resolved by `Cnt` (contest), not `Rec` (recovery). The merge engine surfaces this via `KelMergeResult::ContestRequired` (see [event-log.md](event-log.md#contest-cnt) for the trigger).

`Ror` is the proactive form: an owner who has not been compromised can rotate both keys ahead of the proactive-ROR cap, revoking any future divergent recovery the adversary might attempt with stale key material.

### Forward-key commitments

Establishment events (every kind except `Ixn`) commit one or both forward-key digests:

- **`rotation_hash`**: required on `Icp`, `Dip`, `Rot`, `Rec`, `Ror`. Forbidden on `Dec`, `Cnt` (KEL ends — no future signing key).
- **`recovery_hash`**: required on `Icp`, `Dip`, `Rec`, `Ror`. Forbidden on `Rot` (rot doesn't change recovery commitment), `Dec`, `Cnt` (KEL ends).

The verifier seeds `tracked_rotation_hash` / `tracked_recovery_hash` from inception and updates them on each establishment event. Future revelations are checked against the tracked digest.

### Proactive-ROR bound

`MAX_NON_REVEALING_EVENTS = MINIMUM_PAGE_SIZE - 2 = 62`. After 62 non-recovery-revealing events (i.e., events that aren't `Rec` / `Ror` / `Dec` / `Cnt`), the next event must reveal the recovery key. The `- 2` headroom accommodates a `[rec, rot]` recovery batch fitting in one `MINIMUM_PAGE_SIZE`-bounded page.

This bound caps an adversary's fork to 62 events before they need to satisfy the recovery primitive — which they cannot without the recovery key — and bounds the synchronous archival window during recovery to a single page. The builder auto-inserts `Ror` (upgrading a `Rot`) when the bound is about to be crossed.

KEL's proactive-ROR bound is the structural analog of SEL's evaluation seal (see [../sel/events.md](../sel/events.md#evaluation-bound)): in both, a privileged primitive (recovery-key revelation / governance evaluation) caps how far an adversary can fork before they must satisfy the higher bar.

## Typical Chain Shapes

### Normal lifecycle

```
s0  kind=icp  public_key=k0,  rotation_hash=h(k1),  recovery_hash=h(r0)
s1  kind=ixn  anchor=said_a                           ← signed by k0
s2  kind=rot  public_key=k1,  rotation_hash=h(k2)     ← reveals k1; signed by k1
s3  kind=ixn  anchor=said_b                           ← signed by k1
…
s62 kind=ror  public_key=kN, recovery_key=r0,         ← proactive recovery-rotation; signed by kN + r0
    rotation_hash=h(kN+1), recovery_hash=h(r1)
```

`Ror` at s62 keeps the chain inside the proactive-ROR bound. The recovery key `r0` is revealed and replaced by `r1`.

### Delegated inception

```
s0  kind=dip  public_key=k0, rotation_hash=h(k1), recovery_hash=h(r0),
              delegating_prefix=delegator_prefix
```

Acceptance: structural (SAID + signature by `k0`) AND the delegator's KEL must contain an `ixn` anchoring s0's prefix. Verifiers check the anchor at the time the delegated KEL is used.

### Divergence resolved by recovery

```
s0..s4  normal chain
s5a kind=ixn  anchor=owner_anchor       (owner)        ← fork
s5b kind=ixn  anchor=adversary_anchor   (adversary)    ← fork (races with s5a)
    — KEL frozen, divergent effective SAID —
s6  kind=rec  previous=s5a.said,                       ← Rec extends owner's tip; dual-signed (k5+r0)
              public_key=k6, recovery_key=r0,
              rotation_hash=h(k7), recovery_hash=h(r1)
```

The `Rec` extends owner's authentic tip (s5a), not the pre-divergence ancestor. The merge engine walks back from `Rec.previous` to identify the owner's chain; s5b is archived. See [event-log.md](event-log.md#recovery-rec) for the discriminator algorithm and the conditional `Rot` follow-up when the adversary rotated but the owner didn't.

### Contest after recovery-key revelation

```
s0..s4   normal chain
s5b      adversary submits rec at s5 (revealing recovery key r0)
         — chain now has a recovery-revealing event in a divergent branch —
s6       owner submits cnt extending their authentic tip                 ← chain becomes contested, terminal
                                                                            (cnt dual-signed by k5 + r0)
```

The owner cannot recover — the recovery key has been revealed by the adversary. `Cnt` terminates the chain; both branches remain in the chain (no archival).

### Clean decommission

```
s0..sN   normal chain
sN+1     kind=dec   ← owner ends the KEL cleanly; dual-signed (kN + recovery key)
```

After `Cnt` or `Dec`, all submissions are rejected. See [event-log.md](event-log.md) for the lifecycle and merge-observable case taxonomy.
