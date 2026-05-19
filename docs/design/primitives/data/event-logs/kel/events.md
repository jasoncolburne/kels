# Key Events: Per-Kind Reference

Pure structural reference for KEL event kinds, per-kind field rules, and typical chain shapes.

For chain lifecycle (states, divergence, recovery via discriminator, decommission, proactive-ROR invariant), see [event-log.md](event-log.md). For the merge engine that integrates submitted events server-side, see [merge.md](merge.md).

## Event Kinds

| Kind | Topic | Purpose |
|---|---|---|
| `Icp` | `kels/kel/v1/events/icp` | Inception (s0). Seeds prefix derivation. |
| `Dip` | `kels/kel/v1/events/dip` | Delegated inception (s0). Same as `Icp` but anchored by a delegating prefix. |
| `Rot` | `kels/kel/v1/events/rot` | Rotation. Reveals the next signing key (committed by prior `rotationHash`) and commits a new one. |
| `Ixn` | `kels/kel/v1/events/ixn` | Interaction. Anchors a SAID; does not change keys. |
| `Rec` | `kels/kel/v1/events/rec` | Recovery. Dual-signed; rotates signing + recovery keys; resolves divergence via archival. |
| `Ror` | `kels/kel/v1/events/ror` | Recovery rotation. Dual-signed; pre-emptively rotates both keys (no divergence required). |
| `Dec` | `kels/kel/v1/events/dec` | Decommission. Dual-signed; terminal event ending the chain. |

`Rec`, `Ror`, `Dec` all return `reveals_recovery_key() = true` — each requires dual signatures (signing + recovery). `Rot`, `Ror`, `Rec` return `reveals_rotation_key() = true`.

## Per-Kind Field Rules

`KeyEvent::validate_structure()` enforces these. The verifier and merge engine add chain-state checks on top (e.g., proactive-ROR enforcement; dual-signature verification against prior establishment commitments).

### Structural fields

| Kind | serial | previous | publicKey | rotationHash | recoveryKey | recoveryHash | delegatingPrefix |
|---|---|---|---|---|---|---|---|
| `Icp` | `== 0` | forbidden | **required** | **required** | forbidden | **required** | forbidden |
| `Dip` | `== 0` | forbidden | **required** | **required** | forbidden | **required** | **required** |
| `Ixn` | `>= 1` | required | forbidden | forbidden | forbidden | forbidden | forbidden |
| `Rot` | `>= 1` | required | **required** | **required** | forbidden | forbidden | forbidden |
| `Ror` | `>= 1` | required | **required** | **required** | **required** | **required** | forbidden |
| `Rec` | `>= 1` | required | **required** | **required** | **required** | **required** | forbidden |
| `Dec` | `>= 1` | required | **required** | forbidden | **required** | forbidden | forbidden |

The forward-key commitment fields (`rotationHash`, `recoveryKey`, `recoveryHash`) drive the dual-signature mechanic; see §Forward-key commitments below. `delegatingPrefix` is `Dip`-only and supports the `Delegated(delegator)` policy node (see §Authorization model).

### Authorization, anchor, and routing

| Kind | authorization | anchor | sort_priority |
|---|---|---|---|
| `Icp` | signing | forbidden | 0 |
| `Dip` | signing (+ `Delegated`) | forbidden | 1 |
| `Ixn` | signing | **required** | 2 |
| `Rot` | signing | optional | 3 |
| `Ror` | dual | optional | 4 |
| `Rec` | dual | forbidden | 5 |
| `Dec` | dual | forbidden | 6 |

The `anchor` field (when present) carries the SAID of an IEL/SEL event being anchored cross-chain — see §Anchor on Rot and Ror below. `Rec`/`Dec` are anchor-forbidden by design (single-purpose semantics; see §Anchor on Rot and Ror). `sort_priority` is used by the merge engine for deterministic ordering of events at the same serial.

### Authorization model

The "authorization" column names which signature(s) the verifier requires for the event to be accepted:

- **Icp** must be signed by the private counterpart of the `publicKey` it declares. The verifier recomputes the prefix from the inception template (which includes `publicKey`, `rotationHash`, `recoveryHash`), confirms it matches `event.prefix`, then verifies the event's "signing" signature against `publicKey`. Icp's SAID + prefix derivation provides chain identity; the signature against the declared key is the authorization. Subsequent v1+ events satisfy what Icp committed (`rotationHash` for the next signing key, `recoveryHash` for the recovery key).
- **Dip** has the same submit-time authorization as Icp (signed by the declared `publicKey`). The Dip-specific delegation surface is detailed in §Dip delegation below.
- **Rot** is signed by the new `publicKey` it reveals. The verifier checks `Blake3(publicKey) == prev_establishment.rotationHash`, then verifies the signature against `publicKey`. `rotationHash` on `Rot` commits the *next* rotation key.
- **Ixn** is signed by the current active signing key — the `publicKey` of the most recent establishment event in the chain (Icp / Dip / Rot / Rec / Ror).
- **Rec / Ror / Dec** are dual-signed. The "signing" signature is by the key revealed in `publicKey` (preimage of the prior establishment's `rotationHash`); the "recovery" signature is by the key revealed in `recoveryKey` (preimage of the prior establishment's `recoveryHash`). Both signatures must verify, and both digest commitments must match. This is the privileged primitive — exercising both the rotation key and the recovery key together proves dual control.

### Dip delegation

`Dip` declares a `delegatingPrefix`, captured into the verification token but not checked at submit time. The delegation relationship is verified at **policy-evaluation time** via the `Delegated(delegator)` policy node: any KEL with `delegatingPrefix == delegator` that the delegator anchors (via an `ixn` in the delegator's KEL) satisfies the node.

The single-arg open form (`Delegated(delegator)`, not `Delegated(delegator, delegate)`) is what makes the indirection useful — the delegator can rotate their delegate fleet (decommission, replace, add) without changing any policy that references them. See [../../../../features/policy.md](../../../../features/policy.md) for `Delegated(delegator)` resolution.

### Anchor on Rot and Ror

`Rot.anchor` and `Ror.anchor` are optional fields used for cross-chain anchoring of tier-2 and tier-3 IEL/SEL events per [../../../../protocol-doctrine.md §Anchor Tier Elevation](../../../../protocol-doctrine.md#anchor-tier-elevation). KEL itself does not consume these anchors during its own verification walk — they are read by IEL/SEL verifiers cross-chain when evaluating policy satisfaction at elevated tiers. Anchor format on `Rot`/`Ror` is identical to `Ixn.anchor`: a single `Option<Digest256>` referencing the SAID of the anchored IEL/SEL event.

`Rec` and `Dec` are anchor-forbidden by design. `Rec`'s role is divergence resolution (archival); `Dec` ends the chain. The protocol does not conflate event semantics — anchor emission lives on forward-extension events (`Ixn`/`Rot`/`Ror`), not on the recovery or terminal primitives. Each event kind carries one explicit purpose; operators compose them rather than combining behaviors in a single event.

### Recovery-key revelation

`Rec` / `Ror` / `Dec` reveal the `recoveryKey` field. Once revealed in any event on the chain, that recovery key is "spent" — future divergent events cannot be resolved via `Rec` against the spent key. After recovery-key revelation, contested-termination via a non-archiving privileged event (`Ror` or `Dec`) landing in a divergent set is the only protocol path that ends the chain.

`Ror` is the proactive form: the chain holder rotates both keys ahead of the proactive-ROR cap (no divergence required), revoking any future divergent recovery a second party could attempt with the now-stale key material.

### Forward-key commitments

Establishment events (every kind except `Ixn`) commit one or both forward-key digests:

| Kind | `rotationHash` | `recoveryHash` |
|---|---|---|
| `Icp`, `Dip` | required | required |
| `Rot` | required | forbidden (Rot doesn't change recovery commitment) |
| `Rec`, `Ror` | required | required |
| `Dec` | forbidden (KEL ends) | forbidden (KEL ends) |
| `Ixn` | forbidden | forbidden |

The verifier seeds `tracked_rotation_hash` / `tracked_recovery_hash` from inception and updates them on each establishment event. Future revelations are checked against the tracked digest.

### Proactive-ROR bound

`MAX_NON_REVEALING_EVENTS = MINIMUM_PAGE_SIZE - 2 = 62`. After 62 non-recovery-revealing events (i.e., events that aren't `Rec` / `Ror` / `Dec`), the next event must reveal the recovery key. The `- 2` headroom accommodates a `[rec, rot]` recovery batch fitting in one `MINIMUM_PAGE_SIZE`-bounded page.

This bound caps an adversary's fork to 62 events before they need to satisfy the recovery primitive — which they cannot without the recovery key. It also bounds the synchronous archival window during recovery to a single page. The builder auto-inserts `Ror` (upgrading a `Rot`) when the bound is about to be crossed.

KEL's proactive-ROR bound is the structural analog of SEL's evaluation seal: both are privileged-primitive caps that bound how far an adversary can fork before they must satisfy a higher bar (recovery-key revelation on KEL; governance evaluation on SEL). The two reads on `lastSealAdvancingEvent` operate identically — see [../../../../protocol-doctrine.md §Forks are Seal-Bounded](../../../../protocol-doctrine.md#forks-are-seal-bounded) for the cross-primitive frame, and [../sel/events.md §Evaluation bound](../sel/events.md#evaluation-bound) for the SEL-side instantiation.

## Typical Chain Shapes

### Normal lifecycle

```
s0  kind=icp  publicKey=k0,  rotationHash=h(k1),  recoveryHash=h(r0)
s1  kind=ixn  anchor=said_a                           ← signed by k0
s2  kind=rot  publicKey=k1,  rotationHash=h(k2)     ← reveals k1; signed by k1
s3  kind=ixn  anchor=said_b                           ← signed by k1
…
s62 kind=ror  publicKey=kN, recoveryKey=r0,         ← proactive recovery-rotation; signed by kN + r0
    rotationHash=h(kN+1), recoveryHash=h(r1)
```

`Ror` at s62 keeps the chain inside the proactive-ROR bound. The recovery key `r0` is revealed and replaced by `r1`.

### Delegated inception

```
s0  kind=dip  publicKey=k0, rotationHash=h(k1), recoveryHash=h(r0),
              delegatingPrefix=delegator_prefix
```

Acceptance: structural (SAID + signature by `k0`) AND the delegator's KEL must contain an `ixn` anchoring s0's prefix. Verifiers check the anchor at the time the delegated KEL is used.

### Divergence resolved by recovery

```
s0..s4  normal chain
s5a kind=ixn  anchor=anchor_a                          ← fork
s5b kind=ixn  anchor=anchor_b                          ← fork (races with s5a)
    — Divergent, recoverable via Rec; divergent effective SAID —
s6  kind=rec  previous=s5a.said,                       ← Rec extends s5a (branch-tip-extending shape); dual-signed (k5+r0)
              publicKey=k6, recoveryKey=r0,
              rotationHash=h(k7), recoveryHash=h(r1)
```

The `Rec` extends the s5a branch tip (branch-tip-extending shape), not the pre-divergence ancestor. The merge engine walks back from `Rec.previous` to identify the surviving branch; s5b is archived. Whoever holds the recovery key dictates which branch survives. See [event-log.md](event-log.md#recovery-rec) for the discriminator algorithm and the conditional `Rot` follow-up when the archived branch rotated but the surviving branch didn't.

### Concurrent recovery-key submissions

```
s0..s4   normal chain
s5_a     ixn extending s_4                                         (one signing-key holder)
s5_b     Rec with previous = s_4.said                              (a recovery-key holder, on Node A)
         — divergence-ancestor-extending shape; discriminator archives s5_a;
           Node A is recovered, linear, tip = Rec_b at v_5 —
s5_c     Dec with previous = s_4.said                              (a second recovery-key holder, on Node B)
         — Node B is independently terminated at v_5 via Dec —

(Gossip then delivers each event to the other node.)

  Node A receives Dec: Dec.parent_serial = 4 < seal_serial = 5 → rejected by seal-cap.
  Node B receives Rec_b: Rec_b.parent_serial = 4 < seal_serial = 5 → rejected by seal-cap.
```

Each node retains its locally-landed first-receive. The seal-cap rejects each peer's gossip-arriving submission unconditionally — no boundary case admits competing privileged events at a sealed serial. Federation-level convergence in this scenario is provided at the infrastructure layer via a contested-prefix table that nodes maintain and gossip-sync; see [../../../../protocol-doctrine.md §Limit of the doctrine — concurrent privileged event races](../../../../protocol-doctrine.md#concurrent-privileged-event-races) and [#205](https://github.com/jasoncolburne/kels/issues/205).

### Clean decommission

```
s0..sN   normal chain
sN+1     kind=dec   ← Dec ends the KEL cleanly; dual-signed (kN + recovery key)
```

After `Dec`, the chain is fully terminal. The seal-cap rejects every subsequent submission whose parent sits at-or-before `v_{d-1}`. Federation races between concurrent competing privileged submissions resolve at the infrastructure layer (see [../../../../protocol-doctrine.md §Limit of the doctrine — concurrent privileged event races](../../../../protocol-doctrine.md#concurrent-privileged-event-races) and [#205](https://github.com/jasoncolburne/kels/issues/205)). See [event-log.md](event-log.md) for the lifecycle and merge-observable case taxonomy.

## References

- [event-log.md](event-log.md) — Chain lifecycle, recovery, decommission.
- [verification.md](verification.md) — `KelVerifier` algorithm.
- [merge.md](merge.md) — Submit-handler routing.
- [reconciliation.md](reconciliation.md) — Multi-node correctness matrix.
- [../iel/events.md](../iel/events.md) — IEL per-kind reference.
- [../sel/events.md](../sel/events.md) — SEL per-kind reference.
- [../../../../features/policy.md](../../../../features/policy.md) — Policy DSL and anchoring model (`Delegate(delegator)` resolution for `Dip`).
