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

| Kind | serial | previous | public_key | rotation_hash | recovery_key | recovery_hash | anchor | delegating_prefix | sort_priority | authorization |
|---|---|---|---|---|---|---|---|---|---|---|
| `Icp` | `== 0` | forbidden | **required** | **required** | forbidden | **required** | forbidden | forbidden | 0 | signing |
| `Dip` | `== 0` | forbidden | **required** | **required** | forbidden | **required** | forbidden | **required** | 1 | signing (+ `Delegated`) |
| `Ixn` | `>= 1` | required | forbidden | forbidden | forbidden | forbidden | **required** | forbidden | 2 | signing |
| `Rot` | `>= 1` | required | **required** | **required** | forbidden | forbidden | optional | forbidden | 3 | signing |
| `Ror` | `>= 1` | required | **required** | **required** | **required** | **required** | optional | forbidden | 4 | dual |
| `Rec` | `>= 1` | required | **required** | **required** | **required** | **required** | forbidden | forbidden | 5 | dual |
| `Dec` | `>= 1` | required | **required** | forbidden | **required** | forbidden | forbidden | forbidden | 6 | dual |
| `Cnt` | `>= 1` | required | **required** | forbidden | **required** | forbidden | forbidden | forbidden | 7 | dual |

### Authorization model

The "authorization" column names which signature(s) the verifier requires for the event to be accepted:

- **Icp** must be signed by the private counterpart of the `public_key` it declares. The verifier recomputes the prefix from the inception template (which includes `public_key`, `rotation_hash`, `recovery_hash`), confirms it matches `event.prefix`, then verifies the event's "signing" signature against `public_key`. Icp's SAID + prefix derivation provides chain identity; the signature against the declared key is the authorization. Subsequent v1+ events satisfy what Icp committed (`rotation_hash` for the next signing key, `recovery_hash` for the recovery key).
- **Dip** has the same submit-time authorization as Icp (signed by the declared `public_key`). Dip additionally declares a `delegating_prefix`, captured into the verification token but not checked at submit time. The delegation relationship is verified at *policy-evaluation time* via the `Delegated(delegator)` policy node: any KEL with `delegating_prefix == delegator` that the delegator anchors (via an `ixn` in the delegator's KEL) satisfies the node. The single-arg open form is what makes the indirection useful — the delegator can rotate their delegate fleet (decommission, replace, add) without changing any policy that references them. See [../../features/policy.md](../../features/policy.md) for `Delegated(delegator)` resolution.

  > **Note on current implementation:** `lib/policy/src/evaluator.rs:185` and `lib/policy/src/parser.rs:167` use a closed two-arg form `Delegate(delegator, delegate)`. That form pins a specific delegate in the policy SAID and defeats the indirection (replacing a delegate requires a new policy). It's stale; the target shape is tracked in [#77](https://github.com/jasoncolburne/kels/issues/77).
- **Rot** is signed by the new `public_key` it reveals. The verifier checks `Blake3(public_key) == prev_establishment.rotation_hash`, then verifies the signature against `public_key`. `rotation_hash` on `Rot` commits the *next* rotation key.
- **Ixn** is signed by the current active signing key — the `public_key` of the most recent establishment event in the chain (Icp / Dip / Rot / Rec / Ror).
- **Rec / Ror / Dec / Cnt** are dual-signed. The "signing" signature is by the key revealed in `public_key` (preimage of the prior establishment's `rotation_hash`); the "recovery" signature is by the key revealed in `recovery_key` (preimage of the prior establishment's `recovery_hash`). Both signatures must verify, and both digest commitments must match. This is the privileged primitive — exercising both the rotation key and the recovery key together proves dual control.

### Anchor on Rot and Ror

`Rot.anchor` and `Ror.anchor` are optional fields used for cross-chain anchoring of tier-2 and tier-3 IEL/SEL events per [../../protocol-doctrine.md §Anchor Tier Elevation](../../protocol-doctrine.md#anchor-tier-elevation). KEL itself does not consume these anchors during its own verification walk — they are read by IEL/SEL verifiers cross-chain when evaluating policy satisfaction at elevated tiers. Anchor format on `Rot`/`Ror` is identical to `Ixn.anchor`: a single `Option<Digest256>` referencing the SAID of the anchored IEL/SEL event.

### Recovery-key revelation

`Rec` / `Ror` / `Dec` / `Cnt` reveal the `recovery_key` field. Once revealed in any event on the chain, that recovery key is "spent" — future divergent events must be resolved by `Cnt` (contest), not `Rec` (recovery). The merge engine surfaces this via `KelMergeResult::ContestRequired` (see [event-log.md](event-log.md#contest-cnt) for the trigger).

`Ror` is the proactive form: an owner who has not been compromised can rotate both keys ahead of the proactive-ROR cap, revoking any future divergent recovery the adversary might attempt with stale key material.

### Forward-key commitments

Establishment events (every kind except `Ixn`) commit one or both forward-key digests:

- **`rotation_hash`**: required on `Icp`, `Dip`, `Rot`, `Rec`, `Ror`. Forbidden on `Dec`, `Cnt` (KEL ends — no future signing key).
- **`recovery_hash`**: required on `Icp`, `Dip`, `Rec`, `Ror`. Forbidden on `Rot` (Rot doesn't change recovery commitment), `Dec`, `Cnt` (KEL ends).

The verifier seeds `tracked_rotation_hash` / `tracked_recovery_hash` from inception and updates them on each establishment event. Future revelations are checked against the tracked digest.

### Proactive-ROR bound

`MAX_NON_REVEALING_EVENTS = MINIMUM_PAGE_SIZE - 2 = 62`. After 62 non-recovery-revealing events (i.e., events that aren't `Rec` / `Ror` / `Dec` / `Cnt`), the next event must reveal the recovery key. The `- 2` headroom accommodates a `[rec, rot]` recovery batch fitting in one `MINIMUM_PAGE_SIZE`-bounded page.

This bound caps an adversary's fork to 62 events before they need to satisfy the recovery primitive — which they cannot without the recovery key — and bounds the synchronous archival window during recovery to a single page. The builder auto-inserts `Ror` (upgrading a `Rot`) when the bound is about to be crossed.

KEL's proactive-ROR bound is the structural analog of SEL's evaluation seal (see [../sel/events.md](../sel/events.md#evaluation-bound)): in both, a privileged primitive (recovery-key revelation / governance evaluation) caps how far an adversary can fork before they must satisfy the higher bar.

### Cnt overrides Dec

See [../../protocol-doctrine.md §Cnt Overrides Dec](../../protocol-doctrine.md#cnt-overrides-dec) for the doctrinal mechanic (a gossip-delivered `Cnt` with `previous = v_{d-1}.said` lands alongside an existing `Dec` at `v_d`; the chain transitions to contested). On KEL, the auth check for the overriding `Cnt` is the dual-signature requirement against `v_{d-1}`'s `rotation_hash` and `recovery_hash` commitments.

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
s0..s4   normal chain; s5_a = ixn extending s_4 (operator)
s5_b     a second recovery-key holder submits Rec with previous = s_4.said,
         version = 5 (divergence-ancestor-extending shape; the discriminator
         archives s5_a; chain becomes recovered, linear, tip = Rec_b at v_5)
         — recovery key revealed by Rec_b; no further Rec can succeed —
s5_c     operator submits Cnt with previous = s_4.said, version = 5
                                                                          ← Cnt joins Rec_b at v_5 in a
                                                                            2-event privileged divergent set;
                                                                            privileged-divergence-is-terminal
                                                                            fires; chain contested-terminal.
                                                                            (Cnt dual-signed via s_4's
                                                                             commitments — signing key
                                                                             (preimage of s_4's rotation_hash)
                                                                             + recovery key (preimage of
                                                                             s_4's recovery_hash); both held
                                                                             by the operator.)
```

Recovery is no longer available after Rec_b reveals the recovery key, so Cnt is the only protocol-level path to terminate. Cnt's `previous = v_{tip-1}.said = s_4.said` selects the divergence ancestor (one before the chain's current Rec-tip), which puts authorization at s_4's commitments — the operator still satisfies them. Cnt's land-version v_5 = seal_version (Rec_b advanced the seal to v_5); the seal-cap's parent-at-(seal − 1) boundary case admits this (see [event-log.md §Recovery-Revelation Seal and Key Non-Poisonability](event-log.md#recovery-revelation-seal-and-key-non-poisonability)). The archived s5_a remains in the archive table; Rec_b and Cnt_c stay in live storage as the divergent set.

### Clean decommission

```
s0..sN   normal chain
sN+1     kind=dec   ← owner ends the KEL cleanly; dual-signed (kN + recovery key)
```

After `Cnt`, all submissions are rejected. After `Dec`, all submissions are rejected with one exception: a gossip-delivered `Cnt` (with `previous = v_{d-1}.said`, where `v_{d-1}` is `Dec`'s parent) overrides `Dec` and transitions the chain to contested per [../../protocol-doctrine.md §Cnt Overrides Dec](../../protocol-doctrine.md#cnt-overrides-dec). See [event-log.md](event-log.md) for the lifecycle and merge-observable case taxonomy.
