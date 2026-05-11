# KELS Protocol Attack Surface

Analysis of attack vectors against the KELS protocol — cryptographic properties, chain integrity across KEL/IEL/SEL primitives, key and policy management, and event verification. These are inherent to the protocol design, independent of deployment topology.

## Trust Model

The KELS protocol has no central authority. Four doctrinal pillars frame everything below; each protocol-level attack vector is best understood as an attempt to violate or evade one of them.

**Compromise is permanent — authority is current-state-only.** The protocol grants authority only to a chain's currently-tracked state (and the most-recent shared pre-divergence state, where divergence has occurred). Past keys, past policies, past endorsers have zero structural ability to act on the chain. A KEL signing/recovery key rotated out of current state cannot `Cnt` the chain even if the adversary still holds the key material; an IEL `governance_policy` participant superseded by `Evl` cannot `Cnt`/`Dec` the chain after their revocation; an SEL bound to a stale IEL event whose governance has since rotated cannot be `Cnt`'d/`Dec`'d by the rotated-out parties (subject to operator-side ratcheting via `Sea`). The structural mechanism is the chain's evaluation/recovery seal: new events must land at-or-after `seal_version`, so divergent branches always derive from a parent that carries the chain's currently-tracked state. See [../design/protocol-doctrine.md §Compromise is Permanent](../design/protocol-doctrine.md#compromise-is-permanent).

**End-verifiability.** Every event carries SAID + signature + chain linkage. Tampering at any node — by an adversary, by a buggy replication path, by a malicious peer — surfaces at the consumer's verifier walk. The source of an event is untrusted; the data of the event is end-verified. Protocol attack surface is structurally bounded to what an adversary can do with **valid data**, not what they can do by injecting a single node into the gossip mesh.

**Verifier is the trust boundary.** Every chain-validity invariant lives in the verifier walk (`KelVerifier`, `IelVerifier`, `SelVerifier`). Submit-handler checks are fast-path optimizations and provide better error messages, but they are not the security boundary. A rule enforced only at the submit handler is bypassable via direct DB injection, replication from a tampered peer, or restoration from a tampered backup; the verifier closes those paths because it runs over data from any source. See [§Verifier-Merge Architecture](#verifier-merge-architecture) below.

**Federation convergence.** Gossip propagation paired with deterministic effective-SAID computation ensures every chain resolves to the same semantic state across all nodes in a healthy federation. Anti-entropy detects effective-SAID mismatches and reconciles. This is what makes "the data is end-verified" meaningful in the federated case — a consumer querying any node sees a chain semantically equivalent to what every other node would serve. Doctrine rules that exist specifically to restore convergence on gossip-fragmented chains (Cnt Overrides Dec, the upgrade rule for non-archiving privileged events) depend on this pillar for their cryptographic-soundness argument. **Single-node deployments forfeit this property** — they trade convergence-via-replication for operational simplicity and accept that DB tampering surfaces only at the application/operator layer rather than via cross-node mismatch. See [§DB Compromise + Key Compromise](#db-compromise--key-compromise) for the carve-out, and [../design/protocol-doctrine.md §Federation Convergence](../design/protocol-doctrine.md#federation-convergence) for the full doctrine.

Security rests on cryptographic primitives:
- **Signatures.** ML-DSA-65 (FIPS 204) at 192-bit post-quantum security for all clients and infrastructure by default; ML-DSA-87 at 256-bit available; P-256 / ECDSA at 128-bit classical security as a client fallback.
- **Content-addressable identifiers.** SAID via Blake3-256.
- **Forward commitments.** Rotation/recovery hash chains on KEL; policy immunity (Blake3 SAID-pinning of policy content) on IEL.

**Assumptions:**
- Clients hold private keys in hardware-backed storage (Secure Enclave on iOS, HSM via PKCS#11 for services).
- All clients and infrastructure use ML-DSA-65 or ML-DSA-87 (FIPS 204) by default; clients may use P-256 as a fallback.
- Events are version-qualified (`kels/kel/v1/events/icp`) for future protocol evolution.
- Federation deployments run with replication (multiple nodes behind a gossip mesh).

## Doctrine-Layer Attacks

Attacks that exist *because* of the doctrine's structural decisions — outside the doctrine's reach by construction. Each is documented for honesty rather than defended against in the verifier; operational mitigations are noted where they apply.

### Privileged-Event DoS

**Attack:** A party already controlling a chain's current authority submits `Cnt` (or `Dec`) to pre-emptively terminate the chain.
- **Outcome:** Indistinguishable from legitimate operator-initiated termination. Reduces to current-state compromise (covered under [../design/protocol-doctrine.md §Limit of the Doctrine](../design/protocol-doctrine.md#limit-of-the-doctrine)).
- **Mitigation:** None at the protocol layer. The submitter already passes every authority check; the chain mathematics cannot distinguish them from the legitimate operator. Operational defenses (high thresholds, custody separation, monitoring) reduce the likelihood of current-state compromise in the first place.

### Coerced or Forced Termination

**Attack:** An operator is coerced into submitting `Dec` or `Cnt` under duress.
- **Outcome:** Operationally indistinguishable from voluntary termination. The protocol has no observable signature for coercion.
- **Mitigation:** None at the protocol layer. Operational hardening (legal protections, custody policies, application-layer dead-man patterns) is outside protocol scope.

### Strategic Compromise Patience

**Attack:** A strategic adversary doesn't act on first-key compromise — they accumulate quietly until they hold a satisfying combination of the current policy (threshold met, or full policy in single-custodian cases), then act decisively.
- **Outcome:** The doctrine's "detect-and-respond window" is bounded by the adversary's timeline (when they choose to act), not the operator's observation (when per-key compromise becomes evident). Compromise of individual keys may produce no protocol-observable signal until accumulation completes; by then the adversary's privileged event is already authorized to land.
- **Mitigation:** None at the protocol layer. Operational defense via policy redundancy: high thresholds + custody separation raise the accumulation cost; `threshold(N, M)` with `M > N` allows the operator to ratchet-out detected-compromised members via `Evl` (IEL) or by re-anchoring under a different subset (KEL/SEL anchors), keeping the prefix stable; hierarchical scope partitioning bounds the blast radius. See [../design/protocol-doctrine.md §Adversary Patience and Policy Redundancy](../design/protocol-doctrine.md#adversary-patience-and-policy-redundancy) for the threat model and operational stakes.

### Race-vs-Takeover Indistinguishability

**Attack:** Two parties — one legitimate, one adversarial — submit conflicting events that race onto the chain, producing divergence. Alternatively: two legitimate parties race and produce divergence; an external observer interprets the divergence as evidence of compromise.
- **Outcome:** Divergence is divergence; the chain shape does not record cause. Consumer trust degrades uniformly post-divergence. Out-of-band judgment (the operator's own observation history, external attestations through a different channel) is the only way to interpret event-level legitimacy.
- **Mitigation:** None at the protocol layer. Multi-party governance synchronization above the protocol (designated submitter, leader election, Raft over the registry) prevents accidental race-induced divergence on high-stakes chains. See [../design/iel/event-log.md §Multi-Party Governance Synchronization](../design/primitives/iel/event-log.md#multi-party-governance-synchronization).

### Cnt-Dec Race Convergence

**Phenomenon:** Two parties race terminal events onto a linear chain — the operator submits `Dec` (clean retirement) to one node; a second authority-holder submits `Cnt` (contest) to another. Without a tiebreaker, each node accepts the event it received first via its terminal-state gate, locking in incompatible terminals across the federation.
- **Outcome (without doctrine):** A node that received `Dec` first closes its decommissioned-state gate against gossip-delivered `Cnt`; a node that received `Cnt` first closes its contested-state gate against gossip-delivered `Dec`. Effective SAID diverges across the federation (`hash("decommissioned:{prefix}")` = Dec.said vs `hash("contested:{prefix}")`); anti-entropy spins forever finding mismatched SAIDs without being able to fix either side. The chain has two different "authentic" terminal states under the same prefix — a protocol-completeness failure.
- **Doctrine — Cnt overrides Dec.** The decommissioned-state gate accepts a gossip-delivered `Cnt` (with `previous = v_{d-1}.said`) as a state-transition event. `Cnt` lands at `v_d` alongside `Dec`; privileged-divergence-is-terminal fires; the chain becomes contested. The reverse is rejected: a gossip-delivered `Dec` to a contested chain is dropped by the contested-state gate. The asymmetry is intentional — `Cnt` always wins on a `Cnt`-`Dec` collision, so the federation converges on contested. The override is structural doctrine for protocol-completeness, not a defense against an attacker — it exists to satisfy the [Federation convergence pillar](#trust-model) on `Cnt`-`Dec` races. See [../design/protocol-doctrine.md §Cnt Overrides Dec](../design/protocol-doctrine.md#cnt-overrides-dec) and [../design/protocol-doctrine.md §Federation Convergence](../design/protocol-doctrine.md#federation-convergence).
- **Side-effect:** A safety benefit falls out — an adversary's racing `Dec` cannot launder a contested compromise into a clean-retirement appearance, because the operator's (or any authority-holder's) `Cnt` propagates and forces contested federation-wide.
- **Cross-primitive symmetry:** The override mechanic applies identically on KEL, IEL, and SEL — the convergence failure mode is the same on every primitive, so the doctrine is the same on every primitive.

The remainder of this doc tabulates attacks the doctrine **does** defend against — past-key replay, past-policy replay, past-binding replay, seal-cap violation, divergence flooding, anchor poisoning, single-event squat — and notes mitigations per primitive.

## Key Compromise (KEL)

A controller of a KEL identity has three keys to protect. Clients should be deployed to mobile with hardware-backed keys, or services with HSM-backed keys.

### Key Hierarchy

| Key | Purpose | Exposure |
|-----|---------|----------|
| **Signing** | Signs `ixn` and `rot` events | Active — used for every operation |
| **Rotation** | Pre-committed next key; revealed during rotation, becomes the new signing key | Semi-dormant — only needed for key rotation |
| **Recovery** | Revealed during recovery-revealing events; dual-signed with rotation key | Dormant — only needed for emergency recovery, contest, or decommission |

### Compromise Scenarios

**Signing key compromised:**
- **Attack:** Adversary can sign `ixn` events (anchor arbitrary data) and submit them to any KELS node.
- **Impact:** Limited to interaction events. Cannot rotate keys, cannot take over the identity.
- **Recovery:** Owner rotates signing key (`rot`). If the adversary submits conflicting events before rotation propagates, divergence occurs. Owner submits `rec` (requires rotation + recovery key, dual-signed); the discriminator archives the other branch. KEL resumes normally.
- **Detection:** Divergence is detected automatically when two events share the same `previous` SAID. The chain transitions to **Divergent (non-privileged)** for `Rot`/`Ixn` races, recoverable via `rec`.

**Rotation key compromised:**
- **Attack:** Adversary can submit a `rot` event (taking over the signing key) and subsequently sign unlimited `ixn` and `rot` events.
- **Impact:** Full control of the signing chain. Adversary can anchor data, rotate keys repeatedly.
- **Recovery:** Owner submits `rec` (requires the pre-compromised rotation key + recovery key, dual-signed). After recovery, adversary events are archived. If the adversary rotated the signing key and the owner did not, an extra `rot` is needed post-`rec` to escape the compromised key.
- **Detection:** Same as signing key — divergence detection.

**Signing-key-only `rot` takeover (operator recourse via this design):** A nuance worth calling out. If an adversary captures only the signing key (recovery key remains in separate custody) and submits a `rot` at `v_N`, today's "Cnt extends tip" model would leave the owner with no recourse — `Cnt` would require keys committed by `v_N` (adversary-chosen). Under this design, `Cnt` extends `v_{N-1}.said`, requiring keys committed by `v_{N-1}`: the `v_N`-current signing key (revealed by the adversary's `rot` — both parties have it) AND the `v_N`-current recovery key (NOT revealed by `rot` — only the owner has it, since recovery is revealed only by `rec`/`ror`/`dec`/`cnt`). Owner's dual-signature succeeds; adversary's does not. Operator can terminate the chain and reincept under a new prefix. See [../design/kel/event-log.md §Operator recourse against signing-key-only Rot takeover](../design/primitives/kel/event-log.md#operator-recourse-against-signing-key-only-rot-takeover).

**Recovery key compromised (along with rotation key):**
- **Attack:** Adversary has full administrative control — can submit `rec`, `ror`, `dec`, or `cnt` events.
- **Impact:** Total identity compromise. Both parties hold the same authorities.
- **Recovery:** Owner's recourse is `cnt`. `Cnt.previous = v_{tip-1}.said` (the parent of the chain's current tip on a linear chain, or `v_{d-1}` on a divergent chain — same `v_{tip-1}` rule, different chain shape). `Cnt` is recovery-revealing → privileged → its presence in any divergent set triggers privileged-divergence-is-terminal; the chain transitions to contested-terminal at first observation. Neither party can add further events. This is the correct outcome when key compromise is total.
- **Detection:** The verifier walk identifies the contested state; consumer trust degrades per the whole-chain-suspect rule. See [../design/protocol-doctrine.md §Trust Model on Contested Chains](../design/protocol-doctrine.md#trust-model-on-contested-chains).

**Recovery key compromised (without rotation key):**
- **Impact:** Recovery key alone is useless — all recovery-revealing events (`rec`/`ror`/`dec`/`cnt`) require dual signatures (rotation + recovery). No action possible without both keys.

### Past-Key Replay (Doctrine Win)

**Attack:** Adversary holds a long-ago-rotated key; tries to submit `rot`/`rec`/`ror` using it.
- **Mitigation:** Verifier checks each establishment event's pre-rotation commitment against the **currently-tracked** `rotation_hash` / `recovery_hash` on the branch. Past commitments don't satisfy current state. HARD-fail rejection at the verifier walk — every event with failed auth is rejected.
- **Doctrine reference:** [../design/protocol-doctrine.md §Compromise is Permanent](../design/protocol-doctrine.md#compromise-is-permanent).

## Event Submission Attacks (KEL)

### Forged Event Injection

**Attack:** Submit events with invalid or forged signatures.
- **Mitigation:** `submit_events` validates all signatures upfront before any merge. Each signature is parsed via `Signature::from_qb64()` and verified during the KEL merge against the public key from the latest establishment event. Invalid signatures cause immediate rejection.

### Dual-Signature Bypass

**Attack:** Submit a recovery-revealing event (`rec`, `ror`, `dec`, `cnt`) with only one signature.
- **Mitigation:** `submit_events` explicitly checks `requires_dual_signature()` and rejects events with fewer than 2 signatures. The verifier walk also verifies both signatures independently against the relevant commitments.

### Event Replay

**Attack:** Re-submit previously valid events to trigger unexpected behavior.
- **Mitigation:** Before merging, `submit_events` builds a set of existing SAIDs and filters out duplicates. Duplicate events are silently accepted (idempotent). The advisory lock per prefix serializes concurrent submissions.

### Prefix Spoofing

**Attack:** Submit an event with a prefix that doesn't match the KEL it chains from.
- **Mitigation:** KEL verification checks that all events in a KEL share the same prefix. A mismatched prefix fails validation.

### SAID Manipulation

**Attack:** Submit an event where the SAID doesn't match the content hash.
- **Mitigation:** `event.verify()` recomputes the SAID from the event content and compares it to the declared SAID. Any mismatch is rejected.

### Chain Gap Exploitation

**Attack:** Submit events that reference a `previous` SAID not present in the KEL, attempting to create a phantom chain.
- **Mitigation:** The verifier walk validates that every event's `previous` field references an existing event in the KEL. Missing predecessors cause rejection with "Events not contiguous."

### Seal-Cap Violation

**Attack:** Submit an event with `event_version < seal_version` — attempting to fork at-or-before the last `Rec`/`Ror`/`Dec`/`Cnt`.
- **Mitigation:** The verifier walk enforces `event_version >= seal_version`. Any submission whose land-version is strictly before the seal is rejected with "Cannot land at version V — sealed by evaluation/recovery at version S". This is the structural mechanism that enforces current-state-only authority. See [../design/protocol-doctrine.md §Forks are Seal-Bounded](../design/protocol-doctrine.md#forks-are-seal-bounded).

## KEL Merge Exploitation

### Divergence Flooding

**Attack:** With a compromised signing key, submit divergent events to many different KELS nodes simultaneously, hoping to maximize the window where the KEL is frozen.
- **Mitigation:** Gossip propagates both branches of a divergent KEL. All nodes converge on the same divergent state (cross-node SAID consistency via `hash_effective_said("divergent:{prefix}")` — see [Federation convergence pillar](#trust-model) and [../design/protocol-doctrine.md §Federation Convergence](../design/protocol-doctrine.md#federation-convergence)). The owner can submit `rec` to any single node, and recovery propagates via gossip to all nodes. The post-divergence window is bounded structurally by the proactive-ROR rule (`MAX_NON_REVEALING_EVENTS = 62`) — non-privileged-divergent chains cannot extend more than 62 events before requiring `Rec`/`Ror`/`Dec`/`Cnt`.
- **Residual risk:** Window of frozen KEL depends on gossip propagation speed and owner response time.

### Recovery Race

**Attack:** A second party with the recovery key races the owner to submit a recovery-revealing event first.
- **Mitigation:** Privileged-divergence-is-terminal fires uniformly on `Rec`/`Ror`/`Cnt`/`Dec`. Two shapes:
  - **Concurrent recovery-revealing submissions on different nodes.** Both `rec`s land via linear-chain rules on their submitting nodes; gossip merges into a divergent set containing two privileged events. The privileged-divergence rule fires at first observation on each node; chain transitions to contested-terminal. No race "winner" — the chain ends.
  - **Sequential: one party's `rec` lands cleanly, the other submits `Cnt`.** Loser's `Cnt` extends `v_{tip-1}.said` on the post-`rec` linear chain, lands at the tip's serial, creates fresh divergence with `Cnt` privileged in the set; privileged-divergence fires; chain becomes contested-terminal.
- The second party always retains the ability to force termination — the chain mathematics never let one party "keep the chain" against another holder of recovery authority. This is the correct security outcome.

### Re-divergence After Recovery

**Attack:** After the owner recovers, a second party re-submits events at the same generation to re-diverge.
- **Mitigation:** Recovery via `rec` advances the chain past the divergence point — the discriminator archives the other branch's events. The post-`rec` chain has a new seal at Rec's version (or `v_{d+1}` on branch-tip-extending; `v_d` on divergence-ancestor-extending). Any attempt to re-diverge by an event extending pre-`rec` state fails the seal-cap (`event_version >= seal_version`). If the second party still controls the recovery key and submits `Cnt` extending `v_{tip-1}.said` on the post-`rec` linear chain, `Cnt` lands at the tip's serial, creates a divergent set, privileged-divergence-is-terminal fires, and the chain transitions to contested-terminal. There is no "re-divergence into a recoverable state" — any post-`rec` privileged event from a second authority-holder transitions the chain into contested-terminal, never back into a recoverable divergent state.

### Contested KEL Bypass

**Attack:** Submit events to a contested (permanently frozen) KEL.
- **Mitigation:** The contested-state gate in the verifier walk rejects all submissions, including subsequent privileged events arriving via gossip at `v_d`. A contested KEL is truly permanent — no bypass.

### Decommissioned KEL Bypass

**Attack:** Submit events to a decommissioned KEL (perhaps with a past compromised key from before decommission).
- **Mitigation:** `Dec` is recovery-revealing → privileged → advances the seal to its own version. The seal-cap rule (`event_version >= seal_version`) prevents any event from landing at versions strictly before the seal; a past-key-compromise adversary cannot fork the chain at-or-before `Dec`, and the verifier rejects with "Cannot land at version V — sealed by evaluation/recovery at version S".
- **Sole exception — Cnt override.** A gossip-delivered `Cnt` (with `previous = v_{d-1}.said`, where `v_{d-1}` is `Dec`'s parent) is accepted by the decommissioned-state gate as a state-transition event. `Cnt`'s land-version equals `Dec`'s land-version (`d = seal_version`), satisfying `event_version >= seal_version`; the seal-cap admits this parent-at-(seal − 1) boundary case (the parent sits at `seal − 1`; the new event lives at the seal). `Cnt` lands at `v_d` alongside `Dec`; privileged-divergence-is-terminal fires; the chain transitions to contested. This is structural doctrine for protocol-completeness, not an attack — see [§Cnt-Dec Race Convergence](#cnt-dec-race-convergence) above and [../design/protocol-doctrine.md §Cnt Overrides Dec](../design/protocol-doctrine.md#cnt-overrides-dec). Cnt's dual-signature authorization requirement at `v_{d-1}` still applies; a past-key adversary who cannot satisfy `v_{d-1}`'s commitments is rejected.

## KEL Verification Bypass Attempts

### Verification Bypass

**Attack:** Submit events that pass structure verification but have broken cryptographic properties.
- **Mitigation:** `KelVerifier` performs all checks in a single forward pass — structure, chaining, SAID integrity, pre-rotation commitments, recovery key commitments, and signature verification are all validated as each event is processed. There is no separate backward pass; forward commitments (rotation hash, recovery hash) are tracked per-branch and verified when the next establishment event reveals the committed key.

### Pre-rotation Commitment Violation

**Attack:** Submit a rotation event whose public key doesn't match the rotation hash committed in the previous establishment event.
- **Mitigation:** The verifier tracks `pending_rotation_hash` per branch and verifies `compute_rotation_hash(event.public_key)` matches the committed hash when processing each establishment event. Violations are rejected.

### Recovery Key Commitment Violation

**Attack:** Submit a recovery-revealing event with a recovery key that doesn't match the committed recovery hash.
- **Mitigation:** Same mechanism as rotation — `pending_recovery_hash` is tracked per branch and verified against the revealed recovery key when processing recovery-revealing events. Violations are rejected.

## IEL Attack Surface

The IEL primitive governs identity authorization via `auth_policy` (consumed by SELs) and `governance_policy` (the chain's own gate). All IEL events — `Icp`, `Evl`, `Cnt`, `Dec` — are governance-authorized; this has structural consequences for divergence handling. See [../design/iel/event-log.md](../design/primitives/iel/event-log.md).

### Past Governance-Policy Replay (Doctrine Win)

**Attack:** Adversary holds a past (rotated-out) `governance_policy` preimage. Tries to submit `Evl`/`Cnt`/`Dec` under it.
- **Mitigation:** Verifier resolves authorization against the **currently-tracked** `governance_policy` (declared at the predecessor's `Icp` or evolved by the predecessor's `Evl`). Past-policy preimages fail the current-state check. HARD-fail rejection at the verifier walk — every event with failed auth is rejected.
- **Doctrine reference:** [../design/protocol-doctrine.md §Compromise is Permanent](../design/protocol-doctrine.md#compromise-is-permanent).
- **Symmetry:** Structurally parallel to KEL Past-Key Replay and SEL Past-Binding Replay (see [§Stale-IEL-Binding Upd on Existing SEL](#stale-iel-binding-upd-on-existing-sel)). All three rely on the verifier resolving authorization against current state, not historical state.

### Concurrent Evl Race

**Attack:** Two legitimately governance-authorized parties (or one legitimate + one threshold-compromised — protocol cannot distinguish) submit `Evl` concurrently to different nodes.
- **Mitigation:** Both `Evl`s land via linear-chain rules on their submitting nodes. Gossip merges into a 2-event divergent set at the same version. Every IEL event is privileged → the divergent set always contains a privileged event → privileged-divergence-is-terminal fires → chain transitions to contested-terminal at first observation on each node. No protocol-level distinction between accidental race and threshold compromise; consumer/application response is the same (reincept under a new IEL prefix).
- **Operational mitigation:** Multi-party governance synchronization above the protocol (designated submitter, leader election, Raft) prevents accidental races. **Required for high-stakes IEL identities.** See [../design/iel/event-log.md §Multi-Party Governance Synchronization](../design/primitives/iel/event-log.md#multi-party-governance-synchronization).

### Threshold Compromise via Evl

**Attack:** Adversary acquires enough currently-tracked `governance_policy` preimage to satisfy threshold. Legitimately rotates governance away from the prior operator via `Evl`.
- **Outcome:** Adversary now controls the chain's currently-tracked authority. No protocol-level recourse post-rotation.
- **Mitigation:** None at the protocol layer post-rotation. Operational defenses: high thresholds, separation of custody, threshold redundancy (see [../design/policy.md §Threshold Redundancy](../design/features/policy.md#threshold-redundancy)), abandon-and-reincept under a new prefix. Within the detect-and-respond window (before the adversary's `Evl` lands), the operator can submit `Cnt` under the still-current pre-rotation authority; after the rotation, no protocol-level recourse remains. This is the "current-state compromise" limit covered under [../design/protocol-doctrine.md §Limit of the Doctrine](../design/protocol-doctrine.md#limit-of-the-doctrine).

### Cnt/Dec Submission to Already-Divergent IEL

**Attack:** Submit `Cnt` or `Dec` to an IEL whose contested-state gate has already closed (any divergence on IEL is contested-terminal by privileged-divergence rule).
- **Mitigation:** Contested-state gate rejects all subsequent submissions, including `Cnt`/`Dec` arriving via gossip at `v_d`.
- **Structural note:** IEL has no upgrade-rule path — every IEL event is privileged → no non-privileged divergent set can form on IEL → contested-terminal at first observation of any 2-event divergence. The 3rd-event-via-upgrade pattern that applies on KEL/SEL (non-privileged divergent set transitions to contested when a non-archiving privileged event joins) is structurally vacuous on IEL.

### Stale-IEL-Binding by SEL (cross-reference)

IEL events resolve their authorization intrinsically (via tracked policies); they don't reference other chains for their own auth. SELs bind to IEL events via `identity_event`, and that's where stale-binding attacks land. See [§SEL Attack Surface — Stale-IEL-Binding Upd on Existing SEL](#stale-iel-binding-upd-on-existing-sel).

## SEL Attack Surface

SELs are identity-rooted — every SEL binds at inception to an IEL prefix and resolves per-event authorization through specific IEL event SAIDs (`identity_event` field). See [../design/sel/event-log.md](../design/primitives/sel/event-log.md).

### Pre-Icp Camping

**Attack:** Adversary holds a past IEL `auth_policy` preimage. For a `(identity, topic)` pair that the legitimate operator hasn't asserted yet, the adversary submits `[Icp, Upd_stale]` first — `Icp` derives the SEL prefix deterministically from `(identity, topic)` (permissionless); `Upd_stale` binds to a past IEL event whose `auth_policy` the adversary can satisfy.
- **Mitigation:** Application-layer enrollment-time pattern. When the legitimate operator submits their own `[Icp, Upd_legit]`:
  - `Icp` dedups (deterministic prefix derivation; same SAID across submitters).
  - `Upd_legit.previous = Icp.said` — operator extends `Icp` via dedup-equivalence (an endorsement-class event never extends an adversary event; see [../design/protocol-doctrine.md §Extension Discipline](../design/protocol-doctrine.md#extension-discipline)). `Upd_legit` lands at `v_1` alongside `Upd_stale`, creating a non-privileged divergent set (both auth-authorized; Upd-Upd race shape).
  - Operator submits `Rpr` (governance-authorized via the bound IEL's current `governance_policy`) extending the `Upd_legit` branch; the discriminator archives `Upd_stale`. `Rpr` lands at `v_2`; the chain becomes the operator's.
  - Operator treats the user as inactive during enrollment; no consumers honor authorizations rooted in the in-progress chain. See [../design/iel/event-log.md §Application-developer enrollment patterns](../design/primitives/iel/event-log.md#application-developer-enrollment-patterns).
- **Residual visibility cost:** `Upd_stale` moves to the archive table as forensic record; visible to a determined inspector but cannot ground authorization.
- **Structural impossibility of closing further:** The deterministic prefix derivation enables dedup-idempotency, which is what creates the camping window. Closing the window would require breaking dedup-idempotency.

### Stale-IEL-Binding Upd on Existing SEL (Doctrine Win)

**Attack:** Adversary holds a past IEL `auth_policy` preimage. Tries to extend an existing SEL branch with `Upd_stale` referencing an old IEL event whose `auth_policy` the adversary can satisfy.
- **Mitigation:** Per-event parent-monotonic ratchet on `identity_event` (applied per branch). Each SEL event's `identity_event` must be at-or-after its parent event's `identity_event` in IEL chain order. If the operator's branch tip is bound to a recent IEL event (e.g., `IEL_v5`), an adversary's `Upd_stale` bound to `IEL_v2` cannot extend that branch — its `identity_event` regresses relative to the parent. HARD-fail rejection at the verifier walk.
- **Doctrine reference:** [../design/protocol-doctrine.md §Forks are Seal-Bounded](../design/protocol-doctrine.md#forks-are-seal-bounded) (per-event parent-monotonic on SEL).
- **Symmetry:** Structurally parallel to KEL Past-Key Replay and IEL Past Governance-Policy Replay. The mechanism differs (SEL references its auth context via `identity_event` rather than tracking it intrinsically), but the doctrinal-rejection shape is the same.

### Race-Divergence Upd-Upd

**Attack:** Two parties holding currently-tracked `auth_policy` extend the SEL concurrently — each submits a competing `Upd` on a different node.
- **Mitigation:** Non-privileged divergent set forms at the same version (both `Upd`s auth-authorized, neither privileged). Recoverable via `Rpr` (governance-authorized; archives one branch via the discriminator). Privileged-divergence-is-terminal does NOT fire — no privileged event in the divergent set. Standard divergence-resolution flow.
- **Doctrine note:** Both branches are protocol-valid by construction; the protocol cannot determine which is the rightful operator. The `Rpr`-submitting party (whoever currently holds governance) dictates which branch survives.

### Permissionless-Icp Single-Event Squat

**Attack:** Submit `[Icp]` alone (no `Upd`) for a `(identity, topic)` prefix to lock the chain at `v_0` with no policy enforcement.
- **Mitigation:** Inception batch rule — a submission containing `Icp` MUST also contain `Upd` at `v_1` in the same batch. Enforced inside the verifier (`SelVerifier::finish_internal` returns `IncompleteInception` whenever any branch tip is still `Icp`). The rule lives in the verifier walk, not just at the submit handler, so a tampered DB serving `[Icp]` alone is rejected at end-verification. See [../design/sel/events.md §Inception batch rule](../design/primitives/sel/events.md#inception-batch-rule).
- **Result:** Single-event squat is structurally impossible.

### Stale-Bound Sea/Rpr/Cnt/Dec

**Attack:** Adversary holds a past IEL `governance_policy` preimage. Tries to submit any of the governance-authorized SEL lifecycle events (`Sea`/`Rpr`/`Cnt`/`Dec`) bound to a past IEL event whose `governance_policy` the adversary can satisfy.
- **Mitigation (general case):** HARD anchor — the verifier rejects unless the resolved policy at the bound IEL event is satisfied AND per-event parent-monotonic on `identity_event` is satisfied. On an actively-maintained live branch (operator has ratcheted `identity_event` forward via prior events), an adversary's stale-bound same-branch extension fails parent-monotonic.
- **Acknowledged residual: Cnt fork-contest with low `identity_event`.** A `Cnt` that branches from `v_{d-1}` (forming its own singleton branch at `v_d`) need only satisfy `Cnt.identity_event >= v_{d-1}.identity_event` — it does not need to satisfy any constraint relative to the existing diverged branches (those are structurally independent branches from this `Cnt`'s branch). A stale-governance holder can use this shape to terminate a chain whose live branch hasn't been ratcheted past their old IEL event. **Mitigation: operator discipline.** After IEL governance evolves, the operator submits `Sea` on each dependent SEL to advance the live branch's tip `identity_event` forward to the current IEL event, closing the regression window for adversaries extending the live branch. See [../design/iel/event-log.md §What parent-monotonic blocks (and what it doesn't)](../design/primitives/iel/event-log.md#what-parent-monotonic-blocks-and-what-it-doesnt).

## Cross-Primitive Cascade

KELS primitives chain authority: KELs anchor IEL governance acts; IELs root SEL authorization. When one chain becomes contested, dependent chains lose their authorization basis.

### KEL Cnt Cascade

**Scenario:** A KEL is contested (compromise detected; current authority holder submits `Cnt`).
- **Cascade effect:** IEL events anchored under that KEL lose authorization grounding (their anchors traced through a now-suspect KEL). Dependent SELs bound to those IEL events lose authorization basis. The whole-chain-suspect rule applies recursively.
- **Operator response:** Cascade-reincept under new prefixes. The contested KEL is forensic-readable but cannot ground new trust decisions. The dependent IEL must reincept against a different anchoring KEL; the dependent SELs must reincept against the new IEL.
- **Doctrine reference:** [../../AGENTS.md §System Thesis](../../AGENTS.md#system-thesis) (cascade-reincept honesty) + [../design/protocol-doctrine.md §Limit of the Doctrine](../design/protocol-doctrine.md#limit-of-the-doctrine) (cascade-reincept bullet).

### IEL Contested Cascade

**Scenario:** An IEL becomes contested (divergence on any IEL is immediately contested by privileged-divergence rule, since every IEL event is privileged).
- **Cascade effect:** SELs bound to any event in the contested IEL chain lose authorization basis. Consumers cannot tell from chain data which IEL event was authored legitimately; they cannot ground SEL trust in any IEL event on a contested chain. See [../design/iel/event-log.md §Effect on Bound SELs](../design/primitives/iel/event-log.md#effect-on-bound-sels).
- **Operator response:** Reincept SELs under a new IEL prefix; rebind dependent chains forward to the new identity.

### Stale-Binding Propagation

**Scenario:** An IEL evolves governance (via `Evl`). SELs bound to past IEL events keep their old authorization-resolution path, still resolving against the pre-evolution policy.
- **Operator-discipline mitigation:** After significant IEL governance evolution, the operator submits `Sea` on each dependent SEL to advance the live branch's tip `identity_event` forward to the new IEL event. This closes the regression window on the live branch — any same-branch extension thereafter must bind at-or-after the new IEL event (per-event parent-monotonic).
- **Structural defense:** None — chain mathematics permit stale bindings on pre-evolution events. This is operator-discipline territory, not a structural defense. See [../design/iel/event-log.md §Operator-discipline corollary for governance evolution](../design/primitives/iel/event-log.md#operator-discipline-corollary-for-governance-evolution).

### Cascade-Reincept Cost

The cascade isn't a vulnerability — it's the doctrine's structural cost when a high-stakes identity falls. Identity hierarchies built with a single root carry the entire dependent tree's reincept cost when the root falls. **Operators should partition the dependency graph so a single compromise has a bounded blast radius.** See [../../AGENTS.md §System Thesis](../../AGENTS.md#system-thesis).

## Policy / SAID Layer

Cross-cutting concerns at the policy and SAID-resolution layer that apply across primitives.

### Non-Immune Policy Reference

**Attack:** An IEL `Icp` or `Evl` references a policy whose `immune` flag isn't set, intending to mutate the policy's content later via a poison endorsement.
- **Mitigation:** Both the merge engine (at submit time) and the verifier (at verification time) reject any IEL event that introduces or evolves a non-immune policy. Both layers enforce because the verifier processes data from any source — gossip, peer pulls, restored backups, bootstrap — and cannot trust that the originating node enforced the rule. See [../design/iel/events.md §Policy immunity requirement](../design/primitives/iel/events.md#policy-immunity-requirement).
- **Result:** No policy used in IEL `auth_policy` or `governance_policy` can be poisoned. Past `Evl` / `Cnt` / `Dec` evaluations stay satisfied by construction.

### Policy Substitution Under Same SAID

**Attack:** Replace a policy's content while preserving its SAID, hoping to substitute meaning.
- **Mitigation:** Blake3 collision resistance. SAID = Blake3(policy content, `said` field blanked). Substituting content under the same SAID requires a Blake3 collision; same SAID structurally implies same content. Tampered substitution fails SAID verification on read.

### Policy Resolution from Tampered Node

**Attack:** A consumer fetches a policy from a tampered node; the node returns altered content under the policy's claimed SAID.
- **Mitigation:** Verifier re-verifies the policy's SAID on read from any source. Tampered substitution surfaces as SAID-verification failure. The serving node is not trusted; the data is end-verified.

### Anchor Verification on Recovered or Contested KEL

IEL/SEL verifiers resolve authorization by checking that the event's SAID is anchored under the relevant policy via a signed `ixn` in one or more KELs. The anchoring KEL itself must be valid for the anchor to ground authorization. A recovered KEL has nuanced consequences for past anchors (anchors on the surviving branch survive; anchors on the archived branch may not); a contested KEL is whole-chain-suspect and cannot ground new trust decisions. See [../design/iel/event-log.md §Trust Caveat — Recovered or Contested Anchoring KELs](../design/primitives/iel/event-log.md#trust-caveat--recovered-or-contested-anchoring-kels).

## Verifier-Merge Architecture

The verifier is the trust boundary; every chain-validity invariant lives in the verifier walk. A historically-relevant attack surface — a rule enforced only at the submit handler — is the canonical example of how this trust boundary works.

**Pre-unification surface (historical example).** A chain-validity rule that lived only at the submit handler — e.g., the SEL `[Icp, Upd]` minimum batch rule prior to lifting it into `SelVerifier::finish_internal` — was bypassable by:
- Direct DB injection on a tampered node.
- Replication from a malicious peer that didn't run the submit handler.
- Bootstrap from a tampered backup.
- Any path where the submit handler isn't on the critical path between data ingestion and consumer verification.

A downstream consumer's end-verifier walking the chain would accept the structurally-invalid result because the rule wasn't on its walk.

**Post-unification (design target; tracked by [#181](https://github.com/jasoncolburne/kels/issues/181)).** A single walk implements every chain-validity rule. End-verification and merge-time verification compose because they are the same code path; submit-time verification is "end-verification with new events appended" run under the merge engine's advisory lock. Drift surface eliminated: no rule can drift between the merge-time path and the consumer-verifier path because there's only one path. Submit-handler checks still exist for fast-path optimization (e.g., immediate-rejection error messages), but the verifier walk is the only enforcement boundary.

This is the structural mechanism by which the "verifier is the trust boundary" doctrine is enforced. Any rule lifted from a submit handler into the verifier walk gains end-verifier enforcement automatically across all ingestion paths (submit, gossip-received, replicated cache, restored backup, bootstrap).

## Client-Side Attacks

### Key Extraction

**Attack:** Extract private keys from client storage.
- **Mitigation:** Hardware-backed keys (Secure Enclave on iOS, PKCS#11 HSM for services) are designed to be non-extractable. The `kels-ffi` library interfaces with Apple's Secure Enclave; the identity service loads PKCS#11 .so directly via cryptoki (mock HSM in development, real HSM in production).
- **Residual risk:** Software-only key storage (e.g., file-based `KelStore`) is vulnerable to filesystem access. This is acceptable for development but not production.

### Local State Manipulation

**Attack:** Modify the client's local KEL state (SQLite database or file store) to desynchronize from the server.
- **Mitigation:** The client always fetches the current KEL from the server before creating events. The `KeyEventBuilder` chains from the owner's tail, which is tracked server-side. Local state manipulation causes the client to submit events that fail server-side validation.
- **Residual risk:** A manipulated client could be tricked into signing events based on false local state, but those events would fail validation when submitted.

### Owner Tail Confusion

**Attack:** Trick the client into chaining from the wrong tail, creating an event that doesn't properly connect to the KEL.
- **Mitigation:** The `owner_tail` is tracked in memory by `KeyEventBuilder::get_owner_tail()`, which returns the last event in the builder's local KEL. The builder syncs with the server KEL before creating events, and the server validates that submitted events chain from a valid previous event. Events that don't chain correctly are rejected.

## Automatic Key Rotation

The identity service implements an automatic rotation schedule for HSM-backed service identities (registries and gossip nodes) that limits the window of exposure for any compromised key. End-user clients managing their own keys (e.g., mobile apps with Secure Enclave) are responsible for their own rotation schedule.

### Schedule

- **Check interval:** Configurable via `IDENTITY_ROTATION_CHECK_PERIOD_MINUTES` (default: 360, i.e. every 6 hours). The identity service checks whether the current key binding is due for rotation.
- **Rotation interval:** Configurable via `IDENTITY_ROTATION_INTERVAL_DAYS` (default: 180). If the latest HSM key binding is older than this, rotation is triggered. With ML-DSA's post-quantum security, longer rotation intervals are acceptable.
- **Mode selection:** Scheduled rotation auto-selects the rotation type based on rotation count. Every third rotation is a recovery key rotation (`ror`), the rest are standard signing key rotations (`rot`). This results in recovery keys rotating every third interval.

### Binding Chain Integrity

The auto-rotation loop performs two levels of binding verification:

**Full chain audit** (alert only — does not trigger rotation):
1. Each binding's SAID is verified (content matches declared hash)
2. Chain links are verified (each binding's `previous` pointer matches the prior binding's SAID)
3. Versions increment by exactly 1
4. All binding SAIDs are anchored in the identity's KEL (prevents a database-only attacker from forging bindings)

If the full chain audit fails, a `SECURITY` warning is logged. This is intentionally separated from the rotation decision because a corrupted historical binding cannot be fixed by rotating — triggering rotation on historical chain corruption would cause the service to rotate every check period indefinitely, since the old corrupted records remain in the database.

**Latest binding verification** (triggers defensive rotation on failure):
1. Latest binding's SAID is verified
2. Latest binding's `previous` pointer matches the prior binding's SAID
3. Latest binding's SAID is anchored in the KEL

If the latest binding verification fails, rotation is triggered immediately — something is actively wrong with the current key state. Unlike historical corruption, rotating creates a new valid latest binding, so this check is self-healing.

### Rotation Execution

All KEL operations — automatic and admin-initiated — go through a single `perform_kel_operation` code path:
1. The builder's KEL is reloaded from the database
2. The rotation event (`rot` or `ror`) is created and signed via the HSM
3. The builder's key provider is updated in-place with the new key handles
4. A new HSM binding is created (chained from the previous), anchored in the KEL, and persisted
5. The authority mapping is updated with the new tip SAID

This ensures the server's in-memory signing state is always consistent with the persisted state, regardless of whether rotation was triggered automatically or via the admin CLI.

### Security Properties

- **Bounded exposure window:** A compromised signing key is useful for at most one rotation interval before automatic rotation obsoletes it. The adversary must then compromise the new key (which they cannot predict due to pre-rotation commitment).
- **Recovery key freshness:** Recovery keys rotate every third interval, limiting the window for recovery key compromise.
- **Defensive rotation:** If the binding chain is tampered with, immediate rotation limits the damage window.
- **Authenticated management endpoint:** The `POST /api/v1/identity/kel/manage` endpoint requires a `SignedRequest` verified against the identity's own KEL, preventing unauthorized KEL operations.

## DB Compromise + Key Compromise

If an adversary compromises both a KELS node's database and a signing key, they could remove legitimate events and replace them with their own in the database. On an unreplicated node, this is a problem — the adversary's events would be served as if they were legitimate.

However, with a full backbone deployment (recommended), any sync operation with other nodes will surface the conflicting events as divergence across the gossip mesh. The legitimate events exist on other nodes and will be gossiped back. Recovery proceeds as usual via the `rec` event (or via `cnt` if the compromise is total — see [§Key Compromise](#key-compromise-kel)), and the divergence alerts operators to investigate the compromised node. This is the [Federation convergence pillar](#trust-model) at work — see [../design/protocol-doctrine.md §Federation Convergence](../design/protocol-doctrine.md#federation-convergence) for the upstream doctrine.

**Mitigation:** Deploy with replication (multiple KELS nodes behind a gossip mesh). The gossip protocol's anti-entropy loop will detect and reconcile inconsistencies. Single-node deployments forfeit federation convergence and accept this risk — the carve-out that the Federation convergence pillar explicitly names.

End-verifiability provides a structural safety net here: even if a consumer fetches data from the compromised node, the verifier walk on the consumer's side will surface any structural invalidity (broken signatures, missing chain links, divergence). The compromised node can refuse to serve data, but cannot serve tampered data that passes consumer verification.

## Summary of Residual Risks

**Protocol-level attack vectors closed by the doctrine:**
- **Past-key replay** (KEL) — verifier resolves against currently-tracked commitments.
- **Past-policy replay** (IEL) — verifier resolves against currently-tracked `governance_policy`.
- **Past-binding replay** (SEL) — per-event parent-monotonic on `identity_event` blocks same-branch regression.
- **Seal-cap violation** — verifier rejects events landing strictly before the chain's last seal.
- **Recovery-race / divergence-as-takeover ambiguity** — privileged-divergence-is-terminal fires uniformly on `Rec`/`Ror`/`Cnt`/`Dec` (KEL), `Icp`/`Evl`/`Cnt`/`Dec` (IEL), `Sea`/`Rpr`/`Cnt`/`Dec` (SEL).
- **Policy poisoning** — IEL immunity rule rejects non-immune policies at both submit and verify time.
- **Permissionless-Icp single-event squat** (SEL) — inception batch rule rejects `[Icp]`-alone chains at end-verification.
- **DB-and-key compromise on a single node** — replicated deployment surfaces inconsistency via gossip anti-entropy.

**Residual surfaces the doctrine does not close — by construction:**
- **Current-state compromise.** Once an adversary controls a chain's currently-tracked authority (KEL signing+recovery keys; IEL `governance_policy` threshold; SEL identity binding's authorizing IEL event), they ARE the chain's current state by every protocol-observable measure. Operational defenses only — high thresholds, custody separation, monitoring, fast operator response. See [../design/protocol-doctrine.md §Limit of the Doctrine](../design/protocol-doctrine.md#limit-of-the-doctrine).
- **Race-vs-takeover indistinguishability.** Both legitimate races and adversarial forks produce identical chain shapes. Consumer-side judgment + out-of-band knowledge determines specific event-level interpretation; the protocol does not adjudicate.
- **Coerced/forced termination.** A `Dec` or `Cnt` submitted under duress is operationally indistinguishable from voluntary termination. Operational hardening only.
- **Cascade-reincept cost.** A high-stakes identity (KEL or IEL) that goes terminal cascades into reincept of dependent IELs/SELs. The doctrine doesn't shrink the cost; it bounds it via identity-hierarchy design (don't anchor everything to one root). See [../../AGENTS.md §System Thesis](../../AGENTS.md#system-thesis).
- **Operator-discipline windows.** Stale-bound `Cnt` fork-contest on an SEL whose live branch hasn't been ratcheted forward via `Sea` after IEL governance evolution; pre-Icp camping on a permissionless SEL prefix before the legitimate operator's enrollment. Mitigated by operator discipline (prompt `Sea` post-Evl; structured enrollment flow), not by structural defenses.
- **Key management posture.** Hardware-backed key storage is strongly recommended but not enforced by the protocol itself. Software-only key storage is acceptable for development; production deployments should use Secure Enclave / HSM.

The protocol closes the broad past-state kill-switch surface (low-friction, time-unbounded, structurally unmitigable without the doctrine) in exchange for a narrow current-state-compromise vulnerability (high-friction, time-bounded, operationally mitigable). This trade is intentional. See [../design/protocol-doctrine.md](../design/protocol-doctrine.md) for the full doctrine.
