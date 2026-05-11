# Reading Guide

A table of contents for `docs/design/` organized by the order knowledge builds. Primitives are the load-bearing layer; everything else is downstream — features built on the primitives, operations built on the features.

## Prerequisite

If you haven't read [AGENTS.md §System Thesis](../../AGENTS.md#system-thesis), start there. The Thesis is the high-level framing that everything below assumes (KEL/IEL/SEL roles, the evaluation lens for design decisions, compromise-is-permanent doctrine, federation convergence as a foundational property).

## Foundation

[security-invariant.md](security-invariant.md) — the doctrine. Compromise is permanent (past-state authority has zero structural force), forks are seal-bounded, privileged divergence is terminal, Cnt overrides Dec, ordering without timestamps, federation convergence, extension discipline, trust model on contested chains, limit of the doctrine. Read in full before the primitives — every per-primitive doc cross-references this doc heavily, and reasoning about the primitives without the doctrine forces you to reconstruct invariants from worked examples rather than pick them up directly.

## Primitives

The substantive part of the design. Three primitives (KEL, IEL, SEL) implement the doctrine in different shapes. Each primitive has five docs in the same structural roles, and reading them in the same internal order makes the parallel structure visible.

### Internal order within each primitive

1. **events.md** — per-kind reference. What event kinds exist, their field rules, the satisfaction model (what authorizes each kind). Most approachable entry point.
2. **event-log.md** — chain lifecycle. States (active / divergent / contested / decommissioned), divergence semantics, terminal events, evaluation/recovery seal, trust caveats.
3. **merge.md** — submit handler routing. What the server does at the submit boundary; the kind-discriminator routing matrix.
4. **verification.md** — verifier walk algorithm. The single-pass walk that produces the Verification token; chain-validity invariants.
5. **reconciliation.md** — multi-node correctness matrix. The load-bearing proof that every state × submission × gossip combination terminates correctly and all nodes converge on the same effective SAID. This is the per-primitive proof of [security-invariant.md §Federation Convergence](security-invariant.md#federation-convergence).

### IEL — start here

The simplest primitive. Every IEL event is governance-authorized (no auth-vs-governance asymmetry), there is no recovery primitive (Rpr is absent — divergence is immediately terminal), no content payload (the chain's data is its tracked policy state), and the smallest kind set (`Icp`, `Evl`, `Cnt`, `Dec`). The cleanest place to internalize the core protocol concepts: cryptographically-linked event chains, divergence semantics, terminal events, evaluation seals, authorization via anchored policy.

Read in order: [events.md](primitives/iel/events.md) → [event-log.md](primitives/iel/event-log.md) → [merge.md](primitives/iel/merge.md) → [verification.md](primitives/iel/verification.md) → [reconciliation.md](primitives/iel/reconciliation.md).

### KEL — second

Adds device-level cryptography. Signing key, rotation key (pre-committed via `rotation_hash`), recovery key (revealed only by recovery-revealing events: `Rec`, `Ror`, `Dec`, `Cnt`). Dual-signature requirement on recovery-revealing events. Recovery via `Rec` with its two parent shapes — branch-tip-extending and divergence-ancestor-extending — and the discriminator + archival mechanic that IEL doesn't have. KEL is the authenticity primitive that anchors everything else: IEL Icp anchors in a KEL ixn, SEL inception and lifecycle events also anchor in KELs.

New concepts to internalize after IEL: forward-key commitments (`rotation_hash`, `recovery_hash`), the recovery-revealing event class, dual-sig authorization, the `Rec` discriminator's two shapes, proactive-ROR bound.

Read in order: [events.md](primitives/kel/events.md) → [event-log.md](primitives/kel/event-log.md) → [merge.md](primitives/kel/merge.md) → [verification.md](primitives/kel/verification.md) → [reconciliation.md](primitives/kel/reconciliation.md).

### SEL — third

The most complex primitive. SEL composes KEL anchoring and IEL governance to authorize content-bearing events. Adds a `content` field (the per-event payload — KELS application data), an `identity_event` field (the SAID of the IEL event whose policy authorizes this SEL event), and the SEL-specific per-event parent-monotonic ratchet on `identity_event`. Like KEL, SEL has a discriminator-based recovery primitive (`Rpr`, analogous to KEL's `Rec`), but it also has the upgrade rule for non-archiving privileged events that IEL doesn't (because every IEL event is privileged).

New concepts to internalize after KEL + IEL: identity-rooting (every SEL binds to an IEL prefix at inception), the per-event parent-monotonic ratchet, `Rpr` as SEL's discriminator-based recovery, the upgrade rule (`Upd`-`Upd` divergent set + gossip-delivered privileged event), cross-chain binding stability under IEL governance evolution.

Read in order: [events.md](primitives/sel/events.md) → [event-log.md](primitives/sel/event-log.md) → [merge.md](primitives/sel/merge.md) → [verification.md](primitives/sel/verification.md) → [reconciliation.md](primitives/sel/reconciliation.md).

## Features

Applications built on the primitives. Read once you've internalized the primitive layer.

- [policy.md](features/policy.md) — the kels-policy framework (composable trust policies, DSL, poisoning/immunity, integration with credentials).
- [creds.md](features/creds.md) — credentials (issuance, presentation, edges, claims, expiration).
- [exchange.md](features/exchange.md) — encrypted message exchange (ESSR envelopes, KEM, AES-GCM).
- [mail.md](features/mail.md) — mail service.

## Infrastructure

Runtime services and system components that store/serve/replicate the primitives. Read when reasoning about deployment, gossip mechanics, or the federation layer.

- [sadstore.md](infrastructure/sadstore.md) — SADStore service architecture.
- [streaming.md](infrastructure/streaming.md) — streaming verification architecture.
- [federation.md](infrastructure/federation.md) — multi-registry federation.
- [federation-state-machine.md](infrastructure/federation-state-machine.md) — Raft state machine for federation peer management.
- [gossip.md](infrastructure/gossip.md) — gossip protocol mechanics, anti-entropy.
- [registry.md](infrastructure/registry.md) — node registry and bootstrap sync.
- [secure-registration.md](infrastructure/secure-registration.md) — peer authorization.
- [rejection-threshold.md](infrastructure/rejection-threshold.md) — federation peer-proposal rejection rule.

## Operations

How to run the system. Lives in [`docs/operations/`](../operations/) — deployment, scale, retirement, backup. Read when operating a node or planning a federation deployment.

## Analysis

Threat models and attack surface. Lives in [`docs/analysis/`](../analysis/) — `protocol-attack-surface.md` (cryptographic and protocol-level threats), `node-attack-surface.md` (node-level deployment threats), `registry-attack-surface.md` (registry-level threats). Read when reasoning about specific threats or evaluating mitigations.

## Reference

API and external comparisons. Lives in [`docs/reference/`](../reference/) — `endpoints.md` (API surface), `keri-comparison.md` (KEL/IEL/SEL positioning relative to KERI). Read when integrating against the API or comparing to related work.
