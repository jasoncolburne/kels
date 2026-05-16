# Reading Guide

A table of contents for `docs/design/` organized by the order knowledge builds. Primitives are the load-bearing layer; everything else is downstream — features built on the primitives, operations built on the features.

## Prerequisite

If you haven't read [../../AGENTS.md §System Thesis](../../AGENTS.md#system-thesis), start there. The Thesis is the high-level framing that everything below assumes (KEL/IEL/SEL roles, the evaluation lens for design decisions, compromise-is-permanent doctrine, federation convergence as a foundational property).

## Foundation

[protocol-doctrine.md](protocol-doctrine.md) — three parts: Security Invariants, Cross-Cutting Doctrines, Verification Mechanics. Full TOC at the top of the doc.

Read in full before the primitives — every per-primitive doc cross-references this doc heavily, and reasoning about the primitives without the doctrine forces you to reconstruct invariants from worked examples rather than pick them up directly.

## Primitives

The substantive part of the design. Three primitives (KEL, IEL, SEL) implement the doctrine in different shapes. Each primitive has five docs in the same structural roles, and reading them in the same internal order makes the parallel structure visible.

### Internal order within each primitive

1. **events.md** — per-kind reference. What event kinds exist, their field rules, the satisfaction model (what authorizes each kind). Most approachable entry point.
2. **event-log.md** — chain lifecycle. States (active / divergent / contested / decommissioned), divergence semantics, terminal events, evaluation/recovery seal, trust caveats.
3. **merge.md** — submit handler routing. What the server does at the submit boundary; the kind-discriminator routing matrix.
4. **verification.md** — verifier walk algorithm. The single-pass walk that produces the Verification token; chain-validity invariants.
5. **reconciliation.md** — multi-node correctness matrix. The load-bearing proof that every state × submission × gossip combination terminates correctly and all nodes converge on the same effective SAID. This is the per-primitive proof of [protocol-doctrine.md §Federation Convergence](protocol-doctrine.md#federation-convergence).

### IEL — start here

The simplest primitive. Every IEL event is governance-authorized (no auth-vs-governance asymmetry), there is no recovery primitive (Rpr is absent — divergence is immediately terminal), no content payload (the chain's data is its tracked policy state), and a small kind set (`Icp`, `Evl`, `Sea`, `Cnt`, `Dec`). The cleanest place to internalize the core protocol concepts: cryptographically-linked event chains, divergence semantics, terminal events, evaluation seals, authorization via anchored policy.

Read in order: [events.md](primitives/iel/events.md) → [event-log.md](primitives/iel/event-log.md) → [merge.md](primitives/iel/merge.md) → [verification.md](primitives/iel/verification.md) → [reconciliation.md](primitives/iel/reconciliation.md).

**Note on forward references.** IEL is the authorization root for SEL, so IEL docs forward-reference SEL concepts (`iel_event`, SEL `Upd` / `Est` / `Sea` / `Rpr` / `Cnt` / `Dec` binding rules). On first read, treat these as "the binding exists; the SEL-side docs cover the consumer rules" — you'll fill them in once you reach SEL.

### KEL — second

KEL adds device-level cryptography to the chain model you learned from IEL. A KEL carries three key roles — a signing key, a rotation key (pre-committed via `rotation_hash`), and a recovery key (revealed only by recovery-revealing events: `Rec`, `Ror`, `Dec`, `Cnt`). Recovery-revealing events require a dual signature. KEL is the authenticity primitive that anchors everything else: IEL events anchor in KELs at tier 2 (`Rot`, governance acts) or tier 3 (`Ror`, terminals) per [protocol-doctrine.md §Anchor Tier Elevation](protocol-doctrine.md#anchor-tier-elevation); SEL post-inception events anchor at the same tiers (SEL `Icp` itself is permissionless and unanchored).

New concepts you'll meet:

- Forward-key commitments — `rotation_hash` and `recovery_hash` pre-commit the next pair of keys; the revealing event must produce a matching preimage.
- The recovery-revealing event class — `Rec`/`Ror`/`Cnt`/`Dec` each reveal the recovery key; all four are dual-signed.
- Within that class, `Rec` is the discriminator-based recovery primitive (the only kind that archives), with two parent shapes — branch-tip-extending and divergence-ancestor-extending. `Ror`/`Cnt`/`Dec` are recovery-revealing but non-archiving.
- Proactive-ROR bound — a protocol-level cap on how many non-revealing events can sit between recovery-revealing events.
- The upgrade rule — a non-privileged divergent set plus a gossip-delivered non-archiving privileged event upgrades the chain to contested. Applies to KEL and SEL; IEL is exempt because every IEL event is privileged.

Read in order: [events.md](primitives/kel/events.md) → [event-log.md](primitives/kel/event-log.md) → [merge.md](primitives/kel/merge.md) → [verification.md](primitives/kel/verification.md) → [reconciliation.md](primitives/kel/reconciliation.md). Supplemental: [recovery-workflow.md](primitives/kel/recovery-workflow.md) for the operational walkthrough of `Rec` ceremonies.

### SEL — third

The most complex primitive. SEL composes KEL anchoring and IEL governance to authorize content-bearing events. Kind set: `Icp`, `Est`, `Upd`, `Sea`, `Rpr`, `Dec`, `Cnt` (sort-priority order). Unlike IEL, SEL events carry application content via a `content` field; unlike KEL, SEL events bind to a specific IEL event via an `iel_event` field (the SAID of the IEL event whose policy authorizes the SEL event). Like KEL, SEL has a discriminator-based recovery primitive (`Rpr`, analogous to KEL's `Rec`) and inherits the upgrade rule.

New concepts you'll meet:

- Identity-rooting — every SEL binds at inception to an IEL prefix and resolves per-event authorization through the IEL.
- Per-event parent-monotonic ratchet on `iel_event` — each SEL event's binding must be at-or-after its parent's (per branch), preventing same-branch regression to stale IEL state.
- `Rpr` — SEL's discriminator-based recovery, analogous in shape to KEL's `Rec` but governance-authorized (a higher-bar resolution of auth-policy-level divergence).
- Cross-chain binding stability — how SEL's `iel_event` resolution stays deterministic across IEL governance evolution.

Read in order: [events.md](primitives/sel/events.md) → [event-log.md](primitives/sel/event-log.md) → [merge.md](primitives/sel/merge.md) → [verification.md](primitives/sel/verification.md) → [reconciliation.md](primitives/sel/reconciliation.md). Supplemental: [repair-workflow.md](primitives/sel/repair-workflow.md) for the operational walkthrough of `Rpr` ceremonies.

## Features

Applications built on the primitives. Read once you've internalized the primitive layer.

- [policy.md](features/policy.md) — the kels-policy framework (composable trust policies, DSL, poisoning/immunity, integration with credentials).
- [creds.md](features/creds.md) — credentials (issuance, presentation, edges, claims, expiration).
- [exchange.md](features/exchange.md) — encrypted message exchange (ESSR envelopes, KEM, AES-GCM).
- [mail.md](features/mail.md) — mail service.

## Infrastructure

Runtime services and system components that store/serve/replicate the primitives. Read when reasoning about deployment, gossip mechanics, or the federation layer.

- [sadstore.md](infrastructure/sadstore.md) — SADStore service architecture.
- [federation.md](infrastructure/federation.md) — federation-as-identity model: federation IEL, per-peer address SELs, membership evolution, bootstrap ceremony, recovery.
- [discovery.md](infrastructure/discovery.md) — node-side peer discovery (federation IEL `auth_policy` enumeration + per-peer address SEL walks).
- [peer-identity.md](infrastructure/peer-identity.md) — HSM-backed gossip identity ceremony + handshake authorization against the federation IEL.
- [gossip.md](infrastructure/gossip.md) — gossip protocol mechanics, anti-entropy, transport layer.

## Operations

How to run the system. Lives in [`docs/operations/`](../operations/) — deployment, scale, retirement, backup, multi-party-governance synchronization. Read when operating a node or planning a federation deployment.

## Development

How to build applications on top of the protocol. Lives in [`docs/development/`](../development/) — enrollment patterns and other application-developer guidance. Read when integrating against the primitives.

## Analysis

Threat models and attack surface. Lives in [`docs/analysis/`](../analysis/) — `protocol-attack-surface.md` (cryptographic and protocol-level threats), `node-attack-surface.md` (node-level deployment threats), `registry-attack-surface.md` (registry-level threats). Read when reasoning about specific threats or evaluating mitigations.

## Reference

API and external comparisons. Lives in [`docs/reference/`](../reference/) — `endpoints.md` (API surface), `keri-comparison.md` (KEL/IEL/SEL positioning relative to KERI). Read when integrating against the API or comparing to related work.
