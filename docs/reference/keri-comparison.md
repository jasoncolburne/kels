# KERI vs KELS: Architecture and Security Comparison

This document compares KERI (Key Event Receipt Infrastructure) and KELS (Key Event Log System) across their security properties, architectural decisions, and suitability for various Decentralized Verifiable Trust Infrastructure (DVTI) scenarios — keys, identity, and content. Analysis reflects security best practices as of 2026, including post-quantum readiness, zero-trust architecture, and supply chain integrity considerations.

## Scope

KERI is a DKMI (Decentralized Key Management Infrastructure). KELS started as one and grew into a **DVTI (Decentralized Verifiable Trust Infrastructure)** — keys, identity, and content all live as self-addressed event chains under a unified verification model. Where KERI stops at the Key Event Log, KELS layers:

- **KEL** — the DKMI primitive. Direct KERI analogue; the focus of most of this document.
- **IEL** (Identity Event Log) — aggregates one or more KELs into an identity via `authPolicy` and `governancePolicy`. No KERI analogue (KERI overloads the KEL with identity semantics; KELS separates them). User identities, organizational identities, and the federation itself are all IELs.
- **SEL** (SAD Event Log) — a general append-only verifiable event log for arbitrary Self-Addressing Data, governed by a policy DSL. No KERI analogue. Identity-rooted content chains: exchange-key chains, custody envelopes, mail metadata, per-peer address publications, credential-anchor chains.
- **Policy DSL** — `endorse`, `threshold`, `weighted`, `delegate`, nested `policy` references, with soft/hard/immune poisoning. Governance composes *across* independent identities rather than being embedded as a multisig threshold *within* one identifier.
- **Credentials, exchange, mail, federation** — layered consumers of the above, not built-in DKMI features.

The sharpest statement of the split (expanded in §8): KERI couples governance to identity — the identifier *is* a 2-of-3 multisig. KELS decouples them — three independent identities collectively endorse something per a policy. That decoupling is what makes KELS a DVTI substrate rather than just another DKMI.

Direct comparison in this document focuses on the DKMI layer because that is where an apples-to-apples comparison is meaningful. Where KELS extends beyond KERI's scope (SELs, policy, credentials, exchange, mail, federation), sections note this explicitly.

## Protocol Overview

### KERI

KERI is a decentralized identity protocol built around Key Event Logs (KELs) — append-only chains of signed key events. Its core innovation is **pre-rotation**: each establishment event commits to the hash of the next public key, preventing an adversary who compromises the current signing key from taking permanent control. KERI's prefix equals the inception event's SAID (Self-Addressing IDentifier).

KERI defines a rich taxonomy of infrastructure roles, each with distinct trust properties:

- **Controller** — the entity that controls the identifier and signs key events.
- **Witnesses** — designated services that provide signed receipts for events, establishing a consistency threshold (e.g., 2-of-3). Controllers select their own witness pool.
- **Watchers** — monitor witnesses for duplicity (conflicting events at the same sequence number). They compare KELs across witnesses and flag inconsistencies.
- **Jurors** — evaluate duplicity evidence gathered by watchers and render judgments about identifier trustworthiness.
- **Judges** — make final trust decisions based on juror evaluations, applying policy to determine whether an identifier should still be trusted.
- **Registrars** — manage credential registries that use TELs (Transaction Event Logs) to track credential issuance and revocation state.
- **Validators** — any party that verifies a KEL's cryptographic integrity.

This layered participant model creates a social trust infrastructure where duplicity detection, evaluation, and resolution are distributed across specialized roles. Each role can be operated by different parties, providing separation of concerns and defense in depth through organizational diversity.

Key components: KELs, witnesses, watchers, jurors, judges, OOBIs (Out-of-Band Introductions), delegated identifiers, CESR encoding, TELs (Transaction Event Logs), and the ACDC (Authentic Chained Data Container) credential framework.

### KELS

KELS is a federated DVTI (Decentralized Verifiable Trust Infrastructure) that shares KERI's foundational DKMI concepts (KELs, pre-rotation, SAIDs, CESR) but diverges significantly in how it handles key compromise, replication, and trust — and extends past the keys layer to identity (IEL) and content (SEL). KELS:

- **Stores divergent events directly in the KEL** rather than treating duplicity as an external detection problem.
- Introduces explicit recovery (`rec`) event type with formal semantics; cross-node federation-level non-convergence (priv-vs-priv races) is surfaced structurally via the contested-prefix table at the infrastructure layer rather than via a dedicated terminate-with-prejudice event. The structural property is the seal-cap + priv-divergence-rejected-at-merge rules that keep divergent sets free of privileged events and route federation disagreement to the infrastructure layer.
- Uses a custom gossip protocol for replication (HyParView + PlumTree over ML-KEM-768/1024 + ML-DSA-65/87 + AES-GCM-256) rather than witness receipts.
- Constructs federation as an identity — a shared **federation IEL** whose current `authPolicy` declares the set of authorized peers and whose `governancePolicy` constrains how membership evolves.
- Backs peer gossip-service identities with HSMs.

KELS derives the prefix differently from the SAID (blanking both `said` and `prefix` fields before hashing, and computing each in sequence — prefix first — rather than in the same operation), producing two distinct content-derived identifiers from the same inception event. There is no way to reverse an event's SAID to determine which identity created it — you need the full event. This protects against some identification/correlation attacks.

Beyond the DKMI layer, KELS adds:

- **SELs** (SAD Event Logs) — a generic append-only verifiable event log for arbitrary Self-Addressing Data, with per-event authorization resolved through the bound IEL. Concrete chains include ML-KEM encapsulation-key publication, per-peer gossip-service address publication, custody envelopes, and mail metadata.
- **A composable policy DSL** with the following constructs:
  - `endorse(kel_prefix)` — a specific KEL must anchor the SAID.
  - `identity(iel_prefix)` — resolves through an IEL's current `authPolicy` at evaluation time.
  - `delegate(DELEGATOR)` — any KEL the delegator has dip-delegated and anchored qualifies.
  - `threshold(k, [...])` / `weighted(k, [... : weight])` — composition aggregators.
  - `policy(SAID)` — nest another policy by SAID.
  - Soft/hard/immune poisoning for withdrawing endorsements.

KERI has no analogue at this layer — ACDC credentials and TEL registries are credential-specific data structures rather than a general event-log substrate, and tholder thresholds live within a single identifier's keys rather than composing across identities.

---

## Security Property Comparison

### 1. Key Compromise Recovery

| Property | KERI | KELS |
|----------|------|------|
| Pre-rotation commitment | Yes (hash of next public key) | Yes (Blake3 of next public key) |
| Recovery from signing key compromise | Rotation event | `rec` event (dual-signed: rotation + recovery key) |
| Recovery from pre-committed next-key compromise | Rotation by controller (race condition) | `rec` event (requires recovery key — no race) |
| Total compromise (rotation + recovery) | No explicit recovery key | Federation-level non-convergence — concurrent priv-vs-priv submissions to different nodes produce cross-node disagreement surfaced via the contested-prefix table; per-node priv events whose landing would create or join a divergent set are rejected at the merge layer per [§Privileged Divergence is Terminal](../design/protocol-doctrine.md#privileged-divergence-is-terminal). Operator response is reincept under a new prefix when reconciliation fails. |
| Recovery key hierarchy | Composable (tholder), no explicit tiering | Three-tier (signing, rotation, recovery) |
| Key compromise visibility | External: watchers detect duplicity | Internal: divergence stored in KEL, propagated network-wide |

**Analysis:** KELS's three-tier key hierarchy provides a stronger recovery posture. In KERI, if an adversary compromises a pre-rotated next key, there is a race condition — whoever rotates first wins. KELS eliminates this race by requiring dual signatures (rotation + recovery) for recovery events, meaning the adversary cannot recover with only the rotation key. The structural total-compromise outcome is a significant advantage: rather than leaving a totally compromised identifier in an ambiguous state, KELS's privileged-divergence-is-terminal rule produces a deterministic, auditable freeze whenever a privileged event lands in a divergent set — no dedicated terminate-with-prejudice event needed.

That hierarchy is one half of KELS's key-compromise story. The other half is IEL composition: where KERI composes multiple keys within a single KEL via tholder, KELS composes multiple single-key KELs at the IEL layer (`authPolicy` referencing independent KEL prefixes via `identity(...)`). Compromise of any one member KEL is resolved on that KEL's own recovery primitive, then `Evl`'d out of the IEL's `authPolicy` — the identity continues without disrupting the other members.

**2026 consideration:** With quantum computing advances making asymmetric key compromise more plausible (even if not yet practical at scale), having a formal total-compromise response — federation-level non-convergence surfaced via the contested-prefix table, with merge-layer rejection of priv events that would create or join divergent sets — is increasingly valuable. Both protocols' pre-rotation commitments provide some post-quantum protection since the hash commitment cannot be broken even by a quantum adversary — but KELS's recovery hierarchy provides defense in depth beyond what pre-rotation alone offers.

### 2. Decoupling Device-Level Cryptography from Identity

| Property | KERI | KELS |
|----------|------|------|
| Chain primitives | One (KEL) | Three (KEL, IEL, SEL) |
| What the identifier is | A KEL prefix | An IEL prefix; an IEL aggregates one or more KELs via `authPolicy` |
| Device key role | A device's key lives in the KEL that *is* the identifier | A device's key lives in its own KEL; the IEL references the KEL through policy |
| Multi-device identity | Multi-sig within a single KEL (Tholder thresholds over keys) | `authPolicy` over multiple independent KELs, each with its own key lifecycle |
| Adding a device | Rotation event evolving the multi-sig set within the identifier's KEL | Add a KEL (incept independently) and evolve the IEL's `authPolicy` to include it; identifier prefix unchanged |
| Replacing a compromised device | Rotation that excludes the compromised key from the multi-sig set | `Evl` excluding that KEL's `identity(...)` from `authPolicy`; the rest of the identity unaffected |

**Analysis:** KERI has one chain primitive, the KEL, and overloads it with both device-cryptographic-state semantics and identity semantics — a KEL prefix *is* an identifier. Every device-level change (key rotation, multi-sig change, custody migration) is also an identity-level event, because the same chain carries both.

KELS separates the two structurally. A KEL is a device-level cryptographic chain: signing key, rotation commitment, recovery key, dual-signed recovery. An IEL is an identity-level aggregation: it declares an `authPolicy` (who currently speaks for this identity) and a `governancePolicy` (who can change that), with both policies referencing KEL prefixes through the policy DSL. Identity is therefore composable from independent KELs:

- A single-device identity is an IEL with `authPolicy = endorse(kel_prefix)` over one KEL. Same effective semantics as a KERI identifier, but the device-key chain (KEL) is structurally distinct from the identifier (IEL prefix).
- A multi-device identity is an IEL with `authPolicy = threshold(M, [endorse(kel_a), endorse(kel_b), ...])` over independent KELs. Each device has its own key lifecycle and its own recovery posture; compromise of one device is resolved on that device's KEL, then `Evl`'d out of the identity's `authPolicy` without touching the other devices.
- An organizational identity is an IEL whose `authPolicy` references the IELs of the people/services in the org. Composition crosses identity boundaries naturally — the same policy DSL applies at every level.

The compositional surface is wider:

- **SEL** is a third primitive — an append-only linear chain of SADs (Self-Addressed Data) bound at inception to a specific IEL via `identity` and resolving authorization per-event through that IEL's evolving `authPolicy`. SELs carry content (credentials are not SELs, but exchange-key publications, custody envelopes, mail metadata, per-peer address publications, and federation membership are all SELs or SEL-shaped).
- **Cred** is a credential-specific SAD format, optionally chainable as a graph via edges (similar shape to ACDC).
- **Policy DSL** is the composition surface that ties the identity layers together. A policy expression references KEL prefixes (via `endorse`/`delegate`), IEL prefixes (via `identity`), or other policies by SAID (via `policy(...)`), composed under `threshold`/`weighted` aggregators.

The same primitives carry every content-bearing chain and every authorization decision in the system. Adding a new domain (e.g., custody envelopes, mail metadata) doesn't introduce a new event log type — it's a new SEL topic or SAD shape over the existing primitives.

KERI's contrast: the KEL is the only chain primitive in the core protocol; TELs (Transaction Event Logs) are a credential-specific extension; ACDCs (Authentic Chained Data Containers) are credential-specific data containers. Each is purpose-built for credentials. Reusing TEL infrastructure for non-credential content isn't part of the protocol; KERI applications that need non-credential chains tend to layer them outside the framework.

**2026 consideration:** As identity systems span devices, services, organizations, and credential domains, the ability to compose authorization across these layers using the same primitives — not separate frameworks for each — is the difference between a coherent system and a stack of integrations. The KEL/IEL/SEL split also isolates blast radius: a compromised device key is resolved on its own KEL; the IEL `Evl`'s the KEL out of `authPolicy`; downstream SELs and credentials that bound to the identity at a tier-2 anchor remain valid by the immunity rule. KERI's monolithic-KEL model couples these together — every device-level event is also an identity-level event.

### 3. Divergence and Duplicity Handling

| Property | KERI | KELS |
|----------|------|------|
| Conflicting events | Rejected by witnesses; detected by watchers | Stored in KEL; KEL frozen until resolved |
| Divergence visibility | Requires active watcher monitoring | Inherent in data structure; propagated via gossip |
| Resolution mechanism | Social/out-of-band (controller accountability) | Cryptographic (`rec` to recover; privileged-divergence-is-terminal freezes the chain when any privileged event lands in a divergent set) |
| Forensic record | Distributed across watchers | Preserved in KEL (per-node first-receive retained on priv-vs-priv races; cross-node disagreement surfaced via the contested-prefix table) |
| Adversary event archival | Not formalized | `rec` archives adversary events on divergent KEL; federation-disputed prefixes surface via the contested-prefix table at the infrastructure layer |

**Analysis:** This is the most fundamental architectural difference, and it's narrower than "external vs. internal" — it's **detection-only vs. detection-plus-resolution**.

KERI treats duplicity as a signal of misbehavior to be detected externally, but provides no protocol-defined path to *continue* from a divergent state. Once a watcher flags duplicity, the controller's remaining options are abandoning the identifier (re-incept under a new prefix and propagate the new prefix to every consumer — a truck-roll across every system that pinned the old prefix) or accepting human-mediated arbitration. The social trust layer carries the resolution problem, not the protocol.

KELS treats divergence as a protocol state with defined transitions. `rec` (KEL recovery) and `Rpr` (SEL repair) resolve divergence and continue the chain; privileged-divergence-is-terminal (any privileged event landing in a divergent set) terminates the chain with a deterministic, federation-wide effective SAID. Both paths are protocol-defined and machine-executable. KELS also supports the external auditing path KERI provides — divergence is visible in the data structure and propagated via gossip, so external parties can monitor for it and apply their own social or policy decisions. KELS offers detection *and* resolution; KERI offers detection alone.

The asymmetry compounds in automated systems. Reputation-based trust decisions assume a human party whose reputation is at stake and a counterparty willing to accept reputational evidence; in machine-to-machine contexts, neither holds. KELS's protocol-defined resolution maps directly onto incident-response automation; KERI's social fallback does not.

**2026 consideration:** Zero-trust architectures demand automated, cryptographically-verifiable trust decisions. Detection-only systems force humans into the loop for every divergence event; protocol-defined resolution is what makes machine-autonomous incident response possible.

### 4. Replication and Availability

| Property | KERI | KELS |
|----------|------|------|
| Replication model | Designated witness pools + receipts | Gossip (HyParView + PlumTree) + HTTP fetch |
| Consistency model | Receipt threshold (e.g., 2-of-3 witnesses) | Eventual consistency via gossip + anti-entropy |
| Availability guarantee | Witness liveness required | Any gossip peer can serve; the federation IEL declares which peers are authorized |
| Transport security | Varies by implementation | ML-KEM-768/1024 + ML-DSA-65/87 + AES-GCM-256 (forward secrecy, mutual auth, PQ-secure) |
| Discovery | OOBIs (Out-of-Band Introductions) | Federation IEL `authPolicy` enumeration + per-peer address SEL walks |
| Infrastructure responsibility | Controller selects and manages witnesses | Federation operators jointly operate the shared peer mesh |

**Analysis:** KERI's witness model is the fully-specified replication path; it provides stronger consistency guarantees at the cost of availability — if witnesses are offline, events cannot be receipted. Where KERI gestures at gossip as an alternative replication mechanism, the specification doesn't cover the hard problems gossip raises: send-side ordering across divergent chains, anti-entropy through terminal states, effective-SAID convergence on divergent chains, gossip-driven divergence detection, federation-layer dispute surfacing for cross-node priv-vs-priv races. Gossip in this domain isn't a hand-wave; it's a real engineering problem with subtle correctness traps. KELS has specified and implemented these mechanics (HyParView + PlumTree over a PQ transport, with primitive-specific reconciliation matrices proving convergence under all state-by-submission-by-gossip combinations) — see [../design/protocol-doctrine.md §Federation Convergence](../design/protocol-doctrine.md#federation-convergence) and the per-primitive reconciliation docs. KELS's gossip model prioritizes availability and partition tolerance, accepting eventual consistency, with anti-entropy repair (every 10s by default) bounding staleness.

A critical operational difference is *who bears the infrastructure burden*. KERI presumes each controller selects and manages a witness pool. In roughly a decade of KERI, very few real witness pools have been stood up; the protocol's social trust roles (watchers, jurors, judges) lack standalone deployable implementations. In practice this pushes adopters toward cloud-agent hosting (e.g., KERIA), which re-introduces the centralized trust dependency that KERI's architecture was designed to avoid. KELS inverts this: federation is professional operator infrastructure, jointly run by a small set of operators, and end users carry no infrastructure burden — a consumer's phone talks to a KELS node, gossip handles replication, no per-identity infrastructure is required.

KELS's transport security is notably stronger: the ML-KEM-768/1024 key exchange with ML-DSA-65/87 mutual authentication provides forward secrecy, mutual authentication tied to gossip identities, and post-quantum security. KERI's transport security is implementation-dependent.

**2026 consideration:** The shift toward mesh and edge computing favors gossip-based replication, but specifying gossip correctness in the presence of divergence is hard, and KERI hasn't done that work. KELS's gossip mechanics are specified and implemented, with the convergence proof distributed across the reconciliation docs. End-user infrastructure burden is a separate but related problem: expecting controllers to manage distributed witness pools is a non-starter for mass-market digital wallets, which is why the cloud-agent pattern dominates KERI deployments in practice.

### 5. Trust Model and Trust Anchoring

| Property | KERI | KELS |
|----------|------|------|
| Root of trust | Self-certifying identifiers (inception event) | Self-certifying identifiers (inception event) for participants; federation IEL prefix (compile-time default, runtime-overridable for recovery) for infrastructure |
| Delegation trust | Verified in protocol (delegated rotation) | Deferred to consumers (KELS accepts any valid `dip`) |
| Ambient verifiability | Yes (any party can verify any KEL) | Yes (any party can verify any KEL) |
| Infrastructure trust | Witness selection by controller | Federation IEL `governancePolicy` controls who may evolve membership (typically a threshold over current member identities) |

**Analysis:** Both protocols share the same root of trust for identities — any identifier is self-certifying from its inception event alone. The difference is in infrastructure trust: KERI relies on controller-selected witnesses, while KELS anchors infrastructure trust in a single shared **federation IEL**. The federation IEL is itself a self-certifying identity (verified from its inception), and its current `authPolicy` is the canonical record of which peers may participate in the gossip mesh. The trust assumption reduces to "I trust this federation IEL prefix and the chain it produced," which a verifier can check from the chain alone.

The federation's `governancePolicy` is typically a `threshold(M, [identity(...)])` over current member identities — a structural quorum requirement encoded directly in the policy DSL, evaluated by the standard policy evaluator. Membership evolution requires M valid endorsements on every `Evl` event, giving the same Sybil resistance and unilateral-change resistance that explicit voting protocols provide, expressed as plain chain operations.

**2026 consideration:** A single chain-rooted trust anchor — verified by the standard verifier and propagated via the standard gossip mesh — is auditable in the same way every other chain is: from the data, by anyone. The runtime-overridable federation IEL prefix gives operators a recovery path for federation-disputed federation IELs without a binary rebuild, balancing the auditability of a fixed compile-time default against operational reality.

### 6. Post-Quantum Readiness

| Property | KERI | KELS |
|----------|------|------|
| Pre-rotation hash commitment | SHA-256 or Blake3 (quantum-resistant) | Blake3-256 (quantum-resistant) |
| Signature algorithm | Configurable (Ed25519, secp256k1, etc.) | ML-DSA-65/87 (192/256-bit post-quantum, FIPS 204) for infrastructure; P-256/ML-DSA-65/ML-DSA-87 supported for mobile clients |
| Cryptographic agility | CESR code tables allow algorithm migration | CESR with Blake3; supports mixed algorithms (e.g., P-256 signing + ML-DSA-65 recovery) with algorithm upgrade via rotation |
| Forward secrecy | Implementation-dependent | ML-KEM-768/1024 ephemeral key exchange provides per-session forward secrecy |
| Key exchange | Implementation-dependent | ML-KEM-768/1024 (FIPS 203, post-quantum) |

**Analysis:** Both protocols benefit from pre-rotation's quantum resistance for commitment chains — even a quantum adversary cannot derive a next key from its hash digest. KELS now uses ML-DSA-65 or ML-DSA-87 (FIPS 204, 192/256-bit post-quantum security, configurable via `NEXT_SIGNING_ALGORITHM` / `NEXT_RECOVERY_ALGORITHM`) for all infrastructure identities (registries, gossip nodes), with ML-KEM-1024 (FIPS 203) for gossip transport key exchange. The core service accepts P-256, ML-DSA-65, and ML-DSA-87 KELs, supporting mobile clients during the transition period. The key provider supports mixed algorithms and algorithm upgrade via rotation, enabling gradual migration.

KERI has broader cryptographic agility via CESR code tables that can accommodate new algorithms. KELS targets specific post-quantum algorithms (ML-DSA-65/87, ML-KEM-768/1024) chosen for hardware availability — Apple's Secure Enclave supports ML-DSA-65 and ML-DSA-87 but not ML-DSA-44, making ML-DSA-65 the practical floor for consumer device compatibility.

**2026 consideration:** KELS has completed its post-quantum migration for infrastructure, using FIPS 203/204 algorithms with hardware support from Apple Secure Enclave (iOS 26+), Thales Luna HSMs, and AWS KMS. KERI's algorithm agility theoretically allows any PQ algorithm, but without a specific implementation, the migration timeline is less clear. For the hash-based pre-rotation commitment — the most critical quantum-resistance property — both protocols are already prepared.

### 7. Verification Model

| Property | KERI | KELS |
|----------|------|------|
| Verification approach | Full KEL replay from inception | Full KEL replay; streaming page-by-page |
| Verification proof | Implementation-dependent | Type-safe `KelVerification` token (private fields, no public constructor) |
| TOCTOU prevention | Implementation-dependent | Advisory locks held through verify+write; `PageLoader` trait |
| Anchor verification | Separate check | Inline during verification walk (single pass) |
| DB trust | Implementation-dependent | Explicit zero-trust: DB cannot be trusted, all data re-verified |

**Analysis:** KELS's verification model is notably rigorous. The `KelVerification` token enforced by the type system ensures that security decisions cannot be made on unverified data — this is a compile-time guarantee, not a convention. The advisory locking through verification+write eliminates TOCTOU vulnerabilities that plague many implementations.

KERI's specification defines verification semantics, but implementation rigor varies. KERIpy is well-tested but does not enforce verification-before-use at the type level.

**2026 consideration:** Type-safe security invariants (as in KELS) represent 2026 best practice for systems programming. Relying on developer discipline for verification ordering is increasingly recognized as insufficient for high-assurance systems.

### 8. Credential Ecosystem

| Property | KERI | KELS |
|----------|------|------|
| Credential framework | ACDC (Authentic Chained Data Containers) | kels-creds (see [design](../design/features/creds.md)) |
| Credential issuance/revocation | TELs (Transaction Event Logs) with registry | Policy-based: endorsers anchor credential SAID per policy; poisoning (anchor poison hash) replaces revocation |
| Credential exchange | IPEX (Issuance and Presentation Exchange) | kels-exchange: ESSR authenticated encryption + IPEX-style messaging + mail service |
| Compacted disclosure | Graduated disclosure (compact, partial, full) | Schema-aware path expression DSL (canonical, compacted, expanded) |
| Credential chaining | ACDC edge sections link credentials in directed graphs | SelfAddressed edges with graduated disclosure (schema, credential, policy) + compacted policy matching |
| Schema enforcement | JSON Schema + ACDC rules sections | SelfAddressed schema referenced by SAID; closed-schema validation with typed fields |

**Analysis:** The deeper contrast is **special-purpose vs. general primitives**. KERI's credential stack is a dedicated infrastructure: ACDC is a credential-specific data format, TEL is a credential-specific event log (management TEL per registry, VC TEL per credential). Neither is reused for non-credential domains. Applications that need non-credential chains tend to layer them outside the framework.

KELS provides general primitives that credentials are one consumer of:

- **SAD** (Self-Addressed Data) is the underlying content-addressed-data primitive. Credentials are SADs with credential-specific structure; the same SAD primitive underpins exchange-key publications, custody envelopes, mail metadata, federation per-peer addresses, and every other content-bearing object in the system.
- **SEL** is an append-only linear chain of SADs, bound at inception to an IEL via `identity` and resolving authorization per-event through that IEL's `authPolicy`. SELs carry ongoing-state-evolution domains.
- **Cred** is a SAD-shaped credential, optionally chainable as a graph via edges (similar in shape to ACDC's edge sections). Cred edges are graph-shaped; SEL chaining is linear append-only. The two primitives have different chaining shapes for different purposes.
- **Policy DSL** is the composition surface that ties these primitives together. A policy expression references KEL prefixes (via `endorse`/`delegate`), IEL prefixes (via `identity`), or other policies by SAID (via `policy(...)`), composed under `threshold`/`weighted` aggregators.

Composition between cred and SEL is open: a cred can embed a SEL prefix to anchor against ongoing chain state; a SEL `Upd` can reference a cred or its SAID.

The credential mechanics themselves remain expressive:

- **Endorsement** is anchor-driven. An endorser signs a KEL `Ixn` whose anchor is the credential's SAID; verification walks endorser KELs and evaluates the policy across the anchors found. No separate registry; credential state is derived from KEL anchors.
- **Poisoning** replaces revocation. An endorser (or authorized admin per a `poison` DSL expression) anchors a domain-separated Blake3 hash of the credential SAID to withdraw endorsement. Two mutually exclusive optional policy fields control behavior: `poison` (a DSL expression defining who can kill the credential) and `immune` (no poison checks). By default, any endorser can soft-poison (their endorsement is dropped from threshold counts).
- **Policies** express threshold ("2-of-3 must endorse"), weighted ("board members with weight ≥ 5"), delegation ("any service delegated by this HSM"), and nested composition via policy references.
- **Compacted disclosure** uses a schema-aware path expression DSL that maps naturally to FFI (`*const c_char`). Only fields the schema marks as `compactable: true` are compacted/expanded, preventing blind expansion of SAID-like strings in non-compactable fields. Edge types are themselves SAD and compactable, enabling anti-correlation properties similar to ACDC's partial disclosure — a holder can prove an edge exists without revealing the referenced credential's policy or SAID.
- **Fleet scaling through `delegate(DELEGATOR)`** — the leaf names only the long-lived delegator; the verifier discovers any KEL the delegator has dip-delegated and anchored at evaluation time. New worker keys come online and old keys rotate out without policy edits, because the policy never named a specific delegate to begin with.

**Credential state is derived, not stored.** ACDC credentials are immutable data objects whose issuance/revocation state lives in a TEL. KELS credentials are stateless computational objects verified against KEL anchors via policy evaluation across multiple endorser KELs. This avoids the TEL infrastructure but means credential state is computed at verification time, not directly queryable. In a zero-trust architecture, the anchor walk on use is the right thing to do anyway.

**kels-exchange completes the stack** with three components, shipped with the deployment: (1) **ESSR authenticated encryption** (Encrypt-Sender-Sign-Receiver) providing four unforgeability properties (TUF-PTXT, TUF-CTXT, RUF-PTXT, RUF-CTXT) via ML-KEM key encapsulation + AES-GCM-256 + ML-DSA signatures, (2) **IPEX-style credential exchange messaging** (Apply/Offer/Agree/Grant/Admit/Reject) with chained, self-addressed exchange messages forming cryptographic threads, and (3) a **mail service** for encrypted message delivery with rate limiting, storage caps, blob integrity verification, and gossip-based metadata replication. The mail service is a peer of the kels and sadstore services, not a separate integration stitched together at deployment time.

**2026 consideration:** Verifiable credential adoption is accelerating (eIDAS 2.0, mDL, OpenID4VC). KERI's integrated credential stack is more battle-tested for production deployments. The kels-creds + kels-policy + kels-exchange combination closes the feature gap with a simpler architecture — credentials are one consumer of the same primitives that carry every other content-bearing chain in the system — while preserving expressivity (composable multi-party trust policies, poisoning semantics, post-quantum authenticated encryption for exchange) and adding cross-domain composability that purpose-built credential frameworks don't offer.

### 9. Multi-Signature and Threshold Control

| Property | KERI | KELS |
|----------|------|------|
| Multi-sig signing | Native weighted thresholds (`"kt"`: `"1/2,1/2,1/2"`) | Single signing key per event |
| Multi-sig rotation | Threshold of next key digests (`"nt"`, `"n"`) | Single rotation hash commitment |
| Threshold structures | Fractionally weighted, nested groups | Threshold, weighted, nested groups, delegation via kels-policy DSL |
| Organizational key governance | Multiple keyholders with quorum requirements | Single keyholder per KEL; kels-policy for multi-party governance; federation IEL `governancePolicy` for infrastructure membership |
| Recovery signatures | Implementation-dependent | Dual signature (rotation key + recovery key) required |

**Analysis:** This section dives into the multi-sig mechanics; the underlying structural choice (single chain primitive vs. KEL/IEL/SEL split) is covered in [§2 Decoupling Device-Level Cryptography from Identity](#2-decoupling-device-level-cryptography-from-identity).

KERI's multi-sig support is deeply integrated via the `Tholder` (threshold holder). A KERI identifier can require, for example, 2-of-3 signatures from weighted keyholders for signing and a different 3-of-5 threshold for rotation. The `Tholder` accepts fractional weights on keys (e.g., `"1/2,1/2,1/2"` — three keys each with weight 1/2, requiring any two). This maps directly to organizational governance: a corporate identifier might require two officers to sign but three board members to rotate keys — but all keys live within the identifier's single KEL.

KELS takes a fundamentally different approach: each KEL has a single signing key, a single rotation commitment, and a single recovery key. Multi-party authorization lives at the IEL layer (via `authPolicy` over independent KELs) and at the credential layer (via kels-policy over independent endorser KELs). Core KEL verification stays single-key and simple; multi-party governance composes at a layer above through an expressive, composable policy DSL.

#### Tholder vs. Policy: Detailed Comparison

| | KERI Tholder | KELS Policy |
|---|---|---|
| Scope | Per-identifier (embedded in KEL) | Multi-scope: identity (`authPolicy` on IEL), governance (`governancePolicy` on IEL), credential (travels with credential), federation (membership on the federation IEL) |
| Expressiveness | Fractional weights on keys within one identifier | Nested DSL: threshold, weighted, delegation, policy references |
| Key compromise isolation | All keys share one identifier's fate | Each endorser has an independent recovery lifecycle and structurally-derived contestation outcome (privileged-divergence-is-terminal) |
| Governance changes | Rotation event (changes the identifier's keys) | Issue new credential with new policy |
| Delegation | Separate mechanism (delegated rotation requires delegator approval) | First-class `delegate(DELEGATOR)` node in the DSL (specific delegates discovered at evaluation time) |
| Revocation/withdrawal | TEL-based (separate append-only log) | Poisoning with soft/hard/immune modes and admin-controlled poison expressions |
| Verification cost | One KEL replay (efficient) | N KEL replays, one per endorser (more expensive) |
| Composability | Nested weighted groups within one identifier | Recursive across identities (policies reference other policies by SAID) |
| Fleet scaling | ACDC edge `"o"` operator `DI2I` (Delegated-Issuee-to-Issuee) reserved but not yet implemented (as of KERIpy `49fb6fb`) | Policy compaction: edges match on trust structure without pinning specific delegates |

**Composability and flexibility.** KERI's `Tholder` supports fractional weights on keys and nested threshold groups within a single identifier — it can express hierarchical governance structures like "2-of-(group-A-or-group-B)." However, all keys live within one identifier's KEL, and the `Tholder` cannot reference external identifiers, express delegation relationships, or compose across organizational boundaries.

KELS's policy DSL operates at a different level, composing across independent identities rather than keys within one identity:

- **Cross-identity nesting:** `threshold(2, [endorse(A), weighted(3, [endorse(B):2, endorse(C):1]), policy(SAID)])` — a threshold where A, B, C are independent KEL prefixes (each with their own key lifecycle) and one child is an entire sub-policy resolved by SAID.
- **Cross-identity composition:** Policies reference independent KEL prefixes, each with their own key lifecycle and recovery procedures, and each subject to the same structural contestation outcome (privileged-divergence-is-terminal). A compromised endorser recovers independently without affecting others.
- **Delegation as a node type:** `delegate(HSM_PREFIX)` expresses "any service delegated by this HSM must endorse" as a first-class concept in the trust expression — not a separate mechanism layered on top. The specific delegate is discovered at evaluation time (the open form).
- **Policy references:** `policy(SAID)` enables reuse and composition of policies across credentials. An organization can define a "board approval" policy once and reference it from many credentials.
- **Policy compaction:** `delegate(HSM)` names only the delegator — edges match on trust *structure* (any service delegated by this HSM) without pinning specific delegates, enabling fleet scaling without edge updates.
- **Admin-controlled poisoning:** A separate DSL expression (`poison` field) governs who can kill the credential, independent of who endorses it. KERI has no equivalent — revocation is TEL-based and not expressible as a threshold policy.

As a concrete example, KERI cannot express "2-of-3 endorsers, where one endorser is any service delegated by this HSM, and revocation requires 2-of-2 admins" in a single identifier's threshold structure. KELS can express this in a single policy document:

```
expression: threshold(2, [endorse(A), delegate(HSM), endorse(C)])
poison:     threshold(2, [endorse(ADMIN_1), endorse(ADMIN_2)])
```

**The fundamental architectural difference:** KERI couples governance to identity — the identifier *is* a 2-of-3 multisig. KELS decouples them — three separate identities *collectively endorse* a credential per a policy. KERI's approach is more efficient (one KEL replay). KELS's approach gives each endorser independent key lifecycle — if one endorser's key is compromised, they recover independently via `rec` without affecting the other endorsers or the policy itself; full-tier compromise produces federation-level non-convergence (priv-vs-priv races between adversary and operator surfaced via the contested-prefix table) with reincept as recourse. In KERI, a compromised key in a multisig set requires a rotation of the entire identifier.

KELS's dual-signature requirement for recovery events (rotation key + recovery key) is a form of 2-of-2 multi-sig, but it serves a specific security purpose (proving possession of both key tiers) rather than general governance.

**2026 consideration:** As organizational key management matures, the ability to express governance policies directly in the identifier (KERI's approach) versus at a higher layer (KELS's kels-policy approach) becomes a meaningful architectural decision. KERI's approach integrates multi-sig into KEL verification — a single KEL replay checks all thresholds. KELS's approach requires verifying multiple KELs (one per endorser in the policy) but keeps core verification simple and makes governance independently evolvable. KELS's recursive policy composition and policy compaction have no KERI equivalent — they enable trust structures that span organizational boundaries and scale with fleet operations in ways that a single identifier's key threshold cannot.

### 10. Standards and Interoperability

| Property | KERI | KELS |
|----------|------|------|
| Standards track | IETF Internet-Drafts (CESR, KERI, ACDC) | Standards proposal on roadmap |
| DID method | `did:keri`, `did:webs` (W3C DID-compatible) | DID method specification on roadmap |
| Trust framework alignment | ToIP (Trust over IP) Technology Stack | Standalone |
| Credential format | ACDC (with JSON Schema) | kels-creds (SelfAddressed JSON with typed schema) |
| Wire format specification | CESR (formally specified, code tables) | CESR-based but with Blake3 (no formal spec) |
| Interop with existing PKI | Via DID methods and OOBI bridges | FFI bindings (C, Swift) for integration |

**Analysis:** KERI has invested heavily in standards positioning. The IETF Internet-Drafts for CESR, KERI, and ACDC provide formal specifications that enable independent implementations and regulatory reference. The `did:webs` method bridges KERI to the W3C DID ecosystem, enabling interop with existing SSI (Self-Sovereign Identity) tooling. ToIP alignment connects KERI to a broader governance framework used by governments and enterprises.

KELS has no standards track presence yet, but a standards proposal (IETF Internet-Draft or equivalent) and a DID method specification are both on the roadmap, planned after third-party audit and exhaustive proof of divergence reconciliation. Its wire format is JSON with CESR-encoded cryptographic material and Blake3 hashing. Integration happens through FFI bindings (C for general use, Swift for iOS/macOS) and an Android SDK (on roadmap) rather than through standardized protocols.

**2026 consideration:** Regulated industries increasingly require standards compliance for identity infrastructure. eIDAS 2.0, ISO 18013-5 (mDL), and national digital identity programs reference or require standards-based approaches. KERI's standards positioning is a practical prerequisite for these markets. KELS's planned standards effort would need to cover the core protocol, CESR extensions, and the credential framework to participate in standards-governed ecosystems.

### 11. Community and Ecosystem Maturity

| Property | KERI | KELS |
|----------|------|------|
| Primary steward | WebOfTrust (open community) | Single author |
| Implementations | Python (KERIpy), TypeScript (signify-ts), Rust (partial), Go (partial) | Rust (single implementation) |
| Development history | Public since ~2019, active since 2020 | Newer project |
| Community venues | IIW workshops, ToIP working groups, GitHub discussions | GitHub only |
| Production deployments | GLEIF vLEI (Global Legal Entity Identifier Foundation) | None publicly known |
| Formal security review | Academic papers, community review | Codebase-level (type system, tests) |

**Analysis:** KERI has a substantial head start in community building, multi-implementation diversity, and production validation. The GLEIF vLEI deployment (using KERI for Legal Entity Identifier verification) is a notable real-world reference. Multiple independent implementations provide cross-validation of the protocol specification.

KELS is a single-author, single-implementation project. This is not inherently a weakness for technical quality — many excellent security tools start this way — but it means the protocol has not been independently validated through reimplementation, and the bus factor is 1. The Rust type system and test suite provide strong internal correctness assurance, but external review and diverse implementation are important for protocol-level confidence.

**2026 consideration:** For risk-averse organizations evaluating DVTI infrastructure, community size, implementation diversity, and production references are often deciding factors regardless of technical merit. KERI's ecosystem maturity provides lower perceived risk. KELS's technical advantages (type-safe verification, deterministic recovery, gossip replication) may be more compelling but require more due diligence to adopt.

### 12. Privacy Properties

| Property | KERI | KELS |
|----------|------|------|
| Prefix derivation | Prefix = inception SAID (derived from inception content) | Prefix derived separately (both `said` and `prefix` blanked before hashing) |
| Identifier correlation | SAID reveals inception content hash; prefix = SAID | Prefix and SAID are different values; harder to correlate naked SAIDs to KEL owners |
| Compacted disclosure | ACDC graduated disclosure (compact → partial → full) | kels-creds path expression DSL (compact → compacted → full) |
| Unlinkable presentations | Possible via ACDC compact disclosure | Compactable edges hide referenced credentials and issuers |
| KEL privacy | KEL is public (ambient verifiability) | KEL is public (ambient verifiability) |
| Witness/node privacy | Witness addresses in KEL (`"b"` field) | Peer set declared by the federation IEL's `authPolicy`; addresses live in per-peer address SELs, not in any identity's KEL |

**Analysis:** Both protocols treat KELs as public, verifiable data — ambient verifiability is a core design principle of both. Neither provides KEL confidentiality.

KELS's prefix derivation offers a subtle privacy advantage: KERI computes a single hash (blanking both fields in one pass) and uses it as both prefix and SAID, so they are identical. KELS computes them sequentially — prefix first (both fields blanked), then SAID (only `said` blanked, prefix already populated) — producing two distinct values. A naked SAID seen in an anchor or external reference cannot be trivially mapped to a KEL prefix without additional context. In KERI, any reference to the inception SAID immediately identifies the KEL.

KERI's ACDC graduated disclosure allows credentials to be presented in compact form (just the SAID), partial form (selected fields), or full form. kels-creds provides comparable functionality via recursive compaction of SelfAddressed fields and a path expression DSL for compacted disclosure — fields are either expanded (visible) or compacted (replaced by their SAID). Both approaches enable privacy-preserving verification flows; ACDC is more mature while kels-creds is architecturally simpler. Note: this is compaction-based disclosure, not zero-knowledge selective disclosure — the holder chooses which fields to expand, but cannot make predicate proofs about compacted fields.

KERI exposes witness addresses in the KEL itself (`"b"` field), creating infrastructure metadata in the public record. KELS keeps peer-set management in a dedicated federation IEL and per-peer address SELs, separate from member identities and from individual KELs.

**2026 consideration:** Privacy regulations (GDPR, state privacy laws) increasingly constrain how identity systems handle personal data. Both KERI's ACDC graduated disclosure and kels-creds's path-based compacted disclosure support data minimization for privacy-compliant credential presentation. For pure key management (no credentials), KELS has a privacy advantage: systems that maintain logs of event SAIDs (e.g., audit trails, anchor records) cannot correlate those SAIDs back to a specific identity without the full event content. In KERI, where the prefix equals the inception SAID, any logged SAID from the inception event immediately identifies the KEL owner.

### 13. Delegation Model

| Property | KERI | KELS |
|----------|------|------|
| Delegation inception | Delegated inception (`dip`) requires delegator approval seal | Delegated inception (`dip`) accepted if structurally valid |
| Delegation rotation | Delegated rotation (`drt`) requires delegator approval | No delegated rotation event type |
| Delegation trust verification | In-protocol (delegator must anchor approval in their KEL) | Service-level: deferred to consumers. Credential-level: kels-policy `delegate()` DSL node verifies delegation trust chains |
| Delegation revocation | Delegator can refuse future rotations | Consumer-defined |
| Delegation depth | Multi-level (A delegates to B, B delegates to C) | Structurally possible; kels-policy `delegate(DELEGATOR)` verifies one level per node (specific delegate discovered at evaluation time); nested policies can compose multi-level chains |
| Credential-level delegation | ACDC edge operator `DI2I` reserved but not yet implemented (as of KERIpy `49fb6fb`); `I2I` and `NI2I` operators handle non-delegated issuee constraints | kels-policy `delegate()` node with policy compaction for fleet scaling |
| Cooperative delegation | Delegator and delegate coordinate via interaction events | No built-in coordination protocol |

**Analysis:** KERI's delegation model is deeply integrated into the protocol. When identifier B is delegated from identifier A, the delegator (A) must anchor an approval seal in their own KEL for every delegated establishment event (inception and rotation). This creates a cryptographically verifiable chain of authority: verifying B's KEL requires also verifying A's KEL and confirming the approval seals. The delegator retains ongoing control — they can refuse to approve future rotations, effectively revoking the delegation.

KELS takes a layered approach to delegation. At the service level, the `dip` (delegated inception) event includes a `delegatingPrefix` field, but the KELS service itself does not verify the delegation relationship — any structurally valid KEL starting with `dip` is accepted. This is a deliberate design choice: "Delegation trust is NOT verified by the KELS service. KELS accepts any valid KEL starting with `icp` or `dip`. Consumers verify delegation trust chains when needed."

However, at the credential level, kels-policy provides full delegation verification via the `delegate(DELEGATOR)` DSL node. The leaf names only the delegator; specific delegates are discovered at evaluation time. When a policy includes a `delegate` node, the evaluator walks the delegator's KEL for anchored dip-delegated prefixes and accepts any such KEL X that also anchors the credential SAID — three structural checks: X was incepted via `dip` with DELEGATOR as the delegating prefix, the delegator's KEL is cryptographically verified, and the delegator's KEL anchors X's prefix. Delegation trust is verified automatically during policy evaluation without consumers needing to implement it independently. The single-argument form is the fleet-scaling primitive: edges express "any delegate of this authority" by construction, no compaction step needed.

**2026 consideration:** Delegation is critical for organizational hierarchies (root CA → intermediate CA → end entity, analogous patterns). KERI's in-protocol delegation verification provides stronger guarantees out of the box for all KEL operations. KELS's layered approach defers delegation verification at the service level but provides it automatically at the credential level via kels-creds, covering the most common use case (verifying that a credential issuer is properly delegated) without requiring every consumer to implement delegation checking independently.

### 14. Offline and Airgapped Operation

| Property | KERI | KELS |
|----------|------|------|
| Offline key generation | Supported (inception can happen offline) | Supported (KeyEventBuilder works without network) |
| Airgapped signing | Controller signs locally, submits to witnesses later | Builder signs locally, submits to KELS service later |
| Cold storage rotation | Pre-rotate offline, submit rotation event when ready | Rotation hash commitment is offline; rotation event submission requires service |
| Disconnected verification | Full KEL replay possible with local copy | Full KEL replay possible with local copy or FileKelStore |
| Recovery from offline | Submit recovery event to any witness | Submit recovery event to any gossip node |
| Network partition tolerance | Witnesses must be reachable for receipt threshold | Gossip mesh self-heals; anti-entropy repairs after reconnection |

**Analysis:** Both protocols support offline key operations at the fundamental level — pre-rotation commitments are computed locally, and events can be signed without network access. The difference is in how offline-created events rejoin the network.

KERI requires the controller to submit events to enough witnesses to meet the receipt threshold. If witnesses are unreachable, the event exists but is not "receipted" and may not be trusted by verifiers who require receipt thresholds. This creates a liveness dependency on witness availability.

KELS requires submission to any reachable gossip node (or directly to the KELS service). Once submitted, the gossip mesh propagates the event network-wide — primarily via PlumTree announcements (`prefix:said` pairs pulled over HTTP), with dependency tracking for events whose parents haven't arrived yet, and anti-entropy as a fallback for any gaps the primary path missed. No further controller action required. The mesh is resilient to partial outages — events propagate through whatever paths are available, and anti-entropy repairs gaps after partitions heal.

For airgapped high-security deployments (e.g., root key ceremonies), both protocols support the pattern of: generate keys offline → create inception/rotation event offline → transport signed event to online system → submit. KELS's `KeyEventBuilder` and `FileKelStore` (NDJSON file-based storage) provide explicit tooling for this workflow. KERI's equivalent uses the `Hab` (Habitat) with local-only configuration.

**2026 consideration:** Airgapped key management is increasingly mandated for high-value identifiers (CA roots, national identity anchors, critical infrastructure). Both protocols support the core workflow. KELS's gossip-based propagation provides better resilience for environments with intermittent connectivity (field deployments, satellite-linked infrastructure, disaster recovery scenarios). KERI's witness model is simpler to reason about for compliance auditors who need to verify that an event was properly receipted.

### 15. Device and Platform Integration

| Property | KERI | KELS |
|----------|------|------|
| Native mobile client | None (signify-ts is browser-based) | Swift client (`kels-client`) for iOS/macOS; Android SDK on roadmap |
| FFI bindings | None | C bindings (`kels-ffi`) usable from any language |
| Hardware key integration | signify-ts uses libsodium (software keys) | Secure Enclave (iOS/macOS), PKCS#11 HSM (server-side, ML-DSA-65/87) |
| Client SDK languages | TypeScript (signify-ts), Python (signifypy) | Swift, C (via FFI), Rust (native), Android (on roadmap) |
| Edge signing | Browser-based (signify-ts + KERIA cloud agent) | On-device (Secure Enclave or software keys) |

**Analysis:** KERI's client strategy is web-first: signify-ts runs in browsers and communicates with a KERIA cloud agent. Key generation and signing happen at the edge (in the browser via libsodium), but the architecture assumes a persistent cloud agent for state management. There is no native mobile SDK — iOS or Android apps would need to wrap signify-ts or reimplement the protocol.

KELS provides native device integration through two paths: a Swift client (`kels-client`) with direct Secure Enclave support for iOS/macOS, and C FFI bindings (`kels-ffi`) that enable integration from any language with C interop. An Android SDK (Kotlin/JNI over the C FFI) is on the roadmap. On-device signing uses hardware-backed keys (Secure Enclave) rather than software keys, providing stronger key protection without a cloud agent dependency.

**2026 consideration:** Mobile-first identity is increasingly important as digital wallets (eIDAS 2.0 EUDI Wallet, Apple Wallet, Google Wallet) become primary credential containers. KELS's native Swift client and Secure Enclave integration position it well for this trend. ML-DSA-65 and ML-DSA-87 support is implemented for infrastructure and available for clients, aligning with Apple's Secure Enclave PQ capabilities (iOS 26+). KERI's browser-based approach works for web applications but requires additional work for native mobile experiences.

---

## DVTI Usage Context Recommendations

### 1. Personal/Consumer Identity (e.g., digital wallets, personal credentials)

**Recommended: Context-dependent**

- **For mobile wallets with hardware-backed keys**: **KELS**. Native Swift client with Secure Enclave integration provides on-device signing without cloud agent dependency. ML-DSA-65/87 support aligns with Apple's Secure Enclave PQ capabilities. A single KELS node can serve as the backend; the federation layer is optional for personal use.
- **For fully decentralized, infrastructure-independent identity**: **KERI**. Self-certifying identifiers with controller-selected witnesses and OOBI discovery require no specific backend infrastructure. The social accountability model for duplicity aligns with how personal reputation works.

KERI's browser-based client (signify-ts) works well for web applications but lacks native mobile SDK support or hardware key integration. KELS's native device support is a significant advantage as digital wallets (eIDAS 2.0 EUDI Wallet, Apple Wallet) become primary credential containers.

### 2. Enterprise/Organizational Identity (e.g., corporate PKI replacement, B2B trust)

**Recommended: KELS**

Enterprises need:
- **Deterministic recovery procedures** — KELS's three-tier key hierarchy, explicit recovery events, and merge-layer rejection of privileged-events-in-divergent-sets (with federation-layer dispute surfaced via the contested-prefix table) map directly to incident response runbooks.
- **Auditable divergence handling** — Divergence stored in the KEL provides a forensic record without requiring external watcher infrastructure.
- **Controlled federation** — Membership lives on the federation IEL; changes are governance-authorized `Evl` events requiring threshold endorsement, mapping cleanly to enterprise change-management processes.
- **Automated trust decisions** — Type-safe verification tokens enable high-assurance automated systems without human-in-the-loop for every trust decision.

KERI can work here but requires more operational tooling around witness management and duplicity monitoring.

### 3. IoT and Device Identity (e.g., device attestation, firmware signing)

**Recommended: KELS**

IoT environments demand:
- **Gossip-based replication** — Devices may have intermittent connectivity; gossip with anti-entropy is more resilient than witness receipt requirements.
- **Automated recovery** — Compromised device keys must be recoverable without human intervention; KELS's `rec` event with dual signatures enables this.
- **HSM integration** — KELS's architecture assumes HSM-backed keys for services, aligning with hardware root-of-trust models common in IoT.
- **Bounded resource usage** — KELS's paginated verification with `max_pages` limits prevents resource exhaustion on constrained devices.

KERI's witness model assumes relatively stable infrastructure, which is often unavailable in IoT deployments.

### 4. Decentralized Finance / High-Value Transactions

**Recommended: KELS (with caveats)**

High-value contexts need:
- **Total compromise response** — Privileged-divergence-is-terminal provides a deterministic response to the worst case: any privileged event landing in a divergent set freezes the chain with a federation-wide-consistent effective SAID. In DeFi, an ambiguous identity state can mean unbounded financial loss.
- **Zero-trust verification** — KELS's explicit "DB cannot be trusted" model and type-safe verification align with the assumption that any component may be compromised.
- **Forensic preservation** — Per-node first-receive retained on priv-vs-priv races; cross-node disagreement surfaced via the contested-prefix table for dispute resolution.

**Caveat:** KELS's algorithm choices (ML-DSA-65/87 for infrastructure, P-256 for mobile clients) are not optimal for blockchain interoperability (where Ed25519 and secp256k1 dominate). KERI's algorithm flexibility is an advantage here.

### 5. Government / Regulated Identity (e.g., eIDAS, national identity)

**Recommended: Context-dependent**

- **For closed federations** (e.g., inter-agency trust within a government): **KELS**. The federation IEL anchors trust in a single chain-rooted identity; threshold endorsement on `Evl` events maps well to regulated environments with defined participants and formal change-control processes; deterministic recovery extends to both peer-level and federation-level contests.
- **For open ecosystems** (e.g., citizen-facing credentials): **KERI**. The decentralized trust model and witness flexibility better serve environments where the credential holder must be able to verify against any infrastructure.

KELS has completed its post-quantum signature migration for infrastructure (ML-DSA-65/87, FIPS 204). KERI still needs post-quantum signature migration. For government use cases with typical 15-30 year data protection requirements, KELS's PQ support is a significant advantage.

### 6. Supply Chain Provenance / Verifiable Data

**Recommended: KELS**

Supply chain integrity requires:
- **Anchor verification** — KELS's inline anchor checking during verification (single pass) is well-suited to verifying that specific data items are anchored in a KEL.
- **Divergence as signal** — A divergent supply chain identifier is a meaningful security event that should be visible and actionable, not just a reputation problem.
- **Federation model** — Supply chains naturally involve a known set of participants, mapping well to KELS's federation-as-identity model where membership is encoded as a single identity's `authPolicy`.

### 7. Peer-to-Peer / Censorship-Resistant Communication

**Recommended: KERI**

P2P contexts need:
- **No infrastructure dependency** — KERI identifiers are self-certifying without any federation infrastructure.
- **OOBI flexibility** — Discovery via out-of-band introductions works in environments where centralized discovery is unavailable or undesirable.
- **Controller autonomy** — Witness selection by the controller, not by a federation, preserves user sovereignty.

Any federation introduces infrastructure dependencies that conflict with censorship-resistance goals, and KELS is no exception.

### 8. Multi-Party Coordination / DAOs / Governance

**Recommended: KELS**

Multi-party governance aligns naturally with KELS's design:
- **kels-policy** provides an expressive policy DSL (`endorse`, `identity`, `delegate`, `threshold`, `weighted`, nested `policy` references) for multi-party approval verified against KEL anchors, with soft/hard/immune poisoning and admin-controlled poison expressions.
- **Threshold endorsement** on federation `Evl` events provides multi-party authorization for membership changes using the same policy DSL.
- **Deterministic divergence resolution** provides clear rules when parties disagree.
- **Federation-as-identity** maps governance structures with defined membership directly onto a single shared identity chain.

---

## Summary Matrix

| Usage Context | Recommended | Key Deciding Factor |
|---|---|---|
| Personal identity (mobile) | KELS | Native device client, Secure Enclave, no cloud agent |
| Personal identity (web/decentralized) | KERI | Decentralized trust, no infrastructure dependency |
| Enterprise identity | KELS | Deterministic recovery, auditable divergence, federation-IEL-governed membership |
| IoT / device identity | KELS | Gossip replication, automated recovery, HSM integration |
| DeFi / high-value | KELS | Total compromise response, zero-trust verification |
| Government (closed) | KELS | Federation-IEL trust anchor, threshold-endorsed membership changes, formal recovery |
| Government (open) | KERI | Decentralized trust, flexible infrastructure |
| Supply chain | KELS | Inline anchor verification, federation-as-identity model |
| P2P / censorship-resistant | KERI | No infrastructure dependency, controller autonomy |
| Multi-party governance | KELS | Multi-party voting, deterministic divergence resolution |

---

## Deployment Ease

### KERI

**Initial setup:** A minimal KERI deployment runs a controller agent (e.g., KERIA) and at least one witness. KERIA ships a docker-compose configuration with a single service and references demo witness configurations in its startup scripts. KERIpy's README covers library installation and CLI usage but provides no multi-component deployment documentation.

The operational infrastructure that distinguishes KERI from a plain KEL system has not materialized. Watchers (duplicity detection), jurors (duplicity evaluation), and judges (trust decisions) — the roles that form KERI's social trust layer — do not have standalone deployable implementations in the WebOfTrust GitHub organization. Standing up a real KERI deployment with duplicity detection is uncharted operationally; the specification describes these roles conceptually, but a developer wanting to deploy them faces significant uncertainty about what to deploy and how. After roughly a decade of KERI, only a small number of real witness pools have been stood up. In practice, most adopters reach for cloud-agent hosting (e.g., a KERIA cloud agent), which re-introduces the centralized trust dependency that KERI's architecture was designed to avoid.

**Gossip-based replication is referenced in KERI but not specified.** Gossip is the mechanism that lets a federated event-log system propagate state correctly across divergence, recovery, and federation-level priv-vs-priv races — and getting it right is genuinely hard (send-side ordering on divergent chains, anti-entropy through terminal states, effective-SAID convergence on divergent chains, gossip-driven divergence detection, federation-layer dispute surfacing). Where KERI gestures at gossip as a replication option, it does not specify these problems or their solutions. The witness-receipt model is the only fully-specified replication path.

**Scaling:** Adding witnesses is a rotation event — straightforward in principle. Watchers can be added incrementally if anyone deploys them.

**Bootstrap chicken-and-egg:** Minimal. Identifiers are self-certifying from inception; a controller can create an identifier before any witnesses exist and add witnesses later.

**Upgrades:** Rolling upgrades on witnesses are feasible. Algorithm migration happens per-identifier via rotation events.

### KELS

**Initial setup:** A single KELS node (kels service + sadstore + PostgreSQL) provides the full KEL/IEL/SEL API — inception, rotation, interaction, recovery, contest, decommission, divergence handling — without the federation layer. This is comparable in complexity to any single-service web application; redis can be added for horizontal scaling.

**Features ship with the deployment.** The deployment is not just the core event-log services. Credentials (kels-creds), composable policy DSL (kels-policy), authenticated encrypted exchange (kels-exchange / ESSR), IPEX-style credential exchange messaging, and an encrypted mail service are part of the standard deployment, wired together at integration time and replicated through the same gossip mesh that propagates KEL/IEL/SEL events. An operator standing up a federation gets credentials, encrypted messaging, and credential exchange out of the box.

A federation is born via a one-time **coordinator ceremony**: one node acts as coordinator, the founding members submit signatures on the federation IEL Icp event to the coordinator's `kels`/`sadstore` services over HTTP, and the coordinator distributes the accepted federation IEL plus the member KELs to the other founding members via `transfer_*_events`. After distribution, every node holds the federation IEL and every other member's address SEL in its local sadstore, and the supporting member KELs in its local kels service; each gossip service queries its own node's local services to resolve peer addresses and verify chains. There is no multi-phase rebuild, no compile-time-prefix coordination, no platform-level service-discovery layer needed beyond TCP reachability between gossip endpoints. The full federation deployment is fully automated and reproducible.

**Scaling:** Adding a peer is an `Evl` event on the federation IEL — threshold endorsement collected out-of-band by the operators, then a single chain operation. The new peer receives initial state via `transfer_*_events`. No binary rebuild, no fleet redeploy.

**Bootstrap chicken-and-egg:** Minimal. The federation IEL prefix is baked into binaries at build as a compile-time default and overridable at runtime via `FEDERATION_IEL_PREFIX`. A federation can be brought up with binaries in hand; recovery from a federation-disputed federation IEL is a runtime override flip, not a fleet rebuild.

**Upgrades:** Routine. Membership evolution is a chain operation. Binary rolls happen on their own cadence; the runtime override gives operators a fast path when needed.

### Comparison

| Aspect | KERI | KELS |
|--------|------|------|
| Minimum services for a deployment | 2-3 (agent + witnesses) | 1 (kels) + PostgreSQL; scales horizontally with Redis |
| Full architecture deployable | No (watchers/jurors/judges lack implementations; gossip-based replication unspecified) | Yes (single-command federation deploy; gossip protocol mechanics fully specified and implemented) |
| Time to first identifier | Minutes (without duplicity detection) | ~2.5 minutes (single node, with divergence, reconciliation, and federation-dispute features) |
| Adding a peer / witness | Witness: rotation event. Watcher: no deployable implementation. | Federation IEL `Evl` with threshold endorsement (single chain operation) |
| Trusting a participant (identifier) | OOBI resolution (seconds) | Fetch KEL + verify (seconds) |
| Real-world infrastructure adoption | Most adopters use cloud-agent hosting (KERIA), which re-centralizes trust | Federation is professional operator infrastructure; end users carry no infrastructure burden |
| Bootstrap | Self-certifying inception | Federation IEL coordinator ceremony (one-time) |
| Configuration surface | Agent config + witness URLs | Compile-time federation IEL default + runtime override + HSM config |
| Reproducible dev environment | No (manual setup, no orchestration) | Yes (Garden + Kubernetes, single command) |
| Kubernetes-native | Possible but not designed for it | Garden-based deployment in repo; naturally fits K8s |

---

## Operational Complexity

### Day-to-Day Operations

**KERI:**
- **Key rotation:** Controller-initiated, immediate. No coordination with infrastructure.
- **Witness management:** Add/remove witnesses via rotation events. Witnesses are stateless relays — they can be replaced without data migration.
- **Monitoring:** Watch for duplicity via watchers. Duplicity is an exceptional event that requires human investigation.
- **Backup/recovery:** Controller's key material is the critical backup item. Lost witnesses are replaced by standing up a new witness with fresh keys and rotating the identifier's witness list. Prior receipts from the old witness remain verifiable (they're signed by the old witness's KEL) but the new witness must be receipted going forward.

**KELS:**
- **Key rotation:** Automatic for services. Manual for end-user KELs via CLI or client.
- **Peer management:** Submit an `Evl` event on the federation IEL with threshold endorsement. A single chain operation; no binary rebuild, no fleet redeploy.
- **Monitoring:** Divergence is visible in the KEL/IEL/SEL itself and propagated via gossip — monitoring is built into the data model. Anti-entropy runs every 10 seconds by default, providing continuous consistency checking.
- **Backup/recovery:** PostgreSQL databases are the primary data store. HSM key material must be backed up separately. Redis is reconstructable from PostgreSQL on restart (cache + operational state rebuilt via anti-entropy).
- **Federation health:** Monitor the federation IEL for cross-node priv-vs-priv races (concurrent `Evl`s surfaced via the contested-prefix table) and for member liveness. The federation IEL is propagated via the same gossip mesh as everything else; no separate consensus protocol to operate.

### Incident Response

| Scenario | KERI | KELS |
|----------|------|------|
| Signing key compromised | Rotate immediately (race with adversary) | Submit `rec` event (no race — requires recovery key) |
| Rotation key compromised | Rotate immediately (race with adversary) | Submit `rec` event (dual-signed, no race) |
| Total key compromise | No formal protocol; social resolution | Land a privileged event (`Rot`/`Ror`/`Dec`) extending `v_{d-1}`; privileged-divergence-is-terminal fires and permanently freezes the KEL deterministically |
| Divergence detected | Detection only (via watcher, where deployed); resolution is abandon-and-reincept (propagate new prefix to every consumer) or human arbitration | `rec`/`Rpr` to recover; privileged-divergence-is-terminal terminates. Both protocol-defined, machine-executable. |
| Peer/node compromise | Replace witness, rotate identifier's witness list (per-identifier action) | Federation `Evl` removing the peer from `authPolicy` (single federation-wide action) |
| Infrastructure outage | Witness redundancy; degrade gracefully | Gossip mesh self-heals; anti-entropy repairs gaps |
| Database corruption | Rebuild requires threshold witnesses reachable | Rebuild from any gossip peer holding a chain replica; chain is self-verifying |
| Federation membership change | Per-identifier witness-list rotation | Federation IEL `Evl` (one chain event, federation-wide) |

### Operational Burden Assessment

**Infrastructure burden under KERI falls on every controller.** The protocol presumes each controller selects and manages a witness pool, but in roughly a decade of KERI, very few real witness pools have been stood up. In practice, adopters reach for cloud-agent hosting (KERIA), which re-centralizes trust on a small number of providers. The watcher/juror/judge roles that would make the social trust layer operational lack standalone deployable implementations. The result is a wide gap between KERI as designed and KERI as deployed.

**Infrastructure burden under KELS falls on a small set of federation operators**, jointly. End users (controllers) carry no infrastructure burden. Federation operators do the work once, then operate a gossip mesh that propagates everything — KEL events, IEL events, SEL events, and the federation IEL itself — through the same mechanism. Membership changes are chain operations: collect threshold endorsements out-of-band, submit one `Evl`. No fleet rebuild, no consensus protocol to operate.

**Recovery is the analytical fulcrum.** KERI offers *detection* of divergence (via watchers, where deployed) but no protocol-defined *resolution*; the controller's options are abandoning the identifier (truck-roll to every consumer) or human-mediated arbitration. KELS offers detection *and* protocol-defined resolution — `rec`/`Rpr` to continue; privileged-divergence-is-terminal to terminate. Both paths are machine-executable. Automated trust decisions require both halves; KERI delivers only the first.

---

## Implementation Language Considerations

### KERI: Python (KERIpy)

**KERIpy** is the reference implementation, written in Python using `hio` (hierarchical asynchronous I/O).

**Advantages:**
- **Accessibility:** Python's broad adoption lowers the barrier for contributors, integrators, and auditors. Most developers can read and modify KERIpy without specialized language knowledge.
- **Rapid prototyping:** Protocol changes can be implemented and tested quickly. The KERI specification is still evolving, and Python's flexibility accommodates rapid iteration.
- **Ecosystem:** Rich library ecosystem for cryptography (`pysodium`, `cryptography`), HTTP, and testing.
- **ACDC/CESR tooling:** The broader KERI ecosystem (ACDC credentials, CESR encoding) is primarily Python, so staying in Python avoids FFI boundaries.

**Disadvantages:**
- **Performance:** Python's GIL and interpreted execution limit throughput. KEL verification is CPU-bound (signature verification, hash computation), and Python is 10-100x slower than compiled languages for these operations.
- **Memory safety:** Python is memory-safe (no buffer overflows, use-after-free), but its dynamic typing means type errors surface at runtime, not compile time. For security-critical code, this is a meaningful risk.
- **Deployment:** Python dependency management (virtualenvs, pip, version conflicts) adds operational friction. Container images are larger. Startup time is slower.
- **Concurrency:** `hio`'s cooperative multitasking model is less battle-tested than `tokio` or Go's goroutines for high-concurrency network services.
- **Type safety for security invariants:** Python cannot enforce verification-before-use at the type level. Security invariants must be maintained by convention and testing, not by the compiler.

**Other implementations:** There are also TypeScript (`signify-ts`), Rust, and Go implementations at various stages of maturity, but KERIpy remains the reference.

### KELS: Rust

**Advantages:**
- **Memory safety without GC:** Rust's ownership system prevents buffer overflows, use-after-free, and data races at compile time — critical for security infrastructure that handles cryptographic material.
- **Type-safe security invariants:** The `KelVerification` token pattern (private fields, no public constructor, only obtainable through verification) is a compile-time guarantee that unverified data cannot be used for security decisions. This is impossible to express in Python with equivalent strictness.
- **Performance:** Native compilation with zero-cost abstractions. Signature verification, Blake3 hashing, and KEL walking are orders of magnitude faster than Python equivalents. This matters for gossip nodes processing high event volumes.
- **Concurrency:** `tokio` async runtime is mature and battle-tested for network services. The borrow checker prevents data races at compile time.
- **FFI:** `kels-ffi` provides C bindings for cross-language integration (Swift client for iOS/macOS). Rust's `#[no_mangle]` and `extern "C"` make this straightforward.
- **Deployment:** Static binaries with minimal runtime dependencies. Small container images. Fast startup.
- **Supply chain:** `cargo deny` for dependency auditing is integrated into the build (`make deny`). Compile-time trust anchors are verified by the build system.

**Disadvantages:**
- **Contributor barrier:** Rust's learning curve is steep. The ownership system, lifetime annotations, and trait bounds are obstacles for developers unfamiliar with the language. This limits the contributor pool and makes auditing harder for organizations without Rust expertise.
- **Compile times:** Full rebuilds are slow. The two-phase deployment (recompile with new trust anchors) amplifies this — every trust anchor change requires a full rebuild of all binaries.
- **Ecosystem maturity:** While Rust's cryptography ecosystem is maturing rapidly (`p256`, `blake3`, `aes-gcm` crates are well-maintained), it is smaller than Python's. Some operations require more manual implementation.
- **Iteration speed:** Protocol changes require more code and more careful design. Rust's strictness is a feature for production but a tax on experimentation.

### Language Choice Impact on Security

| Property | Python (KERIpy) | Rust (KELS) |
|----------|-----------------|-------------|
| Memory safety | Runtime (GC) | Compile-time (ownership) |
| Type-safe security invariants | Convention + tests | Compiler-enforced |
| Data race prevention | GIL (single-threaded) | Compile-time (Send/Sync) |
| Buffer overflow risk | None (managed memory) | None (borrow checker) |
| Dependency supply chain | pip (less auditing tooling) | cargo deny (integrated auditing) |
| Cryptographic constant-time | Library-dependent | Library-dependent + compiler hints |
| Integer overflow | Silent in Python 2, safe in 3 | Panics in debug, wraps in release (configurable) |

**2026 assessment:** The industry trend toward memory-safe languages for security infrastructure (driven by CISA guidance, White House directives, and major vendor commitments) favors Rust. However, Python remains appropriate for higher-level protocol implementations where performance is not the bottleneck and contributor accessibility matters more than compile-time guarantees.

For DVTI infrastructure that processes high event volumes, enforces security invariants automatically, and must resist sophisticated attacks, Rust's compile-time guarantees provide material security benefits. For client-side tooling, credential management, and protocol experimentation, Python's accessibility and iteration speed are more valuable.

---

## Terminology and Naming Conventions

One of the most immediate differences between KERIpy and KELS is how they name things. This has a significant impact on onboarding time, code auditability, and the ability of external reviewers to assess security properties.

### KERIpy: Domain-Specific Vocabulary

KERIpy uses a highly customized internal vocabulary that diverges substantially from both standard cryptographic terminology and common software engineering conventions. New contributors must learn what amounts to a project-specific dialect before they can read the code productively.

**Core class names:**

| KERIpy Name | What It Actually Is |
|-------------|-------------------|
| `Hab` / `Habitat` | An identifier manager (holds keys, signs events, tracks state) |
| `Habery` | A collection/factory of Habitats |
| `Kevery` | Key Event Verifier — processes and verifies incoming events |
| `Kever` | Key Event verifier state for a single identifier |
| `Serder` | Serializer/Deserializer for KERI events |
| `Sadder` | Self-Addressing Data wrapper (SAID-able content) |
| `Saider` | SAID computer/holder |
| `Siger` | Indexed signature wrapper |
| `Cigar` | Non-indexed (transferable) signature wrapper |
| `Diger` | Digest wrapper |
| `Prefixer` | Prefix computer/holder |
| `Seqner` | Sequence number wrapper |
| `Verfer` | Verification key wrapper |
| `Signer` | Signing key wrapper |
| `Salter` | Salt generator for key derivation |
| `Encrypter` / `Decrypter` | Asymmetric encryption wrappers |
| `Tholder` | Threshold holder (signing/rotation thresholds) |
| `Psr` | Parser (event stream parser) |
| `Kvy` | Short alias for Kevery in function parameters |
| `Tvy` | Transaction Event Verifier (TEL verifier) |
| `Rgy` | Registry (credential registry manager) |
| `Reger` | Registry database |
| `Vry` | Verifier (in some contexts) |

**Event field names (single-letter or abbreviated):**

| KERIpy Field | KELS Equivalent | Meaning |
|-------------|-----------------|---------|
| `"i"` | `"prefix"` | Identifier prefix |
| `"s"` | `"serial"` | Sequence number |
| `"t"` | `"kind"` | Event type |
| `"d"` | `"said"` | SAID (self-addressing identifier) |
| `"p"` | `"previous"` | Previous event SAID |
| `"kt"` | — | Signing threshold |
| `"k"` | `"publicKey"` | Current signing key(s) |
| `"nt"` | — | Next key threshold |
| `"n"` | `"rotationHash"` | Next key digest(s) (pre-rotation commitment) |
| `"bt"` | — | Witness threshold |
| `"b"` | — | Witness list (backers) |
| `"c"` | — | Configuration traits |
| `"a"` | `"anchor"` | Anchored data / seals |
| `"di"` | `"delegatingPrefix"` | Delegator identifier |
| `"rd"` | — | Registry delegator |
| `"ee"` | — | Last establishment event |
| `"br"` | — | Witnesses to remove (backer remove) |
| `"ba"` | — | Witnesses to add (backer add) |

**Module naming:** KERIpy's module structure uses abbreviated names throughout — `core/eventing.py`, `core/parsing.py`, `app/habbing.py`, `vdr/` (Verifiable Data Registry). Function parameters frequently use 2-3 letter abbreviations (`hab`, `hby`, `kvy`, `psr`, `tvy`, `rgy`, `msg`, `pre`, `sn`, `dig`).

### KELS: Conventional Naming

KELS uses standard software engineering naming conventions with full English words. The vocabulary maps directly to the domain concepts described in the documentation.

**Core type names:**

| KELS Name | Purpose |
|-----------|---------|
| `KeyEvent` | A single event in a Key Event Log |
| `SignedKeyEvent` | KeyEvent with attached signatures |
| `KeyEventBuilder` | Creates and signs key events |
| `KelVerifier` | Streaming verifier for KEL integrity |
| `KelVerification` | Proof-of-verification token |
| `KelStore` | Trait for KEL persistence |
| `KelTransaction` | Advisory-locked database transaction |
| `BranchTip` | Verified chain endpoint |
| `KeyEventKind` | Enum of event types |
| `KeyEventSignature` | Role label ("signing"/"recovery") + signature pair |
| `MergeTransaction` | Verify-then-write for incoming events |
| `Peer` | Network peer record |
| `SignedRequest<T>` | Authenticated request wrapper |

**Event field names:** Full English words with camelCase JSON serialization:

```json
{
  "said": "E...",
  "prefix": "E...",
  "previous": "E...",
  "serial": 3,
  "kind": "kels/kel/v1/events/rot",
  "publicKey": "D...",
  "rotationHash": "E...",
  "recoveryKey": "D...",
  "recoveryHash": "E...",
  "anchor": null,
  "delegatingPrefix": null
}
```

**Method names:** Self-documenting verbs and nouns:

```
incept(), rotate(), recover(), contest(), decommission()
verify_signatures(), verify_inception(), verify_chain_event()
is_establishment(), reveals_recovery_key(), requires_dual_signature()
transfer_key_events(), forward_key_events(), verify_key_events()
compute_rotation_hash(), compute_approval_threshold()
```

**Error variants:** Descriptive English:

```
NotFound, InvalidKeyEvent, SignatureVerificationFailed,
KelDecommissioned, ParentLocked, DivergenceDetected
```

### Side-by-Side Comparison

To illustrate the contrast, here is how equivalent concepts appear in each codebase:

**Creating an identifier:**

KERIpy:
```python
hab = hby.makeHab(name="test", transferable=True)
pre = hab.pre  # prefix
kever = hab.kever  # key event verifier state
```

KELS:
```rust
let builder = KeyEventBuilder::new(key_provider);
let (event, signed) = builder.incept()?;
let prefix = event.prefix;
```

**Verifying incoming events:**

KERIpy:
```python
kvy = Kevery(db=hby.db)
psr = parsing.Parser()
psr.parse(ims=msg, kvy=kvy)
kever = kvy.kevers[pre]
```

KELS:
```rust
let verifier = KelVerifier::new(prefix);
verifier.verify_page(&signed_events)?;
let verification = verifier.into_verification()?;
let key = verification.current_public_key();
```

**Accessing a signature:**

KERIpy:
```python
siger = Siger(qb64=sig)  # indexed signature
cigar = Cigar(qb64=sig)  # non-indexed signature
verfer = Verfer(qb64=pub) # verification key
```

KELS:
```rust
let sig = KeyEventSignature {
    label: "signing".to_string(),
    signature: sig_qb64,
};
```

### Naming Philosophy Analysis

**KERIpy's approach:**
- Internally consistent once learned — the `-er` suffix pattern (Serder, Saider, Siger, Diger, Verfer, etc.) creates a recognizable family of wrapper types.
- Compact — abbreviated names reduce line length and match the terse single-letter field names in the wire format.
- Insider language — creates a strong in-group/out-group dynamic. Contributors who have internalized the vocabulary can read the code fluently, but newcomers face a steep glossary wall before they can begin.
- Wire format bleeds into code — the single-letter event fields (`"i"`, `"s"`, `"t"`, `"d"`) appear directly in code, requiring constant mental translation.

**KELS's approach:**
- Self-documenting — type names, field names, and method names read as English descriptions of their purpose. A developer reading `KelVerifier::verify_chain_event()` or `KeyEventKind::requires_dual_signature()` understands the operation without consulting a glossary.
- Standard conventions — follows Rust community naming (traits named for capabilities, enums named for the domain, methods named as verb phrases). No project-specific lexicon to learn.
- Explicit over compact — `rotationHash` is longer than `"n"` but communicates its meaning without context. `recoveryKey` is unambiguous where `"br"` requires documentation.
- Wire format separated from code — Rust field names are `snake_case`, JSON serialization is `camelCase` via serde attributes. The wire format is a serialization concern, not a naming concern.

---

## Learning Curve for a Cryptographer

Consider a cryptographer with strong knowledge of public key infrastructure, hash functions, digital signatures, and key management — but no prior exposure to either KERI or KELS. How quickly can they become productive in each codebase?

### Week 1: Orientation

**KERIpy:**
- The cryptographer can immediately understand the *cryptographic* operations (Ed25519 signatures, Blake3 hashing, pre-rotation commitments) because the underlying math is standard.
- However, they cannot read the code without first learning the project vocabulary. Terms like `Kevery`, `Habery`, `Serder`, `Siger`, `Cigar`, `Tholder` have no external referent — they are KERIpy coinages that must be memorized.
- The single-letter event fields require a cheat sheet. `"n"` means "next key digest" (pre-rotation commitment), not "nonce." `"b"` means "backers" (witnesses), not "block."
- The `hio` async framework is uncommon — most Python developers know `asyncio`, not `hio`'s cooperative doer model. This is an additional learning curve orthogonal to the domain.
- The role taxonomy (witnesses, watchers, jurors, judges, registrars) requires understanding KERI's social trust model, which is a conceptual framework rather than just code.

**Estimated time to first meaningful code review:** 2-3 weeks. The cryptographer understands the math immediately but cannot map it to the codebase without extensive glossary study.

**KELS:**
- The cryptographer can read the type definitions and understand the security model directly. `KelVerifier`, `KelVerification`, `recoveryKey`, `rotationHash`, `requires_dual_signature()` — these terms map to concepts they already know.
- Rust itself is a learning curve if they are not already proficient, but the *domain naming* does not add to it. A Rust-literate cryptographer can read KELS types on day one.
- The three-tier key hierarchy (signing, rotation, recovery) is documented in the type system: `publicKey`, `rotationHash`, `recoveryKey`, `recoveryHash` are all explicit fields on `KeyEvent`.
- Infrastructure concepts (gossip, federation) use standard distributed systems terminology. `HyParView` and `PlumTree` are published protocols with their own literature.
- The `KelVerification` token pattern is novel but immediately comprehensible to anyone who has worked with capability-based security or proof-carrying code.

**Estimated time to first meaningful code review:** 1 week (if Rust-proficient) or 3-4 weeks (if learning Rust simultaneously). The domain naming is not a bottleneck.

### Month 1-3: Depth

**KERIpy:**
- The cryptographer must internalize the full role model: how witnesses, watchers, jurors, and judges interact. This is a conceptual framework that goes beyond code — it requires understanding KERI's philosophy of duplicity detection as a social accountability mechanism.
- The OOBI discovery mechanism, TELs (Transaction Event Logs), and ACDC credential framework each introduce additional vocabulary and concepts.
- The codebase has significant internal coupling — `Habery` manages `Hab` instances which use `Kevery` for verification which depends on `Kever` state. Understanding one component requires understanding several others.
- Protocol edge cases (partial witness sets, threshold structures, delegation chains) are encoded in the same terse naming style, making debugging harder.

**KERIpy has more concepts to learn:** witnesses, watchers, jurors, judges, registrars, OOBIs, TELs, ACDCs, receipt thresholds, witness rotation, delegation approval, partial rotation — each with its own abbreviated naming.

**KELS:**
- The cryptographer dives into divergence handling, recovery semantics, and the merge transaction. These are complex but documented in the type system — `KelMergeResult` has variants `Accepted`, `Recovered`, `Diverged`, `RecoverRequired`, `ParentLocked` that enumerate the state machine explicitly; cross-node federation-level dispute surfaces via the contested-prefix table at the infrastructure layer.
- The gossip protocol (HyParView + PlumTree) is a standard distributed-systems pattern with extensive external literature; the federation model expresses membership and governance as ordinary IEL operations and uses the same policy DSL the rest of the system uses.
- The verification model's advisory locking and TOCTOU prevention are sophisticated but follow established database patterns.

**KELS has fewer novel concepts:** the event types, key hierarchy, divergence state machine, gossip protocol, and federation model are the core set. Each uses descriptive naming that connects to its external literature.

### Auditability

For a security audit, the naming difference is material:

**KERIpy audit challenge:** An auditor must first build a mental translation layer between KERIpy's vocabulary and standard cryptographic concepts. When reviewing `Kevery.process()` for verification correctness, they must hold in mind that `kever.verfers` means "verification keys for this identifier" and `siger.index` means "which key in the multi-sig set signed this." Errors in this mental translation can cause missed vulnerabilities.

**KELS audit advantage:** An auditor can read `KelVerifier::verify_signatures(signed_event, publicKey)` and immediately assess whether the signature verification is correct relative to the claimed key. The type signature communicates intent. The `KelVerification` token pattern means the auditor can verify that all security-sensitive code paths require proof of verification by tracing type usage — no runtime behavior analysis needed.

### Summary

| Factor | KERIpy | KELS |
|--------|--------|------|
| Domain vocabulary to memorize | ~30+ project-specific terms | ~5 (KEL, SAID, CESR, prefix, serial) |
| Event field readability | Single-letter (`"i"`, `"s"`, `"n"`, `"b"`) | Full words (`"prefix"`, `"serial"`, `"rotationHash"`) |
| Infrastructure roles to understand | 7+ (controller, witness, watcher, juror, judge, registrar, validator) | 2 (gossip node, identity service) |
| Naming convention | Project-specific (`-ery`, `-er` suffixes) | Standard Rust / English |
| External literature alignment | Low — terms are KERI-specific coinages | High — uses published protocol names and standard crypto terms |
| Time to first code review (domain-experienced) | 2-3 weeks | 1 week (Rust-proficient) |
| Security audit readability | Requires glossary translation layer | Self-documenting types and methods |

---

## Conclusion

KERI and KELS represent different points in the DVTI design space — KERI is positioned as a DKMI (the keys slice); KELS spans the broader DVTI (keys + identity + content + the features built on them). KERI optimizes for decentralization, controller autonomy, and a rich taxonomy of participant roles (witnesses, watchers, jurors, judges) intended to support open ecosystems where no single party controls the infrastructure and where a social trust layer carries resolution. KELS optimizes for operational rigor, deterministic security, and automated trust decisions, targeting environments with defined participants and high-assurance requirements.

The most significant differentiator is **detection vs. resolution**. KERI provides detection of divergence via watchers but no protocol-defined path to continue from a divergent state — the controller's options are abandoning the identifier (propagate a new prefix to every consumer) or human-mediated arbitration. KELS provides both detection *and* resolution: `rec`/`Rpr` to recover; privileged-divergence-is-terminal (any privileged event landing in a divergent set) to terminate the chain — all protocol-defined and machine-executable. In a zero-trust landscape where automated trust decisions are the norm, detection-only systems force humans into the loop for every divergence event; protocol-defined resolution is what makes machine-autonomous incident response possible.

The empirical state of KERI's social trust layer compounds the gap. After roughly a decade of KERI, the operational infrastructure that distinguishes it from a plain KEL system has not materialized: watchers, jurors, and judges lack standalone deployable implementations, and only a small number of real witness pools exist. In practice, adopters reach for cloud-agent hosting (KERIA), which re-introduces the centralized trust dependency KERI was designed to avoid. KERI as designed and KERI as deployed are different systems.

KELS's three-tier key hierarchy (signing, rotation, recovery) provides a stronger recovery posture than KERI's tholder + pre-rotation model, which composes keys but has no explicit recovery-key tiering. KELS eliminates the race condition inherent in KERI's pre-committed-next-key compromise scenario by requiring dual signatures (rotation + recovery) for recovery events, and provides a deterministic total-compromise response — federation-level non-convergence surfaced via the contested-prefix table, with merge-layer rejection of priv events that would create or join divergent sets — that KERI lacks. On multi-party governance, KERI embeds weighted multi-sig thresholds directly in the identifier, while KELS keeps core KELs single-key and provides governance at a higher layer via kels-policy — an expressive policy DSL supporting `endorse`, `identity`, `delegate`, `threshold`, `weighted`, and nested `policy` references, with soft/hard/immune poisoning and admin-controlled poison expressions. The single-argument `delegate(DELEGATOR)` form discovers specific delegates at evaluation time, so edges match on trust structure without pinning specific services. Both approaches can express equivalent policies; the difference is where verification complexity lives.

KELS's verification model enforces security invariants at the type level: the `KelVerification` token (private fields, no public constructor, obtainable only through `KelVerifier::into_verification()`) guarantees at compile time that security decisions cannot be made on unverified data. Advisory locking through verify+write eliminates TOCTOU vulnerabilities. KERI's verification semantics are specified but enforcement rigor is implementation-dependent.

The credential ecosystems are converging. KERI's ACDC framework with TELs is more mature, but kels-creds + kels-policy + kels-exchange provides a leaner alternative — schema-aware compaction, graduated disclosure via a path expression DSL, recursive edge verification with compacted policy matching, composable multi-party trust policies including `identity(...)` for resolution-current authority and `delegate(DELEGATOR)` for fleet-scaling delegate discovery, poisoning semantics, ESSR post-quantum authenticated encryption for credential exchange, and no separate registry infrastructure. The remaining functional gap is primarily ecosystem maturity rather than missing capabilities.

The two protocols also differ on delegation. KERI verifies delegation trust in-protocol — delegated establishment events require the delegator to anchor approval seals in their own KEL. KELS defers delegation verification at the service level (accepting any structurally valid `dip`) but provides automatic delegation trust verification at the credential level via the kels-policy `delegate(DELEGATOR)` DSL node — single-argument, with specific delegates discovered at evaluation time by walking the delegator's KEL. The policy names only the delegator, so edges express "any delegate of this authority" by construction, supporting fleet scaling (HSM-backed service delegates to rotating software-key services) without policy edits.

KELS's prefix derivation provides a privacy advantage absent from KERI: because the prefix and SAID are computed sequentially (producing distinct values), event SAIDs in logs or anchor records cannot be correlated back to an identity without the full event. In KERI, prefix equals inception SAID, making any logged inception SAID immediately identifying.

Both protocols support offline and airgapped key operations — pre-rotation commitments are computed locally and events can be signed without network access. The difference is in reconnection: KERI requires submission to enough witnesses to meet the receipt threshold (a liveness dependency), while KELS requires submission to any reachable gossip node, after which the gossip mesh handles distribution (announcement-driven primary, dependency tracking for out-of-order arrivals, anti-entropy as fallback) without further controller action.

The terminology gap compounds the architectural differences. KERIpy's custom vocabulary (~30+ project-specific terms like `Kevery`, `Habery`, `Serder`, `Siger`) creates a significant onboarding barrier that slows auditing, limits the contributor pool, and increases the risk of misunderstanding during security review. KELS's conventional naming makes the codebase immediately legible to anyone familiar with cryptography and distributed systems, reducing the distance between "reading the code" and "understanding the security model." For a domain-experienced cryptographer, the estimated time to first meaningful code review is 2-3 weeks for KERIpy (due to vocabulary overhead) versus 1 week for KELS (if Rust-proficient).

The deployment and operational picture has flipped from older comparisons. Under federation-as-identity, KELS is the lighter system to deploy and operate: a single coordinator ceremony brings up the federation IEL, peer adds and removes are chain operations with threshold endorsement, and there's no per-controller infrastructure burden — federation operators run the mesh jointly, end users carry nothing. KERI's minimal deployment is conceptually simple, but a real KERI deployment that includes duplicity detection (the social trust layer) is uncharted operationally, and gossip-based replication is referenced in KERI but not specified — the hard problems (send-side ordering across divergent chains, anti-entropy through terminal states, effective-SAID convergence on divergent chains, federation-layer dispute surfacing for cross-node priv-vs-priv races) are the work KELS has had to do and prove. The language choice (Python vs Rust) mirrors a separate tension — accessibility and iteration speed versus compile-time safety guarantees and performance — but it doesn't drive the operational story.

Device integration is another differentiator. KELS was designed for hardware-backed keys from the start — the Swift client with Secure Enclave integration, C FFI bindings for cross-language use, HSM-backed service identities (ML-DSA-65/87 via PKCS#11), and an Android SDK on the roadmap reflect this. KERI's client ecosystem is web-first (signify-ts in browsers, signifypy in Python), with no native mobile SDK or hardware key integration. As mobile-first identity wallets become the norm, KELS's native device support and ML-DSA-65 compatibility with Apple Secure Enclave (iOS 26+) provide a clear advantage.

On post-quantum readiness, KELS has completed its infrastructure migration: ML-DSA-65 or ML-DSA-87 (FIPS 204, configurable via `NEXT_SIGNING_ALGORITHM` / `NEXT_RECOVERY_ALGORITHM`) for all infrastructure signing, ML-KEM-768 or ML-KEM-1024 (FIPS 203, auto-negotiated based on peer signing algorithms) for gossip transport key exchange, and support for mixed algorithms with upgrade via rotation. The core service accepts P-256, ML-DSA-65, and ML-DSA-87 KELs, enabling gradual client migration. KERI's broader cryptographic agility theoretically accommodates any PQ algorithm, but without a specific implementation, the migration timeline is less defined. Both protocols' pre-rotation hash commitments are already quantum-resistant.

KELS's roadmap — Android SDK, exhaustive proof of divergence reconciliation, a standards proposal, and a DID method specification — positions it for production readiness and ecosystem participation. kels-policy (multi-party governance DSL with composable trust policies, poisoning, and admin-controlled poison expressions) and kels-exchange (ESSR post-quantum authenticated encryption, IPEX-style credential exchange messaging, and a mail service for encrypted message delivery) are implemented. KERI's head start in standards (IETF Internet-Drafts), community (WebOfTrust, GLEIF vLEI), and multi-implementation diversity remains a significant advantage for risk-averse adopters today.
