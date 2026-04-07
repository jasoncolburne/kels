# KERI vs KELS: Comparative Security Analysis for DKMI Usage Contexts

This document compares KERI (Key Event Receipt Infrastructure) and KELS (Key Event Log System) across their security properties, architectural decisions, and suitability for various Decentralized Key Management Infrastructure (DKMI) scenarios. Analysis reflects security best practices as of 2026, including post-quantum readiness, zero-trust architecture, and supply chain integrity considerations.

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

KELS is a federated key event system that shares KERI's foundational concepts (KELs, pre-rotation, SAIDs, CESR) but diverges significantly in how it handles key compromise, replication, and trust. KELS **stores divergent events directly in the KEL** rather than treating duplicity as an external detection problem. It introduces explicit recovery (`rec`) and contest (`cnt`) event types with formal semantics. Replication uses a custom gossip protocol (HyParView + PlumTree over ML-KEM-768/1024 + ML-DSA-65/87 + AES-GCM-256) rather than witness receipts. Trust anchors are compile-time registry prefixes with multi-party voting for peer lifecycle.

KELS derives the prefix differently from the SAID (blanking both `said` and `prefix` fields before hashing, and computing each in sequence — prefix first — rather than in the same operation), producing two distinct content-derived identifiers from the same inception event. There is no way to reverse an event's SAID to determine which identity created it — you need the full event. This protects against some identification attacks.

---

## Security Property Comparison

### 1. Key Compromise Recovery

| Property | KERI | KELS |
|----------|------|------|
| Pre-rotation commitment | Yes (hash of next public key) | Yes (Blake3 of next public key) |
| Recovery from signing key compromise | Rotation event | `rec` event (dual-signed: rotation + recovery key) |
| Recovery from rotation key compromise | Rotation by controller (race condition) | `rec` event (requires recovery key — no race) |
| Total compromise (rotation + recovery) | No formal mechanism; duplicity detected | `cnt` (contest) permanently freezes KEL |
| Recovery key hierarchy | Two-tier (signing + pre-rotated next) | Three-tier (signing, rotation, recovery) |
| Key compromise visibility | External: watchers detect duplicity | Internal: divergence stored in KEL, propagated network-wide |

**Analysis:** KELS's three-tier key hierarchy provides a stronger recovery posture. In KERI, if an adversary compromises the pre-rotated next key, there is a race condition — whoever rotates first wins. KELS eliminates this race by requiring dual signatures (rotation + recovery) for recovery events, meaning the adversary cannot recover with only the rotation key. The explicit contest mechanism for total compromise is a significant advantage: rather than leaving a totally compromised identifier in an ambiguous state, KELS provides a deterministic, auditable freeze.

**2026 consideration:** With quantum computing advances making asymmetric key compromise more plausible (even if not yet practical at scale), having a formal total-compromise response (`cnt`) is increasingly valuable. Both protocols' pre-rotation commitments provide some post-quantum protection since the hash commitment cannot be broken even by a quantum adversary — but KELS's recovery hierarchy provides defense in depth beyond what pre-rotation alone offers.

### 2. Divergence and Duplicity Handling

| Property | KERI | KELS |
|----------|------|------|
| Conflicting events | Rejected by witnesses; detected by watchers | Stored in KEL; KEL frozen until resolved |
| Divergence visibility | Requires active watcher monitoring | Inherent in data structure; propagated via gossip |
| Resolution mechanism | Social/out-of-band (controller accountability) | Cryptographic (`rec` to recover, `cnt` to freeze) |
| Forensic record | Distributed across watchers | Preserved in KEL (contest does not archive) |
| Adversary event archival | Not formalized | `rec` archives adversary events; `cnt` preserves all |

**Analysis:** This is the most fundamental architectural difference. KERI treats duplicity as a signal of misbehavior to be detected externally, while KELS treats divergence as a state to be managed cryptographically within the protocol itself.

KERI's approach relies on the social layer — once duplicity is detected, the controller's reputation is damaged, and relying parties must make trust decisions. This works well in contexts where identity reputation matters (human identifiers, organizational credentials) but poorly in automated systems where there is no "reputation" to damage.

KELS's approach is more mechanical and auditable: divergence is a protocol state with defined transitions (recover or contest). This is better suited to automated, high-assurance environments where human judgment cannot be inserted at every trust decision. Notably, KELS also supports external auditing of divergence — since divergence is visible in the data structure and propagated via gossip, external parties can monitor for divergence events and apply their own social or policy-based trust decisions, just as KERI's watchers do for duplicity. KELS provides both the cryptographic resolution path and the external monitoring path; KERI provides only the external path.

**2026 consideration:** Zero-trust architectures demand automated, cryptographically-verifiable trust decisions. KELS's approach aligns better with this paradigm — divergence state is machine-readable and resolution is protocol-defined rather than requiring human interpretation.

### 3. Replication and Availability

| Property | KERI | KELS |
|----------|------|------|
| Replication model | Designated witness pools + receipts | Gossip (HyParView + PlumTree) + HTTP fetch |
| Consistency model | Receipt threshold (e.g., 2-of-3 witnesses) | Eventual consistency via gossip + anti-entropy |
| Availability guarantee | Witness liveness required | Any gossip peer can serve; registry manages peer set |
| Transport security | Varies by implementation | ML-KEM-768/1024 + ML-DSA-65/87 + AES-GCM-256 (forward secrecy, mutual auth, PQ-secure) |
| Discovery | OOBIs (Out-of-Band Introductions) | Registry-managed peer allowlists (compile-time trust roots) |
| Infrastructure responsibility | Controller selects and manages witnesses | Federation operators run shared infrastructure |

**Analysis:** KERI's witness model provides stronger consistency guarantees at the cost of availability — if witnesses are offline, events cannot be receipted. KELS's gossip model prioritizes availability and partition tolerance, accepting eventual consistency. The tradeoff is that KELS nodes may temporarily have stale views, but anti-entropy repair (every 10s by default) bounds staleness.

A critical operational difference is *who bears the infrastructure burden*. In KERI, the controller is responsible for selecting and managing their own witness pool. For organizations with infrastructure teams this is manageable, but for small businesses or consumers it creates an unrealistic operational requirement. In practice, this pushes most users toward third-party witness hosting (e.g., a KERIA cloud agent), which re-introduces the centralized trust dependency that KERI's architecture was designed to avoid. KELS inverts this: the service is shared infrastructure that verifies and stores KELs — it has no per-identity infrastructure. A consumer's phone talks to the KELS service, gossip handles replication, and the operational burden falls entirely on federation operators rather than end users.

KELS's transport security is notably stronger: the ML-KEM-768/1024 key exchange with ML-DSA-65/87 mutual authentication provides forward secrecy, mutual authentication tied to KEL identities, and post-quantum security. KERI's transport security is implementation-dependent.

**2026 consideration:** The shift toward mesh and edge computing favors gossip-based replication. KELS's model works better in environments with intermittent connectivity or where designated infrastructure (witnesses) cannot be guaranteed. However, KERI's witness model is simpler to reason about for compliance and audit purposes. The witness operational burden is increasingly relevant as identity systems target consumer adoption — expecting end users to manage distributed infrastructure is a non-starter for mass-market digital wallets.

### 4. Trust Model and Trust Anchoring

| Property | KERI | KELS |
|----------|------|------|
| Root of trust | Self-certifying identifiers (inception event) | Self-certifying identifiers (inception event) for participants, Compile-time trusted registry prefixes for infrastructure |
| Delegation trust | Verified in protocol (delegated rotation) | Deferred to consumers (KELS accepts any valid `dip`) |
| Ambient verifiability | Yes (any party can verify any KEL) | Yes (any party can verify any KEL) |
| Infrastructure trust | Witness selection by controller | Multi-party voting (min 3 votes scaling to 1/3 voter pool) for peer lifecycle |

**Analysis:** Both protocols share the same root of trust for identities — any identifier is self-certifying from its inception event alone. The difference is in infrastructure trust: KERI relies on controller-selected witnesses, while KELS introduces a federation layer with compile-time trust anchors for infrastructure (registries and gossip peers). This is a stronger assumption but provides a clearer trust boundary for organizational deployments.

KELS's multi-party voting for peer lifecycle (minimum 3 votes, scaling to 1/3 of registries as the federation grows) provides strong Sybil resistance and prevents unilateral infrastructure changes. KERI relies on the controller's witness selection, which is more flexible but places more trust in the controller.

**2026 consideration:** Supply chain security concerns favor KELS's compile-time trust anchors — the trusted set is auditable and cannot be changed at runtime. However, this rigidity is a liability in dynamic environments. KERI's model is more adaptable but requires more careful operational security around witness management.

### 5. Post-Quantum Readiness

| Property | KERI | KELS |
|----------|------|------|
| Pre-rotation hash commitment | SHA-256 or Blake3 (quantum-resistant) | Blake3-256 (quantum-resistant) |
| Signature algorithm | Configurable (Ed25519, secp256k1, etc.) | ML-DSA-65/87 (192/256-bit post-quantum, FIPS 204) for infrastructure; P-256/ML-DSA-65/ML-DSA-87 supported for mobile clients |
| Cryptographic agility | CESR code tables allow algorithm migration | CESR with Blake3; supports mixed algorithms (e.g., P-256 signing + ML-DSA-65 recovery) with algorithm upgrade via rotation |
| Forward secrecy | Implementation-dependent | ML-KEM-768/1024 ephemeral key exchange provides per-session forward secrecy |
| Key exchange | Implementation-dependent | ML-KEM-768/1024 (FIPS 203, post-quantum) |

**Analysis:** Both protocols benefit from pre-rotation's quantum resistance for commitment chains — even a quantum adversary cannot derive the next key from its hash. KELS now uses ML-DSA-65 or ML-DSA-87 (FIPS 204, 192/256-bit post-quantum security, configurable via `NEXT_SIGNING_ALGORITHM` / `NEXT_RECOVERY_ALGORITHM`) for all infrastructure identities (registries, gossip nodes), with ML-KEM-1024 (FIPS 203) for gossip transport key exchange. The core service accepts P-256, ML-DSA-65, and ML-DSA-87 KELs, supporting mobile clients during the transition period. The key provider supports mixed algorithms and algorithm upgrade via rotation, enabling gradual migration.

KERI has broader cryptographic agility via CESR code tables that can accommodate new algorithms. KELS targets specific post-quantum algorithms (ML-DSA-65/87, ML-KEM-768/1024) chosen for hardware availability — Apple's Secure Enclave supports ML-DSA-65 and ML-DSA-87 but not ML-DSA-44, making ML-DSA-65 the practical floor for consumer device compatibility.

**2026 consideration:** KELS has completed its post-quantum migration for infrastructure, using FIPS 203/204 algorithms with hardware support from Apple Secure Enclave (iOS 26+), Thales Luna HSMs, and AWS KMS. KERI's algorithm agility theoretically allows any PQ algorithm, but without a specific implementation, the migration timeline is less clear. For the hash-based pre-rotation commitment — the most critical quantum-resistance property — both protocols are already prepared.

### 6. Verification Model

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

### 7. Credential Ecosystem

| Property | KERI | KELS |
|----------|------|------|
| Credential framework | ACDC (Authentic Chained Data Containers) | kels-creds (see [design](design/creds.md)) |
| Credential issuance/revocation | TELs (Transaction Event Logs) with registry | Policy-based: endorsers anchor credential SAID per policy; poisoning (anchor poison hash) replaces revocation |
| Credential exchange | IPEX (Issuance and Presentation Exchange) | kels-exchange: ESSR authenticated encryption + IPEX-style messaging + mail service |
| Compacted disclosure | Graduated disclosure (compact, partial, full) | Schema-aware path expression DSL (canonical, compacted, expanded) |
| Credential chaining | ACDC edge sections link credentials in directed graphs | SelfAddressed edges with graduated disclosure (schema, credential, policy) + compacted policy matching |
| Schema enforcement | JSON Schema + ACDC rules sections | SelfAddressed schema referenced by SAID; closed-schema validation with typed fields |

**Analysis:** KERI's ACDC framework remains more mature, with TELs providing a dedicated append-only log for credential state. KELS takes a leaner approach with kels-creds + kels-policy: credentials are purely computational (no separate storage or event log), with endorsement expressed as anchors in interaction events across multiple endorser KELs per a composable policy. Poisoning replaces revocation — an endorser (or authorized admin per a poison expression) anchors a domain-separated Blake3 hash of the credential SAID to withdraw endorsement. Policies define the trust structure: threshold ("2-of-3 must endorse"), weighted ("board members with weight >= 5"), delegation ("any service delegated by this HSM"), and nested composition via policy references. Poisoning semantics are controlled by two mutually exclusive optional fields: `poison` (a DSL expression defining who can poison — when satisfied, the policy is killed) and `immune` (no poison checks). By default (neither set), any endorser can soft-poison (their endorsement doesn't count toward the threshold).

Compacted disclosure uses a schema-aware path expression DSL that maps naturally to FFI (`*const c_char`) — only fields the schema marks as `compactable: true` are compacted/expanded, preventing blind expansion of SAID-like strings in non-compactable fields. Edge types are themselves SelfAddressed and compactable, enabling anti-correlation properties similar to ACDC's partial disclosure — a holder can prove an edge exists without revealing the referenced credential's policy or SAID. Edge verification uses **policy compaction** — the edge stores a compacted policy SAID (delegates stripped), and verification compacts the presented credential's policy to check for a match. This means edges don't need updating when delegated services rotate.

The key architectural difference: ACDC credentials are immutable data objects whose issuance/revocation state is tracked by TELs (separate append-only event logs — a management TEL per registry and a VC TEL per credential), while kels-creds credentials are stateless computational objects verified against KEL anchors via policy evaluation across multiple endorser KELs. This avoids additional infrastructure but means credential state is derived rather than directly queryable. One should likely be verifying anchors on use of a credential in a zero-trust architecture, anyway.

kels-exchange completes the credential exchange stack with three components: (1) **ESSR authenticated encryption** (Encrypt-Sender-Sign-Receiver) providing four unforgeability properties (TUF-PTXT, TUF-CTXT, RUF-PTXT, RUF-CTXT) via ML-KEM key encapsulation + AES-GCM-256 + ML-DSA signatures, (2) **IPEX-style credential exchange messaging** (Apply/Offer/Agree/Grant/Admit/Reject) with chained, self-addressed exchange messages forming cryptographic threads, and (3) a **mail service** for encrypted message delivery with rate limiting, storage caps, blob integrity verification, and gossip-based metadata replication.

**2026 consideration:** Verifiable credential adoption is accelerating (eIDAS 2.0, mDL, OpenID4VC). KERI's integrated credential stack is more battle-tested for production deployments. kels-creds + kels-policy + kels-exchange closes the feature gap with a simpler model — no TELs, no registrars — trading ecosystem maturity for architectural simplicity, a smaller attack surface, expressive multi-party trust policies, and post-quantum authenticated encryption for credential exchange.

### 8. Multi-Signature and Threshold Control

| Property | KERI | KELS |
|----------|------|------|
| Multi-sig signing | Native weighted thresholds (`"kt"`: `"1/2,1/2,1/2"`) | Single signing key per event |
| Multi-sig rotation | Threshold of next key digests (`"nt"`, `"n"`) | Single rotation hash commitment |
| Threshold structures | Fractionally weighted, nested groups | Threshold, weighted, nested groups, delegation via kels-policy DSL |
| Organizational key governance | Multiple keyholders with quorum requirements | Single keyholder per KEL; kels-policy for multi-party governance; federation voting for infrastructure |
| Recovery signatures | Implementation-dependent | Dual signature (rotation key + recovery key) required |

**Analysis:** KERI's multi-sig support is deeply integrated via the `Tholder` (threshold holder). A KERI identifier can require, for example, 2-of-3 signatures from weighted keyholders for signing and a different 3-of-5 threshold for rotation. The `Tholder` accepts fractional weights on keys (e.g., `"1/2,1/2,1/2"` — three keys each with weight 1/2, requiring any two). This maps directly to organizational governance: a corporate identifier might require two officers to sign but three board members to rotate keys.

KELS takes a fundamentally different approach: each KEL has a single signing key, a single rotation commitment, and a single recovery key. Core KEL verification stays single-key and simple. kels-policy provides multi-party governance at a layer above the KEL through an expressive, composable policy DSL.

#### Tholder vs. Policy: Detailed Comparison

| | KERI Tholder | KELS Policy |
|---|---|---|
| Scope | Per-identifier (embedded in KEL) | Per-credential (travels with credential) |
| Expressiveness | Fractional weights on keys within one identifier | Nested DSL: threshold, weighted, delegation, policy references |
| Key compromise isolation | All keys share one identifier's fate | Each endorser has independent recovery/contest lifecycle |
| Governance changes | Rotation event (changes the identifier's keys) | Issue new credential with new policy |
| Delegation | Separate mechanism (delegated rotation requires delegator approval) | First-class `delegate(DELEGATOR, DELEGATE)` node in the DSL |
| Revocation/withdrawal | TEL-based (separate append-only log) | Poisoning with soft/hard/immune modes and admin-controlled poison expressions |
| Verification cost | One KEL replay (efficient) | N KEL replays, one per endorser (more expensive) |
| Composability | Nested weighted groups within one identifier | Recursive across identities (policies reference other policies by SAID) |
| Fleet scaling | ACDC edge `"o"` operator `DI2I` (Delegated-Issuee-to-Issuee) reserved but not yet implemented (as of KERIpy `49fb6fb`) | Policy compaction: edges match on trust structure without pinning specific delegates |

**Composability and flexibility.** KERI's `Tholder` supports fractional weights on keys and nested threshold groups within a single identifier — it can express hierarchical governance structures like "2-of-(group-A-or-group-B)." However, all keys live within one identifier's KEL, and the `Tholder` cannot reference external identifiers, express delegation relationships, or compose across organizational boundaries.

KELS's policy DSL operates at a different level, composing across independent identities rather than keys within one identity:

- **Cross-identity nesting:** `threshold(2, [endorse(A), weighted(3, [endorse(B):2, endorse(C):1]), policy(SAID)])` — a threshold where A, B, C are independent KEL prefixes (each with their own key lifecycle) and one child is an entire sub-policy resolved by SAID.
- **Cross-identity composition:** Policies reference independent KEL prefixes, each with their own key lifecycle, recovery procedures, and contest mechanisms. A compromised endorser recovers independently without affecting others.
- **Delegation as a node type:** `delegate(HSM_PREFIX, SERVICE_PREFIX)` expresses "this service, delegated by this HSM, must endorse" as a first-class concept in the trust expression — not a separate mechanism layered on top.
- **Policy references:** `policy(SAID)` enables reuse and composition of policies across credentials. An organization can define a "board approval" policy once and reference it from many credentials.
- **Policy compaction:** `delegate(HSM, SERVICE)` compacts to `delegate(HSM)` — edges match on trust *structure* (any service delegated by this HSM) without pinning specific delegates, enabling fleet scaling without edge updates.
- **Admin-controlled poisoning:** A separate DSL expression (`poison` field) governs who can kill the credential, independent of who endorses it. KERI has no equivalent — revocation is TEL-based and not expressible as a threshold policy.

As a concrete example, KERI cannot express "2-of-3 endorsers, where one endorser is any service delegated by this HSM, and revocation requires 2-of-2 admins" in a single identifier's threshold structure. KELS can express this in a single policy document:

```
expression: threshold(2, [endorse(A), delegate(HSM, SERVICE), endorse(C)])
poison:     threshold(2, [endorse(ADMIN_1), endorse(ADMIN_2)])
```

**The fundamental architectural difference:** KERI couples governance to identity — the identifier *is* a 2-of-3 multisig. KELS decouples them — three separate identities *collectively endorse* a credential per a policy. KERI's approach is more efficient (one KEL replay). KELS's approach gives each endorser independent key lifecycle — if one endorser's key is compromised, they recover independently via `rec`/`cnt` without affecting the other endorsers or the policy itself. In KERI, a compromised key in a multisig set requires a rotation of the entire identifier.

KELS's dual-signature requirement for recovery events (rotation key + recovery key) is a form of 2-of-2 multi-sig, but it serves a specific security purpose (proving possession of both key tiers) rather than general governance.

**2026 consideration:** As organizational key management matures, the ability to express governance policies directly in the identifier (KERI's approach) versus at a higher layer (KELS's kels-policy approach) becomes a meaningful architectural decision. KERI's approach integrates multi-sig into KEL verification — a single KEL replay checks all thresholds. KELS's approach requires verifying multiple KELs (one per endorser in the policy) but keeps core verification simple and makes governance independently evolvable. KELS's recursive policy composition and policy compaction have no KERI equivalent — they enable trust structures that span organizational boundaries and scale with fleet operations in ways that a single identifier's key threshold cannot.

### 9. Standards and Interoperability

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

### 10. Community and Ecosystem Maturity

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

**2026 consideration:** For risk-averse organizations evaluating DKMI infrastructure, community size, implementation diversity, and production references are often deciding factors regardless of technical merit. KERI's ecosystem maturity provides lower perceived risk. KELS's technical advantages (type-safe verification, deterministic recovery, gossip replication) may be more compelling but require more due diligence to adopt.

### 11. Privacy Properties

| Property | KERI | KELS |
|----------|------|------|
| Prefix derivation | Prefix = inception SAID (derived from inception content) | Prefix derived separately (both `said` and `prefix` blanked before hashing) |
| Identifier correlation | SAID reveals inception content hash; prefix = SAID | Prefix and SAID are different values; harder to correlate naked SAIDs to KEL owners |
| Compacted disclosure | ACDC graduated disclosure (compact → partial → full) | kels-creds path expression DSL (compact → compacted → full) |
| Unlinkable presentations | Possible via ACDC compact disclosure | Compactable edges hide referenced credentials and issuers |
| KEL privacy | KEL is public (ambient verifiability) | KEL is public (ambient verifiability) |
| Witness/node privacy | Witness addresses in KEL (`"b"` field) | Peer set managed by registry; not in KEL |

**Analysis:** Both protocols treat KELs as public, verifiable data — ambient verifiability is a core design principle of both. Neither provides KEL confidentiality.

KELS's prefix derivation offers a subtle privacy advantage: KERI computes a single hash (blanking both fields in one pass) and uses it as both prefix and SAID, so they are identical. KELS computes them sequentially — prefix first (both fields blanked), then SAID (only `said` blanked, prefix already populated) — producing two distinct values. A naked SAID seen in an anchor or external reference cannot be trivially mapped to a KEL prefix without additional context. In KERI, any reference to the inception SAID immediately identifies the KEL.

KERI's ACDC graduated disclosure allows credentials to be presented in compact form (just the SAID), partial form (selected fields), or full form. kels-creds provides comparable functionality via recursive compaction of SelfAddressed fields and a path expression DSL for compacted disclosure — fields are either expanded (visible) or compacted (replaced by their SAID). Both approaches enable privacy-preserving verification flows; ACDC is more mature while kels-creds is architecturally simpler. Note: this is compaction-based disclosure, not zero-knowledge selective disclosure — the holder chooses which fields to expand, but cannot make predicate proofs about compacted fields.

KERI exposes witness addresses in the KEL itself (`"b"` field), creating infrastructure metadata in the public record. KELS keeps peer set management in the registry layer, separate from individual KELs.

**2026 consideration:** Privacy regulations (GDPR, state privacy laws) increasingly constrain how identity systems handle personal data. Both KERI's ACDC graduated disclosure and kels-creds's path-based compacted disclosure support data minimization for privacy-compliant credential presentation. For pure key management (no credentials), KELS has a privacy advantage: systems that maintain logs of event SAIDs (e.g., audit trails, anchor records) cannot correlate those SAIDs back to a specific identity without the full event content. In KERI, where the prefix equals the inception SAID, any logged SAID from the inception event immediately identifies the KEL owner.

### 12. Delegation Model

| Property | KERI | KELS |
|----------|------|------|
| Delegation inception | Delegated inception (`dip`) requires delegator approval seal | Delegated inception (`dip`) accepted if structurally valid |
| Delegation rotation | Delegated rotation (`drt`) requires delegator approval | No delegated rotation event type |
| Delegation trust verification | In-protocol (delegator must anchor approval in their KEL) | Service-level: deferred to consumers. Credential-level: kels-policy `delegate()` DSL node verifies delegation trust chains |
| Delegation revocation | Delegator can refuse future rotations | Consumer-defined |
| Delegation depth | Multi-level (A delegates to B, B delegates to C) | Structurally possible; kels-policy `delegate(DELEGATOR, DELEGATE)` verifies one level per node; nested policies can compose multi-level chains |
| Credential-level delegation | ACDC edge operator `DI2I` reserved but not yet implemented (as of KERIpy `49fb6fb`); `I2I` and `NI2I` operators handle non-delegated issuee constraints | kels-policy `delegate()` node with policy compaction for fleet scaling |
| Cooperative delegation | Delegator and delegate coordinate via interaction events | No built-in coordination protocol |

**Analysis:** KERI's delegation model is deeply integrated into the protocol. When identifier B is delegated from identifier A, the delegator (A) must anchor an approval seal in their own KEL for every delegated establishment event (inception and rotation). This creates a cryptographically verifiable chain of authority: verifying B's KEL requires also verifying A's KEL and confirming the approval seals. The delegator retains ongoing control — they can refuse to approve future rotations, effectively revoking the delegation.

KELS takes a layered approach to delegation. At the service level, the `dip` (delegated inception) event includes a `delegating_prefix` field, but the KELS service itself does not verify the delegation relationship — any structurally valid KEL starting with `dip` is accepted. This is a deliberate design choice: "Delegation trust is NOT verified by the KELS service. KELS accepts any valid KEL starting with `icp` or `dip`. Consumers verify delegation trust chains when needed."

However, at the credential level, kels-policy provides full delegation verification via the `delegate(DELEGATOR, DELEGATE)` DSL node. When a policy includes a `delegate` node, the evaluator performs three checks: (1) the delegate's KEL inception is a `dip` with the delegator as delegating prefix, (2) the delegator's KEL is cryptographically verified, and (3) the delegator's KEL anchors the delegate's prefix. This means delegation trust is verified automatically during policy evaluation without consumers needing to implement it independently. Policy compaction strips the specific delegate from `delegate(DELEGATOR, DELEGATE)` to `delegate(DELEGATOR)`, enabling edges to express "any delegate of this authority" without pinning a specific service.

**2026 consideration:** Delegation is critical for organizational hierarchies (root CA → intermediate CA → end entity, analogous patterns). KERI's in-protocol delegation verification provides stronger guarantees out of the box for all KEL operations. KELS's layered approach defers delegation verification at the service level but provides it automatically at the credential level via kels-creds, covering the most common use case (verifying that a credential issuer is properly delegated) without requiring every consumer to implement delegation checking independently.

### 13. Offline and Airgapped Operation

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

KELS requires submission to any reachable gossip node (or directly to the KELS service). Once submitted, gossip propagation and anti-entropy ensure network-wide distribution without further controller action. The gossip mesh is more resilient to partial outages — events propagate through whatever paths are available, and anti-entropy repairs gaps after partitions heal.

For airgapped high-security deployments (e.g., root key ceremonies), both protocols support the pattern of: generate keys offline → create inception/rotation event offline → transport signed event to online system → submit. KELS's `KeyEventBuilder` and `FileKelStore` (NDJSON file-based storage) provide explicit tooling for this workflow. KERI's equivalent uses the `Hab` (Habitat) with local-only configuration.

**2026 consideration:** Airgapped key management is increasingly mandated for high-value identifiers (CA roots, national identity anchors, critical infrastructure). Both protocols support the core workflow. KELS's gossip-based propagation provides better resilience for environments with intermittent connectivity (field deployments, satellite-linked infrastructure, disaster recovery scenarios). KERI's witness model is simpler to reason about for compliance auditors who need to verify that an event was properly receipted.

### 14. Device and Platform Integration

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

## DKMI Usage Context Recommendations

### 1. Personal/Consumer Identity (e.g., digital wallets, personal credentials)

**Recommended: Context-dependent**

- **For mobile wallets with hardware-backed keys**: **KELS**. Native Swift client with Secure Enclave integration provides on-device signing without cloud agent dependency. ML-DSA-65/87 support aligns with Apple's Secure Enclave PQ capabilities. A single KELS node can serve as the backend — no federation required for personal use.
- **For fully decentralized, infrastructure-independent identity**: **KERI**. Self-certifying identifiers with controller-selected witnesses and OOBI discovery require no specific backend infrastructure. The social accountability model for duplicity aligns with how personal reputation works.

KERI's browser-based client (signify-ts) works well for web applications but lacks native mobile SDK support or hardware key integration. KELS's native device support is a significant advantage as digital wallets (eIDAS 2.0 EUDI Wallet, Apple Wallet) become primary credential containers.

### 2. Enterprise/Organizational Identity (e.g., corporate PKI replacement, B2B trust)

**Recommended: KELS**

Enterprises need:
- **Deterministic recovery procedures** — KELS's three-tier key hierarchy and explicit recovery/contest events map directly to incident response runbooks.
- **Auditable divergence handling** — Divergence stored in the KEL provides a forensic record without requiring external watcher infrastructure.
- **Controlled federation** — Compile-time trust anchors and multi-party voting align with enterprise change management (no unilateral infrastructure changes).
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
- **Total compromise response** — The `cnt` (contest) mechanism provides a deterministic response to the worst case. In DeFi, an ambiguous identity state can mean unbounded financial loss.
- **Zero-trust verification** — KELS's explicit "DB cannot be trusted" model and type-safe verification align with the assumption that any component may be compromised.
- **Forensic preservation** — Contest events preserve all divergent branches for dispute resolution.

**Caveat:** KELS's algorithm choices (ML-DSA-65/87 for infrastructure, P-256 for mobile clients) are not optimal for blockchain interoperability (where Ed25519 and secp256k1 dominate). KERI's algorithm flexibility is an advantage here.

### 5. Government / Regulated Identity (e.g., eIDAS, national identity)

**Recommended: Context-dependent**

- **For closed federations** (e.g., inter-agency trust within a government): **KELS**. The compile-time trust anchors, multi-party voting, and deterministic recovery map well to regulated environments with defined participants and formal change control processes.
- **For open ecosystems** (e.g., citizen-facing credentials): **KERI**. The decentralized trust model and witness flexibility better serve environments where the credential holder must be able to verify against any infrastructure.

KELS has completed its post-quantum signature migration for infrastructure (ML-DSA-65/87, FIPS 204). KERI still needs post-quantum signature migration. For government use cases with typical 15-30 year data protection requirements, KELS's PQ support is a significant advantage.

### 6. Supply Chain Provenance / Verifiable Data

**Recommended: KELS**

Supply chain integrity requires:
- **Anchor verification** — KELS's inline anchor checking during verification (single pass) is well-suited to verifying that specific data items are anchored in a KEL.
- **Divergence as signal** — A divergent supply chain identifier is a meaningful security event that should be visible and actionable, not just a reputation problem.
- **Federation model** — Supply chains naturally involve a known set of participants, mapping well to KELS's registry federation.

### 7. Peer-to-Peer / Censorship-Resistant Communication

**Recommended: KERI**

P2P contexts need:
- **No infrastructure dependency** — KERI identifiers are self-certifying without any registry or federation.
- **OOBI flexibility** — Discovery via out-of-band introductions works in environments where centralized discovery is unavailable or undesirable.
- **Controller autonomy** — Witness selection by the controller, not by a federation, preserves user sovereignty.

KELS's federation model introduces infrastructure dependencies that conflict with censorship-resistance goals.

### 8. Multi-Party Coordination / DAOs / Governance

**Recommended: KELS**

Multi-party governance aligns naturally with KELS's design:
- **kels-policy** provides an expressive policy DSL (`endorse`, `delegate`, `threshold`, `weighted`, nested `policy` references) for multi-party approval verified against KEL anchors, with soft/hard/immune poisoning and admin-controlled poison expressions.
- **Multi-party voting** for infrastructure changes mirrors governance voting patterns.
- **Deterministic divergence resolution** provides clear rules when parties disagree.
- **Federation model** maps to governance structures with defined membership.

---

## Summary Matrix

| Usage Context | Recommended | Key Deciding Factor |
|---|---|---|
| Personal identity (mobile) | KELS | Native device client, Secure Enclave, no cloud agent |
| Personal identity (web/decentralized) | KERI | Decentralized trust, no infrastructure dependency |
| Enterprise identity | KELS | Deterministic recovery, auditable divergence, controlled federation |
| IoT / device identity | KELS | Gossip replication, automated recovery, HSM integration |
| DeFi / high-value | KELS | Total compromise response, zero-trust verification |
| Government (closed) | KELS | Compile-time trust, multi-party voting, formal recovery |
| Government (open) | KERI | Decentralized trust, flexible infrastructure |
| Supply chain | KELS | Inline anchor verification, federation model |
| P2P / censorship-resistant | KERI | No infrastructure dependency, controller autonomy |
| Multi-party governance | KELS | Multi-party voting, deterministic divergence resolution |

---

## Deployment Ease

### KERI

**Initial setup:** Moderate in theory, unclear in practice. A minimal KERI deployment requires running a controller agent (e.g., KERIA) and at least one witness. KERIA provides a docker-compose configuration with a single service exposing three ports (admin, HTTP, boot), and references demo witness configurations in its startup scripts. KERIpy's README covers library installation and CLI usage but provides no multi-component deployment documentation or docker-compose.

However, the KERI ecosystem provides no guidance for deploying the operational infrastructure that distinguishes KERI from a plain KEL system. Watchers (duplicity detection), jurors (duplicity evaluation), and judges (trust decisions) — the roles that form KERI's social trust layer — do not appear to have standalone deployable implementations in the WebOfTrust GitHub organization. The KERI specification defines these roles conceptually, but a developer wanting to stand up a full KERI environment with duplicity detection faces significant uncertainty about what to deploy and how, or whether deployable implementations exist at all. No Kubernetes deployment configurations were found for any KERI component.

**Scaling:** Adding witnesses is straightforward — deploy the service and update the controller's witness list via a rotation event. No recompilation or coordinated redeployment required. Watchers (for duplicity detection) are described as optional infrastructure that can be added incrementally, but the absence of deployable watcher implementations makes this theoretical.

**Bootstrap chicken-and-egg:** Minimal. Identifiers are self-certifying from inception, so there is no circular dependency between infrastructure components. A controller can create an identifier before any witnesses exist and add witnesses later.

**Upgrades:** Rolling upgrades are feasible since witnesses are independent. Algorithm migration happens per-identifier via rotation events with new key types.

### KELS

**Initial setup:** Simple for a single node, complex for the full federation. A single KELS node (kels service + PostgreSQL) provides the full KEL API — inception, rotation, interaction, recovery, contest, decommission, divergence handling — without gossip or registries. This is comparable in complexity to any single-service web application. You can scale a single kels deployment horizontally by adding redis.

For the full federation with gossip replication, the deployment is more involved but fully automated, tested and reproducible (`make test-federation` deploys/tests everything in ~35 minutes; `make deploy-fresh-federation` deploys without tests in ~10 minutes). The full federation deployment requires:
1. Deploy 3 registries in standalone mode (each running 4 services: registry, identity, PostgreSQL, Redis)
2. Collect prefixes from each registry
3. Recompile all binaries with collected prefixes as compile-time trust anchors
4. Redeploy registries in federation mode (Raft cluster forms)
5. Deploy gossip nodes (each running 5 services)
6. Propose and vote (minimum 3 votes) to authorize each gossip node
7. Restart gossip nodes to pick up authorization

This two-phase deployment (standalone → collect prefixes → recompile → federated) is inherent to the compile-time trust anchor design. It cannot be simplified without changing the security model.

**Scaling:** Adding gossip nodes requires multi-party voting (minimum 3 registry votes). Adding a new registry requires recompiling and redeploying all binaries network-wide, plus waiting for acceptable client deployment coverage before activating the new member. This is a significant operational event.

**Bootstrap chicken-and-egg:** Significant. Registry prefixes are not known until identity generation, but must be compiled into all binaries. This creates a mandatory two-phase deployment that cannot be automated into a single step.

**Upgrades:** Coordinated. Any change to the trusted registry set requires full recompilation and redeployment. Redis ACLs are per-service with least-privilege command sets, which is excellent for security but adds configuration surface.

### Comparison

| Aspect | KERI | KELS |
|--------|------|------|
| Minimum services for a deployment | 2-3 (agent + witnesses) | 1 (kels) + PostgreSQL; scales horizontally with Redis |
| Full architecture deployable | No (watchers/jurors/judges lack implementations) | Yes (`make test-federation` deploys everything) |
| Time to first identifier | Minutes (without duplicity detection) | ~2.5 minutes (single node, with divergence, reconciliation, and contest features); ~10 minutes (full federation deploy); ~35 minutes (full federation + tests) |
| Adding infrastructure nodes | Rotation event (seconds) | Multi-party vote (minutes) |
| Trusting a participant (identifier) | OOBI resolution (seconds) | Fetch KEL + verify (seconds) |
| Adding federation infrastructure | N/A (no federated infrastructure layer) | Recompile + redeploy all binaries (hours to days) |
| Configuration surface | Low (agent config + witness URLs) | High (compile-time vars, runtime env, Redis ACLs, Raft config) |
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
- **Peer management:** Proposing and voting on peers requires coordination across registry operators. Minimum 3 operators must act for any peer change.
- **Monitoring:** Divergence is visible in the KEL and propagated via gossip — monitoring is built into the data model. Anti-entropy runs every 10 seconds by default, providing continuous consistency checking.
- **Backup/recovery:** PostgreSQL databases are the primary data store. HSM key material must be backed up separately (PVC for mock HSM, native persistence for real HSMs). Redis is reconstructable from PostgreSQL on restart (cache + operational state rebuilt via anti-entropy).
- **Federation health:** Raft cluster health must be monitored. Leader election failures, log replication lag, and split-brain scenarios are possible failure modes.

### Incident Response

| Scenario | KERI | KELS |
|----------|------|------|
| Signing key compromised | Rotate immediately (race with adversary) | Submit `rec` event (no race — requires recovery key) |
| Rotation key compromised | Rotate immediately (race with adversary) | Submit `rec` event (dual-signed, no race) |
| Total key compromise | No formal protocol; social resolution | Submit `cnt` to permanently freeze; deterministic |
| Witness/node compromise | Replace witness, rotate witness list | Propose removal via multi-party vote |
| Infrastructure outage | Witness redundancy; degrade gracefully | Gossip mesh self-heals; anti-entropy repairs gaps |
| Database corruption | Rebuild from witnesses/peers | Rebuild from gossip peers; verify from inception |

### Operational Burden Assessment

**KERI** is operationally lighter but places more burden on the controller. The controller must manage their own key material, witness relationships, and recovery procedures. There is less infrastructure to operate but more individual responsibility.

**KELS** is operationally heavier but distributes responsibility across the federation. Automated key rotation, built-in anti-entropy, and protocol-defined recovery procedures reduce individual burden at the cost of coordination overhead. The multi-party voting requirement for infrastructure changes is both a security feature and an operational bottleneck — intentionally so.

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

For DKMI infrastructure that processes high event volumes, enforces security invariants automatically, and must resist sophisticated attacks, Rust's compile-time guarantees provide material security benefits. For client-side tooling, credential management, and protocol experimentation, Python's accessibility and iteration speed are more valuable.

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
| `EventKind` | Enum of event types |
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
  "kind": "kels/v1/rot",
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
KelDecommissioned, ContestRequired, DivergenceDetected
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
- Self-documenting — type names, field names, and method names read as English descriptions of their purpose. A developer reading `KelVerifier::verify_chain_event()` or `EventKind::requires_dual_signature()` understands the operation without consulting a glossary.
- Standard conventions — follows Rust community naming (traits named for capabilities, enums named for the domain, methods named as verb phrases). No project-specific lexicon to learn.
- Explicit over compact — `rotation_hash` is longer than `"n"` but communicates its meaning without context. `recovery_key` is unambiguous where `"br"` requires documentation.
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
- The cryptographer can read the type definitions and understand the security model directly. `KelVerifier`, `KelVerification`, `recovery_key`, `rotation_hash`, `requires_dual_signature()` — these terms map to concepts they already know.
- Rust itself is a learning curve if they are not already proficient, but the *domain naming* does not add to it. A Rust-literate cryptographer can read KELS types on day one.
- The three-tier key hierarchy (signing, rotation, recovery) is documented in the type system: `public_key`, `rotation_hash`, `recovery_key`, `recovery_hash` are all explicit fields on `KeyEvent`.
- Infrastructure concepts (gossip, federation, Raft) use standard distributed systems terminology. `HyParView` and `PlumTree` are published protocols with their own literature.
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
- The cryptographer dives into divergence handling, recovery semantics, and the merge transaction. These are complex but documented in the type system — `KelMergeResult` has variants `Accepted`, `Recovered`, `Contested`, `Diverged`, `RecoverRequired`, `ContestRequired` that enumerate the state machine explicitly.
- The gossip protocol (HyParView + PlumTree) and federation model (Raft + multi-party voting) are standard distributed systems patterns with extensive external literature.
- The verification model's advisory locking and TOCTOU prevention are sophisticated but follow established database patterns.

**KELS has fewer novel concepts:** the event types, key hierarchy, divergence state machine, gossip protocol, and federation model are the core set. Each uses descriptive naming that connects to its external literature.

### Auditability

For a security audit, the naming difference is material:

**KERIpy audit challenge:** An auditor must first build a mental translation layer between KERIpy's vocabulary and standard cryptographic concepts. When reviewing `Kevery.process()` for verification correctness, they must hold in mind that `kever.verfers` means "verification keys for this identifier" and `siger.index` means "which key in the multi-sig set signed this." Errors in this mental translation can cause missed vulnerabilities.

**KELS audit advantage:** An auditor can read `KelVerifier::verify_signatures(signed_event, public_key)` and immediately assess whether the signature verification is correct relative to the claimed key. The type signature communicates intent. The `KelVerification` token pattern means the auditor can verify that all security-sensitive code paths require proof of verification by tracing type usage — no runtime behavior analysis needed.

### Summary

| Factor | KERIpy | KELS |
|--------|--------|------|
| Domain vocabulary to memorize | ~30+ project-specific terms | ~5 (KEL, SAID, CESR, prefix, serial) |
| Event field readability | Single-letter (`"i"`, `"s"`, `"n"`, `"b"`) | Full words (`"prefix"`, `"serial"`, `"rotationHash"`) |
| Infrastructure roles to understand | 7+ (controller, witness, watcher, juror, judge, registrar, validator) | 3 (registry, gossip node, identity service) |
| Naming convention | Project-specific (`-ery`, `-er` suffixes) | Standard Rust / English |
| External literature alignment | Low — terms are KERI-specific coinages | High — uses published protocol names and standard crypto terms |
| Time to first code review (domain-experienced) | 2-3 weeks | 1 week (Rust-proficient) |
| Security audit readability | Requires glossary translation layer | Self-documenting types and methods |

---

## Conclusion

KERI and KELS represent different points in the DKMI design space. KERI optimizes for decentralization, controller autonomy, and a rich taxonomy of participant roles (witnesses, watchers, jurors, judges), making it ideal for open ecosystems where no single party controls the infrastructure and where social/governance trust layers are appropriate. KELS optimizes for operational rigor, deterministic security, and automated trust decisions, making it ideal for environments with defined participants and high-assurance requirements.

The most significant differentiator is divergence handling: KERI treats it as an external detection problem resolved through its layered participant model (watchers detect duplicity, jurors evaluate evidence, judges render verdicts), while KELS treats it as a protocol state with cryptographic resolution (`rec`/`cnt`). In 2026's zero-trust landscape, where automated trust decisions are the norm and human-in-the-loop is a liability for infrastructure, KELS's approach provides stronger security guarantees for most organizational and infrastructure use cases. KERI's richer social trust layer remains the better choice where human governance, decentralization, and individual sovereignty are paramount. However, the deployability gap is notable: KERI's watcher, juror, and judge roles lack standalone deployable implementations, while KELS ships a complete, reproducible environment behind a single command.

KELS's three-tier key hierarchy (signing, rotation, recovery) provides a stronger recovery posture than KERI's two-tier model (signing + pre-rotated next). KELS eliminates the race condition inherent in KERI's rotation-key compromise scenario by requiring dual signatures (rotation + recovery) for recovery events, and provides a deterministic total-compromise response (`cnt`) that KERI lacks. On multi-party governance, KERI embeds weighted multi-sig thresholds directly in the identifier, while KELS keeps core KELs single-key and provides governance at a higher layer via kels-policy — an expressive policy DSL supporting `endorse`, `delegate`, `threshold`, `weighted`, and nested `policy` references, with soft/hard/immune poisoning and admin-controlled poison expressions. Policy compaction enables edges to match on trust structure without pinning specific delegates. Both approaches can express equivalent policies; the difference is where verification complexity lives.

KELS's verification model enforces security invariants at the type level: the `KelVerification` token (private fields, no public constructor, obtainable only through `KelVerifier::into_verification()`) guarantees at compile time that security decisions cannot be made on unverified data. Advisory locking through verify+write eliminates TOCTOU vulnerabilities. KERI's verification semantics are specified but enforcement rigor is implementation-dependent.

The credential ecosystems are converging. KERI's ACDC framework with TELs is more mature, but kels-creds + kels-policy + kels-exchange provides a leaner alternative — schema-aware compaction, graduated disclosure via a path expression DSL, recursive edge verification with compacted policy matching, composable multi-party trust policies with poisoning semantics, ESSR post-quantum authenticated encryption for credential exchange, and no separate registry infrastructure. The remaining functional gap is primarily ecosystem maturity rather than missing capabilities.

The two protocols also differ on delegation. KERI verifies delegation trust in-protocol — delegated establishment events require the delegator to anchor approval seals in their own KEL. KELS defers delegation verification at the service level (accepting any structurally valid `dip`) but provides automatic delegation trust verification at the credential level via the kels-policy `delegate(DELEGATOR, DELEGATE)` DSL node, which verifies the delegation chain during policy evaluation. Policy compaction strips the specific delegate, enabling edges to express "any delegate of this authority" — supporting fleet scaling (HSM-backed service delegates to rotating software-key services) without edge updates.

KELS's prefix derivation provides a privacy advantage absent from KERI: because the prefix and SAID are computed sequentially (producing distinct values), event SAIDs in logs or anchor records cannot be correlated back to an identity without the full event. In KERI, prefix equals inception SAID, making any logged inception SAID immediately identifying.

Both protocols support offline and airgapped key operations — pre-rotation commitments are computed locally and events can be signed without network access. The difference is in reconnection: KERI requires submission to enough witnesses to meet the receipt threshold (a liveness dependency), while KELS requires submission to any reachable gossip node, after which gossip propagation and anti-entropy handle distribution without further controller action.

The terminology gap compounds the architectural differences. KERIpy's custom vocabulary (~30+ project-specific terms like `Kevery`, `Habery`, `Serder`, `Siger`) creates a significant onboarding barrier that slows auditing, limits the contributor pool, and increases the risk of misunderstanding during security review. KELS's conventional naming makes the codebase immediately legible to anyone familiar with cryptography and distributed systems, reducing the distance between "reading the code" and "understanding the security model." For a domain-experienced cryptographer, the estimated time to first meaningful code review is 2-3 weeks for KERIpy (due to vocabulary overhead) versus 1 week for KELS (if Rust-proficient).

The deployment and operational tradeoffs reinforce this split: KERI is lighter to deploy for a minimal setup but lacks reproducible orchestration and deployable implementations of its full architecture. KELS is heavier to deploy in full federation mode but provides a single-node development path (~2.5 minutes to first identifier with divergence, reconciliation, and contest features) and a fully automated federation deployment (~10 minutes without tests, ~35 minutes including integration tests). The language choice (Python vs Rust) mirrors the same tension — accessibility and iteration speed versus compile-time safety guarantees and performance.

Device integration is another differentiator. KELS was designed for hardware-backed keys from the start — the Swift client with Secure Enclave integration, C FFI bindings for cross-language use, HSM-backed service identities (ML-DSA-65/87 via PKCS#11), and an Android SDK on the roadmap reflect this. KERI's client ecosystem is web-first (signify-ts in browsers, signifypy in Python), with no native mobile SDK or hardware key integration. As mobile-first identity wallets become the norm, KELS's native device support and ML-DSA-65 compatibility with Apple Secure Enclave (iOS 26+) provide a clear advantage.

On post-quantum readiness, KELS has completed its infrastructure migration: ML-DSA-65 or ML-DSA-87 (FIPS 204, configurable via `NEXT_SIGNING_ALGORITHM` / `NEXT_RECOVERY_ALGORITHM`) for all infrastructure signing, ML-KEM-768 or ML-KEM-1024 (FIPS 203, auto-negotiated based on peer signing algorithms) for gossip transport key exchange, and support for mixed algorithms with upgrade via rotation. The core service accepts P-256, ML-DSA-65, and ML-DSA-87 KELs, enabling gradual client migration. KERI's broader cryptographic agility theoretically accommodates any PQ algorithm, but without a specific implementation, the migration timeline is less defined. Both protocols' pre-rotation hash commitments are already quantum-resistant.

KELS's roadmap — Android SDK, exhaustive proof of divergence reconciliation, a standards proposal, and a DID method specification — positions it for production readiness and ecosystem participation. kels-policy (multi-party governance DSL with composable trust policies, poisoning, and admin-controlled poison expressions) and kels-exchange (ESSR post-quantum authenticated encryption, IPEX-style credential exchange messaging, and a mail service for encrypted message delivery) are implemented. KERI's head start in standards (IETF Internet-Drafts), community (WebOfTrust, GLEIF vLEI), and multi-implementation diversity remains a significant advantage for risk-averse adopters today.
