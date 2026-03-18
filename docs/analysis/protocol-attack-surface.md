# KELS Protocol Attack Surface

Analysis of attack vectors against the KELS protocol — cryptographic properties, KEL integrity, key management, and event verification. These are inherent to the protocol design, independent of deployment topology.

## Trust Model

The KELS protocol has no central authority. Security rests entirely on cryptographic properties: signatures (ML-DSA-65 or ML-DSA-87 for infrastructure at 192/256-bit post-quantum security; P-256 / ECDSA at 128-bit classical security for mobile clients), content-addressable identifiers (SAID via Blake3-256), and forward commitments (rotation/recovery hash chains). Any valid signed event is accepted regardless of source.

**Assumptions:**
- Clients hold private keys in hardware-backed storage (Secure Enclave, HSM)
- Infrastructure uses ML-DSA-65 or ML-DSA-87 (FIPS 204); the core service accepts P-256, ML-DSA-65, and ML-DSA-87 KELs
- Events are version-qualified (`kels/v1/icp`) for future protocol evolution

## Key Compromise

A controller of an identity has 3 keys to protect. It's advised that clients only be deployed to mobile with hardware-backed keys, or services with HSM-backed keys.

### Key Hierarchy

| Key | Purpose | Exposure |
|-----|---------|----------|
| **Signing** | Signs `ixn` and `rot` events | Active — used for every operation |
| **Rotation** | Pre-committed next key; revealed during rotation, becomes the new signing key | Semi-dormant — only needed for key rotation |
| **Recovery** | Revealed during recovery events; dual-signed with rotation key | Dormant — only needed for emergency recovery |

### Compromise Scenarios

**Signing key compromised:**
- **Attack:** Adversary can sign `ixn` events (anchor arbitrary data) and submit them to any KELS node.
- **Impact:** Limited to interaction events. Cannot rotate keys, cannot take over the identity.
- **Recovery:** Owner rotates signing key (`rot`). If adversary submits conflicting events before rotation propagates, divergence occurs. Owner submits `rec` (requires rotation + recovery key). KEL resumes normally.
- **Detection:** Divergence is detected automatically when events with the same `previous` but different SAIDs appear.

**Rotation key compromised:**
- **Attack:** Adversary can submit a `rot` event (taking over the signing key) and subsequently sign unlimited `ixn` and `rot` events.
- **Impact:** Full control of the signing chain. Adversary can anchor data, rotate keys repeatedly.
- **Recovery:** Owner submits `rec` (requires the pre-compromised rotation key + recovery key, dual-signed). After recovery, adversary events are archived. If the adversary rotated and the owner did not, an extra `rot` is needed post-recovery to escape the compromised key.
- **Detection:** Same as signing key — divergence detection.

**Recovery key compromised (along with rotation key):**
- **Attack:** Adversary has full administrative control — can submit `rec`, `ror`, `dec`, or `cnt` events.
- **Impact:** Total identity compromise. Adversary can recover from owner's recovery attempts.
- **Recovery:** Owner's only recourse is `cnt` (contest), which permanently freezes the KEL. Neither party can add further events. This is the correct outcome when key compromise is total.
- **Detection:** If adversary submits a recovery-revealing event, the merge protocol detects it and marks the KEL as requiring contest.

**Recovery key compromised (without rotation key):**
- **Impact:** Recovery key alone is useless — all recovery-revealing events require dual signatures (rotation + recovery). No action possible without both keys.

## Event Submission Attacks

### Forged Event Injection

**Attack:** Submit events with invalid or forged signatures.
- **Mitigation:** `submit_events` validates all signatures upfront before any merge. Each signature is parsed via `Signature::from_qb64()` and verified during the KEL merge against the public key from the latest establishment event. Invalid signatures cause immediate rejection.

### Dual-Signature Bypass

**Attack:** Submit a recovery-revealing event (`rec`, `ror`, `dec`, `cnt`) with only one signature.
- **Mitigation:** `submit_events` explicitly checks `requires_dual_signature()` and rejects events with fewer than 2 signatures. The merge protocol also verifies both signatures independently.

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
- **Mitigation:** The merge protocol validates that every event's `previous` field references an existing event in the KEL. Missing predecessors cause rejection with "Events not contiguous."

## KEL Merge Exploitation

### Divergence Flooding

**Attack:** With a compromised signing key, submit divergent events to many different KELS nodes simultaneously, hoping to maximize the window where the KEL is frozen.
- **Mitigation:** Gossip propagates both branches of a divergent KEL. All nodes converge on the same divergent state. The owner can submit `rec` to any single node, and recovery propagates via gossip to all nodes.
- **Residual risk:** Window of frozen KEL depends on gossip propagation speed and owner response time.

### Recovery Race

**Attack:** Adversary (who also has the recovery key) races the owner to submit `rec` first.
- **Mitigation:** If the adversary submits a recovery-revealing event, the merge protocol returns `ContestRequired` for non-contest submissions. The owner must `cnt` (contest) instead, which permanently freezes the KEL. This is the correct security outcome — it prevents an attacker with the recovery key from winning a recovery race.

### Re-divergence After Recovery

**Attack:** After the owner recovers, adversary re-submits events at the same generation to re-diverge.
- **Mitigation:** Once a recovery-revealing event exists in a divergent branch, non-contest submissions return `ContestRequired` (only `cnt` is allowed through). This is an important security invariant that prevents recovery battles.

### Contested KEL Bypass

**Attack:** Submit events to a contested (permanently frozen) KEL.
- **Mitigation:** Pre-merge validation checks `is_contested()` and immediately rejects all submissions. A contested KEL is truly permanent — there is no bypass.

### Decommissioned KEL Bypass

**Attack:** Submit events to a decommissioned KEL.
- **Mitigation:** The merge protocol checks for decommission and rejects appends. Only divergence at earlier generations is possible (with a compromised signing key from before decommission), which would still be caught by recovery protection if `dec` was the decommissioning event.

## KEL Verification Bypass Attempts

### Verification Bypass

**Attack:** Submit events that pass structure verification but have broken cryptographic properties.
- **Mitigation:** `KelVerifier` performs all checks in a single forward pass — structure, chaining, SAID integrity, pre-rotation commitments, recovery key commitments, and signature verification are all validated as each event is processed. There is no separate backward pass; forward commitments (rotation hash, recovery hash) are tracked per-branch and verified when the next establishment event reveals the committed key.

### Pre-rotation Commitment Violation

**Attack:** Submit a rotation event whose public key doesn't match the rotation hash committed in the previous establishment event.
- **Mitigation:** The verifier tracks `pending_rotation_hash` per branch and verifies `compute_rotation_hash(event.public_key)` matches the committed hash when processing each establishment event. Violations are rejected.

### Recovery Key Commitment Violation

**Attack:** Submit a recovery event with a recovery key that doesn't match the committed recovery hash.
- **Mitigation:** Same mechanism as rotation — `pending_recovery_hash` is tracked per branch and verified against the revealed recovery key when processing recovery-revealing events. Violations are rejected.

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

- **Check interval:** Every 6 hours, the identity service checks whether the current key binding is due for rotation.
- **Rotation interval:** 30 days. If the latest HSM key binding is older than 30 days, rotation is triggered.
- **Mode selection:** Scheduled rotation auto-selects the rotation type based on rotation count. Every third rotation is a recovery key rotation (`ror`), the rest are standard signing key rotations (`rot`). This results in signing keys rotating approximately every 30 days and recovery keys every ~90 days.

### Binding Chain Integrity

The auto-rotation loop performs two levels of binding verification:

**Full chain audit** (alert only — does not trigger rotation):
1. Each binding's SAID is verified (content matches declared hash)
2. Chain links are verified (each binding's `previous` pointer matches the prior binding's SAID)
3. Versions increment by exactly 1
4. All binding SAIDs are anchored in the identity's KEL (prevents a database-only attacker from forging bindings)

If the full chain audit fails, a `SECURITY` warning is logged. This is intentionally separated from the rotation decision because a corrupted historical binding cannot be fixed by rotating — triggering rotation on historical chain corruption would cause the service to rotate every 6 hours indefinitely, since the old corrupted records remain in the database.

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

- **Bounded exposure window:** A compromised signing key is useful for at most 30 days before automatic rotation obsoletes it. The adversary must then compromise the new key (which they cannot predict due to pre-rotation commitment).
- **Recovery key freshness:** Recovery keys rotate every ~90 days, limiting the window for recovery key compromise.
- **Defensive rotation:** If the binding chain is tampered with, immediate rotation limits the damage window.
- **Authenticated management endpoint:** The `POST /api/identity/kel/manage` endpoint requires a `SignedRequest` verified against the identity's own KEL, preventing unauthorized KEL operations.

## DB Compromise + Key Compromise

If an adversary compromises both a KELS node's database and a signing key, they could remove legitimate events and replace them with their own in the database. On an unreplicated node, this is a problem — the adversary's events would be served as if they were legitimate.

However, with a full backbone deployment (recommended), any sync operation with other nodes will surface the conflicting events as divergence across the gossip mesh. The legitimate events exist on other nodes and will be gossiped back. Recovery proceeds as usual via the `rec` event, and the divergence alerts operators to investigate the compromised node.

**Mitigation:** Deploy with replication (multiple KELS nodes behind a gossip mesh). The gossip protocol's anti-entropy loop will detect and reconcile inconsistencies. Single-node deployments accept this risk.

## Summary of Residual Risks

All protocol-level attack vectors have mitigations. The protocol's security properties are derived from cryptographic invariants (signatures, SAID integrity, forward commitments, dual-signature requirements) rather than access control, so there are no residual risks that depend on deployment configuration.

The remaining protocol-level concern is key management — hardware-backed key storage is strongly recommended but not enforced by the protocol itself.
