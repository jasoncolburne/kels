# KELS Protocol Attack Surface

Analysis of attack vectors against the KELS protocol — cryptographic properties, KEL integrity, key management, and event verification. These are inherent to the protocol design, independent of deployment topology.

## Trust Model

The KELS protocol has no central authority. Security rests entirely on cryptographic properties: signatures (secp256r1 / ECDSA P-256, 128-bit security), content-addressable identifiers (SAID via Blake3-256), and forward commitments (rotation/recovery hash chains). Any valid signed event is accepted regardless of source.

**Assumptions:**
- Clients hold private keys in hardware-backed storage (Secure Enclave, HSM)
- The signing algorithm is secp256r1 (ECDSA P-256), providing 128 bits of security
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
- **Mitigation:** If the adversary submits a recovery-revealing event, the merge protocol returns `RecoveryProtected`. The owner must `cnt` (contest) instead, which permanently freezes the KEL. This is the correct security outcome — it prevents an attacker with the recovery key from winning a recovery race.

### Re-divergence After Recovery

**Attack:** After the owner recovers, adversary re-submits events at the same generation to re-diverge.
- **Mitigation:** Recovery protection — any recovery-revealing event at generation N protects generation N and all earlier generations. Events at generation <= N are rejected with `RecoveryProtected` (except `cnt`). This is an important security invariant that prevents recovery battles.

### Contested KEL Bypass

**Attack:** Submit events to a contested (permanently frozen) KEL.
- **Mitigation:** Pre-merge validation checks `is_contested()` and immediately rejects all submissions. A contested KEL is truly permanent — there is no bypass.

### Decommissioned KEL Bypass

**Attack:** Submit events to a decommissioned KEL.
- **Mitigation:** The merge protocol checks for decommission and rejects appends. Only divergence at earlier generations is possible (with a compromised signing key from before decommission), which would still be caught by recovery protection if `dec` was the decommissioning event.

## KEL Verification Bypass Attempts

### Forward Pass Bypass

**Attack:** Submit events that pass structure verification but have broken cryptographic properties.
- **Mitigation:** KEL verification is two-phase. Phase 1 (forward pass) checks structure, chaining, and SAID integrity. Phase 2 (backward pass) walks from each tail backward, verifying pre-rotation commitments, recovery key commitments, and all signatures. Both phases must pass.

### Pre-rotation Commitment Violation

**Attack:** Submit a rotation event whose public key doesn't match the rotation hash committed in the previous establishment event.
- **Mitigation:** The backward pass explicitly verifies `rotation_hash` commitments — `compute_rotation_hash(future_event.public_key)` must equal the committed `rotation_hash`. Violations are rejected.

### Recovery Key Commitment Violation

**Attack:** Submit a recovery event with a recovery key that doesn't match the committed recovery hash.
- **Mitigation:** Same mechanism as rotation — `recovery_hash` is verified against the revealed recovery key. Violations are rejected.

## Client-Side Attacks

### Key Extraction

**Attack:** Extract private keys from client storage.
- **Mitigation:** Hardware-backed keys (Secure Enclave on iOS, SoftHSM2 for services) are designed to be non-extractable. The `kels-ffi` library interfaces with Apple's Secure Enclave; the HSM service wraps SoftHSM2 via PKCS#11.
- **Residual risk:** Software-only key storage (e.g., file-based `KelStore`) is vulnerable to filesystem access. This is acceptable for development but not production.

### Local State Manipulation

**Attack:** Modify the client's local KEL state (SQLite database or file store) to desynchronize from the server.
- **Mitigation:** The client always fetches the current KEL from the server before creating events. The `KeyEventBuilder` chains from the owner's tail, which is tracked server-side. Local state manipulation causes the client to submit events that fail server-side validation.
- **Residual risk:** A manipulated client could be tricked into signing events based on false local state, but those events would fail validation when submitted.

### Owner Tail Confusion

**Attack:** Trick the client into chaining from the wrong tail, creating an event that doesn't properly connect to the KEL.
- **Mitigation:** The `owner_tail` is tracked via `save_owner_tail()` / `load_owner_tail()` on the `KelStore`. The builder syncs with the server KEL before creating events. Events that don't chain from a valid previous are rejected by the server.

## Summary of Residual Risks

All protocol-level attack vectors have mitigations. The protocol's security properties are derived from cryptographic invariants (signatures, SAID integrity, forward commitments, dual-signature requirements) rather than access control, so there are no residual risks that depend on deployment configuration.

The remaining protocol-level concern is key management — hardware-backed key storage is strongly recommended but not enforced by the protocol itself.
