# Peer Identity

Each gossip node carries an HSM-backed identity. At handshake time, the federation IEL's current `authPolicy` decides whether a connecting peer is authorized to participate in the mesh.

This document covers two things:

- The **HSM-backed identity ceremony** that produces each node's gossip identity.
- The **handshake authorization check** that gates mesh participation.

The federation IEL itself, the per-peer SELs (`peer/services` + `peer/gossip`), and the discovery flow that resolves them are in [federation.md](federation.md) and [discovery.md](discovery.md).

## Gossip identity = degenerate IEL over an HSM-backed KEL

A gossip identity is structurally a normal KELS identity, with two simplifying conventions:

- **One KEL.** The KEL holds the gossip service's signing key — an ML-DSA-65 or ML-DSA-87 key generated inside an HSM. The KEL goes through standard inception, rotation, and recovery via the existing key-event flow; the only special property is that the private key never leaves the HSM.
- **A single-KEL IEL wrapping it.** The IEL declares:
  - `authPolicy = kel(gossip_kel_prefix)`
  - `governancePolicy = kel(gossip_kel_prefix)`

  Both policies are the same `kel` over the single HSM-backed KEL. For a degenerate single-KEL identity, the same-set-different-thresholds convention used by user and federation IELs collapses — there's only one identity in the set, so `threshold(1) = any`. The two policies stay structurally distinct so the same evolution machinery (`Evl`, immunity, governance authorization) applies. The IEL prefix is the **peer identity** referenced from the federation IEL's `authPolicy`.

The IEL is intentionally "degenerate" — it has one KEL under it. The IEL layer is there because the federation IEL's `authPolicy` references identities (IEL prefixes via `iel(...)`), not raw KEL prefixes — and because the operator may later want to evolve auth (e.g., adding a backup key) without changing the peer identity from the federation's point of view.

## HSM-backed identity ceremony

When a node is provisioned, the following happens once per node:

1. **HSM key generation.** The identity service loads a PKCS#11 module and generates (or loads, if present) an ML-DSA-65 or ML-DSA-87 keypair under a stable key label. Convention: `gossip-{node_id}` (e.g., `gossip-node-a`).
   - Development: `kels-mock-hsm` (`kels_mock_hsm.so`), a PKCS#11 cdylib implementing ML-DSA-65/87 via fips204. Not for production.
   - Production: a real HSM's PKCS#11 module (CloudHSM, Luna, etc.) via the `PKCS11_LIBRARY_PATH` env var.
2. **KEL inception.** Standard KEL `Icp` with the HSM-backed public key as the signing key, signed via the HSM. Produces `gossip_kel_prefix`.
3. **IEL inception.** Standard IEL `Icp` with `authPolicy = kel(gossip_kel_prefix)` and an operator-chosen `governancePolicy`. The Icp is anchored in the KEL per the standard inception ceremony. Produces the peer identity prefix.
4. **Per-peer SEL inceptions (two chains).** Standard SEL `[Icp, Upd, Sea]` batches for both per-peer chains — `peer/services` (public, `{ said, domain }`) and `peer/gossip` (federation-gated, `{ said, readPolicy, address }`). Each chain's deterministic prefix is `compute_sel_prefix(peer_identity, TOPIC)` with the respective topic string (see [federation.md §Per-peer publication](federation.md#per-peer-publication)). The trailing `Sea` (tier-2) on each chain is required by the Sea-after-Upd ratchet so the chain is sealed at every publication boundary. Conforming tooling never produces an Upd-tailed chain on either topic. See [protocol-doctrine.md §Sea-after-Upd ratchet](../protocol-doctrine.md#sea-after-upd-ratchet-application-pattern).
5. **Distribute the new peer identity to federation operators.** Out-of-band — by whatever channel the operators use to coordinate federation membership changes. The new identity is added to the federation IEL via a normal `Evl` (subject to the federation's `governancePolicy`); see [federation.md §Membership evolution](federation.md#membership-evolution).

After the ceremony, the node holds:

- An HSM with its private key.
- A KEL whose tip's public key is the HSM key.
- An IEL whose `authPolicy` resolves to that KEL.
- A `peer/services` SEL with its initial published domain.
- A `peer/gossip` SEL with its initial gossip endpoint.

The node's gossip identity is **stable across restarts and key rotations**. Rotating the gossip signing key produces a new KEL `Rot` event but does not change the peer identity prefix (the IEL prefix is unchanged). The federation does not need to be notified of routine key rotations — peer authorization is identity-current, not key-current.

## Handshake authorization

When peer A initiates a gossip handshake with peer B:

1. **Cryptographic handshake.** Standard gossip-service handshake: prefix exchange, ML-KEM-1024 key exchange, mutual ML-DSA-65/87 signature, BLAKE3-derived AES-GCM-256 session key. The mechanics live in [gossip.md §HSM-backed gossip identity](gossip.md#hsm-backed-gossip-identity).
2. **Peer A's identity claim.** A presents its identity prefix and signs the handshake transcript using its current gossip signing key (extracted from its KEL tip).
3. **Peer B's authorization check.**
   - Read B's local federation IEL tip; take the current `authPolicy`.
   - Evaluate the policy against A's claimed identity using `evaluate_signed_policy`.
   - The policy is an `authPolicy` expression over `iel(...)` leaves; satisfaction requires A's identity to appear (directly or via threshold composition) in the current `authPolicy`.
4. **Decision.**
   - **Authorized:** the handshake completes and the gossip session is established.
   - **Not authorized:** the handshake is rejected. B logs the rejection; no fallback, no soft-fail.

The authorization check is symmetric: B's identity is independently checked by A's policy evaluation. A handshake is established only if both sides authorize each other.

### Authorization view stays current via gossip

The federation IEL is the authoritative source for who's authorized, and it propagates to every node via standard IEL gossip. The local view updates automatically:

- A new `Evl` on the federation IEL lands locally → the node's next handshake check sees the new `authPolicy` and behaves accordingly.
- A peer dropped from `authPolicy` → existing sessions with that peer are torn down synchronously when the federation IEL `Evl` arrives. The federation IEL announcement path re-walks the chain fresh and dispatches an eager teardown across active connections, pending dials, and cached addresses; handshake re-check stays as defense-in-depth, not the primary mechanism.
- A peer added to `authPolicy` → new handshakes from that peer succeed.

The freshness of the authorization view is the freshness of the federation IEL and the supporting member KELs as held by the local sadstore and kels services on the node, which the gossip mesh keeps current — announcements (PlumTree) drive primary propagation, dependency tracking handles out-of-order arrivals, and anti-entropy catches anything the primary path missed.

## Identity properties

### Stability

- **Peer identity prefix** is the IEL prefix. Stable across all key rotations and restarts. This is what the federation IEL's `authPolicy` references.
- **Gossip signing key** is the KEL tip's public key. Rotates on every KEL `Rot`. Other peers re-fetch the KEL tip on signature-verification mismatch (key rotation flow).
- **Per-peer SEL prefixes** are `compute_sel_prefix(peer_identity, "kels/sel/v1/peer/services")` and `compute_sel_prefix(peer_identity, "kels/sel/v1/peer/gossip")`. Both stable across rotations — only the `Upd` content changes.

### Key custody

- The HSM holds the private key. Private-key operations happen inside the HSM; the key material never leaves the PKCS#11 module.
- Each node has an isolated HSM with separate persistent storage.

### Signature algorithm

- **Gossip key type:** ML-DSA-65 (FIPS 204, 192-bit post-quantum) or ML-DSA-87 (FIPS 204, 256-bit post-quantum).
- **Encoding:** CESR qb64 for public keys and signatures.
- **Payload:** the gossip handshake transcript (binary; not JSON). See [gossip.md](gossip.md) for the exact transcript composition.

The KELS core service additionally accepts P-256 (ECDSA), ML-DSA-65, and ML-DSA-87 KELs from end-user identities. Gossip-service identities are ML-DSA-65/87 only.

## Security considerations

### What the protocol enforces

- **Identity-current authorization.** Past authorization decisions stay final (federation IEL immunity rule), but the *currently-authorized set* is whatever the current `authPolicy` says. A peer dropped from `authPolicy` cannot continue participating on the strength of its past membership.
- **No key material crossing the HSM boundary.** Compromise of the gossip service binary does not compromise the gossip signing key; only HSM compromise does.
- **Verifier discipline.** The federation IEL is verified at every check via `IelVerifier`, not trusted from cache. The "DB cannot be trusted" invariant applies to federation IEL state on every node.

### What is operator policy

- Choice of `authPolicy` shape (threshold, weighted, etc.).
- Threshold value M(n) (stair function — see [federation.md §Threshold formula](federation.md#threshold-formula-application-level); application-level).
- Coordination protocol for collecting `Evl` endorsements.
- HSM selection and operational hardening.

### Read vs write security

The gossip-handshake authorization gate covers participation in the gossip mesh. Read access to KELS service data is separate; KELS data is end-verifiable, and read access policies live at the application layer.

| Operation | Authentication |
|---|---|
| Read KELS data | None (data is end-verifiable; signature chains are the trust mechanism) |
| Read federation IEL | None (chain is end-verifiable) |
| Read per-peer `peer/services` SEL | None (chain and body are public; body fetch is unauthenticated) |
| Read per-peer `peer/gossip` SEL | Chain end-verifiable (no auth); SAD body fetch gated by `readPolicy` = `iel(FEDERATION_IEL_PREFIX)` |
| Gossip handshake | Federation IEL `authPolicy` satisfaction at handshake time |
| Federation IEL `Evl` submission | Federation IEL `governancePolicy` satisfaction |

## Troubleshooting

### Connecting peer rejected

1. Confirm the connecting peer's identity is in the current federation `authPolicy`:
   - Read the local federation IEL tip.
   - Walk the `authPolicy` for `iel(<connecting_peer_prefix>)`.
2. If the identity is not present, check whether a recent `Evl` removed it.
3. If the identity should be present but isn't, verify the federation IEL has converged (effective SAID matches across peers).

### Signature verification failed

- HSM healthy and responding?
- Key label matches `gossip-{node_id}`?
- Connecting peer's KEL tip's signing key matches the signature received? (If the peer rotated keys, the accepting peer needs to re-fetch the KEL tip.)

### Federation IEL prefix warning at startup

- Runtime `FEDERATION_IEL_PREFIX` env var differs from the compile-time default. Expected during contested-federation recovery (see [federation.md §Recovery](federation.md#recovery)). Confirm the runtime value is the intended new federation IEL prefix.

## References

- [federation.md](federation.md) — the federation IEL and how `authPolicy` evolves.
- [discovery.md](discovery.md) — node-side discovery (resolving who + where).
- [gossip.md](gossip.md) — handshake transport mechanics.
- [primitives/iel/event-log.md](../primitives/iel/event-log.md) — IEL semantics, immunity rule.
- [features/policy.md](../features/policy.md) — policy DSL and evaluation.
