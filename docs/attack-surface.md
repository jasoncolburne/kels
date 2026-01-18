# KELS Attack Surface

Compromise of a KELS service doesn't gain you much - it has no identity or signing authority. The
server performs signature verification on all incoming events but has no ability to forge events
itself. Since all data is tamper-evident, signed, and end-verifiable, DOS attacks are probably
the main concern.

A controller of an identity has 3 keys to protect. It's advised that clients only be deployed to
mobile with hardware-backed keys, or services with HSM-backed keys. Integrations already exist
in this repository for both.

## Keys

- Signing - the current key, used to sign ixn and rot events
- Rotation - the pre-committed next key (revealed during rotation, becomes the new signing key)
- Recovery - revealed only during recovery events, used in conjunction with rotation key for dual-signed events

## What Compromise Allows

- Signing - if the signing key is compromised, at most, an adversary can sign ixn events
- Rotation - if the rotation key is compromised, an adversary can submit a rot event, and subsequently
as many ixn or rot events as they desire
- Recovery - can't act unless rotation key also compromised, which allows full administrative control
of the kel. if this happens, the owner's only recourse is to contest and permanently freeze their kel

## Event Kinds

- icp - inception, creates the KEL
- dip - delegated inception, creates a KEL under a delegator's authority
- ixn - interaction, anchors external data
- rot - rotation, rotates the signing key
- rec - recovery, recovers from divergence (dual-signed)
- ror - recovery rotation, rotates the recovery key (dual-signed)
- cnt - contest, permanently freezes the KEL (dual-signed)
- dec - decommission, ends the KEL (dual-signed)

## KEL States

- **Normal** - single chain of events, all operations allowed
- **Divergent** - multiple events at same version, KEL is frozen until recovery
- **Contested** - both parties revealed recovery keys, KEL is permanently frozen
- **Decommissioned** - KEL ended normally, no further events allowed

## How Recovery Works

There are 4 kinds of events that reveal the recovery key:

- cnt - contest, appended to owners tail, but no archival happens, kel remains divergent and contested
- dec - decommission kel, a normal decommissioning
- rec - recover kel, appended to owner's tail, triggers archival of other tails in kels
- ror - rotate recovery key, a normal preventative rotation

Recovery-revealing events require dual signatures: the current rotation key AND the recovery key. The
event commits to both a new signing key (via rotation_hash) and a new recovery key (via recovery_hash).

After a recovery event at version N, no events other than contest can be inserted at version ≤ N. This is
an important security property that prevents re-divergence and recovery battles.

Contest is the ultimate recovery event, and no change to the kel is possible if contest is submitted
successfully.

## Proactive Protection

The signing algorithm is Secp256r1 throughout, meaning you have 128 bits of security to work with.
You probably want to rotate your signing key every 1-3 months and your recovery key each 3-12 months.
But, I just kind of pulled those numbers out of the air. They are probably reasonable, but with
advances in computing you should do the assessment yourself for the current point in time.

These intervals should be adjusted based on your threat model and key storage security. Hardware-backed
keys (Secure Enclave, HSM) are significantly harder to extract and may allow longer rotation intervals.
