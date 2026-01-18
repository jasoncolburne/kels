# KELS Attack Surface

Compromise of a kels service doesn't gain you much, it has no identity or signing authority.

A controller of an identity has 3 keys to protect. It's advised that clients only be deployed to
mobile with hardware-backed keys, or services with HSM-backed keys. Integrations already exist
in this repository for both.

## Keys

- Signing - used to sign ixn events
- Rotation - revealed during rotation, used as next signing
- Recovery - revealed during recovery events, used for recovery in conjunction with rotation key

## What Compromise Allows

- Signing - if the signing key is compromised, at most, an adversary can sign ixn events
- Rotation - if the rotation key is compromised, an adversary can submit a rot event, and subsequently
as many ixn or rot event as they desire
- Recovery - can't act unless rotation key also compromised, which allows full administrative control
of the kel. if this happens, the owner's only recourse is to contest and permanently freeze their kel

## How Recovery Works

There are 4 kinds of events that reveal the recovery key:

- cnt - contest, appended to owners tail, but no archival happens, kel remains divergent and contested
- dec - decommission kel, a normal decommissioning
- rec - recover kel, appended to owner's tail, triggers archival of other tails in kels
- ror - rotate recovery key, a normal preventative rotation

Events that reveal the recovery key are signed with that same key, while a commitment to a new recovery
key is made. These events are only valid in combination with a standard rotation (revealing the
rotation key as current and establishing a new rotation hash). These two actions happen within the same
recovery event. Recovery prior to an existing recovery event is not allowed. Contest is the ultimate
recovery event, and no change to the kel is possible if contest is submitted successfully.
