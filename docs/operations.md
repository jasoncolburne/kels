# Operations Guide

## Identity Service Recovery

The identity service manages the gossip and registry services own KELs and signing keys. It is the sole writer to its own prefix, forwarding events it creates to a remote store (kels or registry). An adversary with broken keys could submit new or divergent events to the kels/registry service - posing as the identity service. They could also impersonate the identity-backed service in raft or gossip.

### Detection

The identity service's auto-rotation loop detects divergence on every cycle:

```
SECURITY: Identity KEL has diverged
```

Additionally, the binding chain audit detects inconsistencies between HSM key bindings and the KEL state. Either of these alerts indicates potential compromise.

### Recovery via `rec` event

The standard recovery flow works for identity:

1. **Run `identity-admin recover`** or **`identity-admin contest`** via the identity service's manage endpoint. The HSM provides both the rotation and recovery keys for dual signing.
2. **The merge engine detects divergence**, identifies adversary events, archives them to mirror tables, inserts the recovery events, and creates a `RecoveryRecord` — all atomically within the merge transaction.
3. **After recovery completes**, the adversary events are archived and the clean chain is all that remains. Normal operations resume immediately.

### Recovery

Adversary events are archived synchronously during the merge transaction. Recovery completes atomically — no window where the KEL appears divergent after a successful recovery submission.

- A `RecoveryRecord` audit trail is written for each recovery. Query via `GET /api/v1/kels/kel/:prefix/audit`.
- Archived adversary events are available via `GET /api/v1/kels/kel/:prefix/archived` for forensics.

### Post-recovery checklist

For gossip identity:
- Verify the kels service accepted the recovery (check the prefix's KEL via the API).

For registry identity:
- Verify federation peers have synced the recovered KEL (registry member KEL sync).

For both:
- Verify the identity KEL is non-divergent (check logs — the auto-rotation loop logs `SECURITY` warnings on divergence).
- Audit the adversary's events (available in the archive tables or recovery chain) to understand what was signed and whether downstream consumers were affected.

## Datastore Tampering

Datastore tampering without key compromise is not a security threat — all KEL data is cryptographically verified (signatures, SAID integrity, chain linkage) before use. An attacker with only database access cannot forge valid events, though they can probably delete or modify data and break valid KELs.

An attacker who has **both database access and broken keys** can write cryptographically valid but protocol-violating data directly to the database, bypassing the merge engine's invariant enforcement. For example, writing a chain that violates proactive ROR compliance (more than 62 non-revealing events between recovery-revealing events) would cause the verification engine to reject the KEL entirely, preventing normal operations including recovery.

In these cases, manual database surgery (or a restore) may be required to restore the KEL to a valid state before protocol-level recovery (`rec` or `cnt`) can proceed. The verification engine will reject the tampered KEL (fail-secure), but this also blocks recovery since the merge engine verifies the existing chain before accepting new events.
