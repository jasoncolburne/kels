# Operations Guide

## Identity Service Recovery

The identity service manages the registry's own KEL and signing keys. It is the sole writer to its own prefix, forwarding events to the kels service. If the identity database is tampered with — for example, an adversary compromises the signing key and injects valid events — the following procedures apply.

### Detection

The identity service's auto-rotation loop detects divergence on every cycle:

```
SECURITY: Identity KEL has diverged
```

Additionally, the binding chain audit detects inconsistencies between HSM key bindings and the KEL state. Either of these alerts indicates potential compromise.

### Recovery via `rec` event

The standard recovery flow works for identity:

1. **Run `identity-admin recover`** to submit a `rec + rot` batch via the identity service's manage endpoint. The HSM provides both the rotation and recovery keys for dual signing.
2. **The merge engine detects divergence**, identifies adversary events, archives them to mirror tables, inserts the recovery events, and creates a `RecoveryRecord` — all atomically within the merge transaction.
3. **After recovery completes**, the adversary events are archived and the clean chain is all that remains. Normal operations resume immediately.

### During active recovery

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
