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

1. **Rotate the recovery key offline.** The recovery key should be stored in a separate HSM or cold storage, not accessible to the compromised signing key.
2. **Submit a `rec + rot` batch** using the recovery key. This can be done via the identity service's manage endpoint or directly against the kels service.
3. **The merge engine detects divergence**, accepts the recovery, and creates a `RecoveryRecord`.
4. **The background archival task** asynchronously moves adversary events to archive tables.
5. **During recovery**, the serve filter caps events at the recovery serial — consumers see a consistent view.
6. **After recovery completes**, the new `rot` becomes visible and normal operations resume.

### Recovery via database truncation

For the identity service specifically, database-level truncation may be simpler operationally because:

- Identity manages a single prefix (no multi-tenant complexity).
- The authoritative KEL copy lives in the kels service.
- Builder state (HSM key bindings, generation counters) must be reset regardless.

Procedure:

1. **Stop the identity service.**
2. **Identify the last known-good serial** — the last event the operator trusts (before the adversary's extension).
3. **Delete adversary events and signatures** from `identity_key_events` and `identity_key_event_signatures` where `serial > last_known_good_serial`.
4. **Delete the corresponding HSM key bindings** from `identity_hsm_key_bindings` that reference the adversary's key generations.
5. **Restart the identity service.** The auto-rotation loop will detect the state and re-derive builder state from the remaining KEL + HSM bindings.
6. **Submit recovery (`rec + rot`) via the identity service** to rotate away from the compromised signing key. This propagates to the kels service and federation.

### Post-recovery checklist

- Verify the identity KEL is non-divergent (`/health` endpoint, logs).
- Verify the kels service accepted the recovery (check the prefix's KEL via the API).
- Verify federation peers have synced the recovered KEL (registry member KEL sync).
- Rotate the signing key material in the HSM if the key was compromised (not just the KEL key — the underlying HSM slot).
- Audit the adversary's events (available in the archive tables or recovery chain) to understand what was signed and whether downstream consumers were affected.
