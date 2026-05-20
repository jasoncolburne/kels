# Identity Rooting

**Canonical name:** identity rooting — the structural pattern by which a SAD references its IEL-resolved issuer / subject.

A SAD that asserts something about an identity carries an IEL-event SAID rather than a KEL prefix. The IEL event resolves to the issuer's (or subject's) currently-tracked `authPolicy` / `governancePolicy` at the moment the SAD was produced. Pinning to a specific IEL event means consumers can choose between **frozen-mode** (re-resolve at the bound event, preserving issuance-time policy) and **identity-current** (re-resolve at the IEL's current tip, picking up evolutions) verification.

**Consumers:** credentials (`issuerIelEvent`, `subjectIelEvent`), custody-bearing objects (`ownerIelEvent` for write attestation; `readPolicy` for read enforcement), SEL events (`ielEvent`).

**Dependencies:** [../event-logs/iel/events.md](../event-logs/iel/events.md) for the IEL event semantics; [../../logic/resolvers/iel-resolver.md](../../logic/resolvers/iel-resolver.md) for the resolution mechanism; [../../../features/creds.md](../../../features/creds.md) for the credential-side framing.

Stub. The full identity-rooting story (frozen-vs-current modes, edge resolution, the `identity(X)` policy leaf, the SAD-side binding rules) is consolidated in the credentials and policy features docs; this primitive doc will consolidate the design-level account as it firms up.
