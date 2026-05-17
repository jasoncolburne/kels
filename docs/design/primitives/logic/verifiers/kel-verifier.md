# KelVerifier

**Canonical name:** `KelVerifier`

The KEL chain-walker. Streams events page by page in generations, tracks per-branch state (signing/rotation/recovery commitments, divergence ancestor, seal), and produces a `KelVerification` token whose existence proves the chain was verified. Inline anchor checking against caller-registered SAIDs runs during the walk.

**Consumers:** every chain-data consumer — submit handlers, anchor checkers, gossip-receive, recovery ceremonies. Holding a `KelVerification` is the only way to access KEL-derived data for security decisions.

**Dependencies:** [`../../data/event-logs/kel/verification.md`](../../data/event-logs/kel/verification.md), [`../../data/event-logs/kel/event-log.md`](../../data/event-logs/kel/event-log.md).

Stub. Detailed content lands iteratively.
