# [Issue #156 → resolved] PendingMap::refresh same-SAID short-circuit

Slice 4 §F1 flagged that `PendingMap::refresh` (`services/gossip/src/pending.rs`) called `cleanup_record + park` unconditionally on 422-on-replay, even when the new deps set was identical to the prior park (producing the same `record.said`). `park`'s `set_ex(..., self.ttl_secs)` renews the TTL on every call, so on busy chains whose advances never satisfy the parked record's deps, the park's TTL was being renewed every drain cycle — extending park lifetimes well beyond the documented 5-minute eviction bound.

**Fix (Option (a) — filter at the refresh site).** `refresh()` now computes the candidate `ParkRecord` first, compares its SAID to the old record's, and short-circuits without touching Redis when they match. Trust-evidence holds (every replay still re-runs the verifier on origin-refetched bytes); deps still eventually satisfy or permanently fail; the original park's 5-minute TTL is now the firm upper bound on individual park lifetimes.

Why filter inside `refresh` rather than at `handle_drain_outcome` (the slice's first option (a)): applies regardless of caller, no double `ParkRecord::create` at the call site, preserves the simple call-site ergonomic. Tested by relying on the existing `park_record_said_is_deterministic` and `park_record_said_independent_of_dep_insertion_order` invariants in `pending.rs` — same-deps reproducibly hit the short-circuit.

Cf. slice 4 §F1 + §M2.
