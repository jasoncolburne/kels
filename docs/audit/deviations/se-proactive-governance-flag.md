# [Round-12 doc drift → resolved] SEL `is_proactively_governed` flag mirrors KEL's `is_proactive_ror_compliant`

Slice 1 §F1 / slice 6 §H3 / slice 7 §Item 4 flagged a doc/code mismatch: four design docs (`docs/design/sel/{verification,events,event-log,merge,reconciliation}.md`) listed the SEL proactive-evaluation rule (`MAX_NON_EVALUATION_EVENTS = 63`) as a verifier-enforced "Property Verified", but the verifier only incremented `events_since_evaluation` without ever comparing it against the bound. KEL had the symmetric rule enforced and surfaced (`KelVerification::is_proactive_ror_compliant`); SEL didn't.

**Fix (Option (a) per slice 7 §Item 4).** Added a chain-wide `is_proactively_governed: bool` flag to `SelVerifier` and `SelVerification`. Default `true`; flipped to `false` once any branch's `events_since_evaluation` exceeds `MAX_NON_EVALUATION_EVENTS = 63` during the walk. `Sea`/`Rpr` reset the per-branch counter; `Cnt`/`Dec` preserve it (terminal events don't advance the seal). Surfaced via `SelVerification::is_proactively_governed()` accessor; rehydrated on `resume`. Surface signal only — doesn't gate the chain (consistent with KEL's posture).

**Naming.** Chose `is_proactively_governed` rather than copying KEL's `is_proactive_ror_compliant` shape. The SEL rule's purpose is "the chain has had governance evaluations within the cadence bound" — `proactively governed` reads cleanly without context, whereas KEL's `_ror_` requires knowing the rotation-recovery abbreviation. Cross-primitive asymmetric naming is intentional; the underlying contract (surface signal, default true, flipped on bound-cross) is identical.

Constant `MAX_NON_EVALUATION_EVENTS` retained as-is (referenced in 5 design docs and ~10 code sites; rename not in scope).

Code anchors: `lib/kels/src/types/sad/verification.rs` (verifier flag + flush_generation Upd advancement), `lib/kels/src/types/sad/event.rs` (`SelVerification` field + accessor + `new()` signature). KEL parallel: `lib/kels/src/types/kel/verification.rs:630-632`.
