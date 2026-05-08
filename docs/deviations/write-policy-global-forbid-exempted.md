# [Gap 11 → standalone] `write_policy` not globally forbidden by `.terminology-forbidden`

Plan §Gap 11 line 481 instructed forbidding `write_policy` globally as part of the round-12 doc/terminology sweep. Implementation deviated: `write_policy` is **not** globally forbidden because Custody legitimately uses `write_policy` as a distinct concept from SE auth — see `lib/kels/src/types/sad/custody.rs` (round-11 baseline, unchanged in round 12). Forbidding globally would have broken Custody's field naming.

Resolution: `.terminology-forbidden` keeps `write_policy` allowed; the Custody usage stays. Plan author was wrong about Custody usage in the round-12 plan — the rename was scoped to SE only, not Custody. Pinned here as a permanent design exemption.
