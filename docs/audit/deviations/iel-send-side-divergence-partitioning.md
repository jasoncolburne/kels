# [Pre-round-12 IEL primitive gap → Round-12 third follow-up commit 4] IEL send-side divergence partitioning implemented

`send_divergent_iel_events` added at `lib/kels/src/types/iel/sync.rs`, mirroring KEL's `send_divergent_events` (`lib/kels/src/types/kel/sync.rs:517`).

Partitions post-divergence events into `chain_a` / `chain_b` by tracing forward from each fork event. **Contested** case (Cnt on either branch): pre-divergence + non-cnt chain go as paged appends, cnt-chain as an atomic single-page batch (errors if cnt-chain exceeds `MINIMUM_PAGE_SIZE` — indicates DB tampering). **Unrecovered** (defensive — production routing rejects this state with `ContestRequired`): longer chain as paged appends, then the fork event from the shorter chain establishes divergence at the receiver.

`forward_identity_events` refactored from a flat paging loop into a thin wrapper around new private `transfer_identity_events`, which detects divergence at page boundaries via the held-back-event strategy (mirrors SEL's `transfer_sad_events`) and invokes `send_divergent_iel_events` on detection.

Removes the pre-round-12 asymmetry where `forward_identity_events` relied on the receiver's submit handler to "figure out" complex batches — sender-side composition is now the cryptographic-soundness gate, matching the round-12 design's explicit framing in `docs/design/iel/merge.md §Gossip Send-Side Partitioning`. KEL/SEL/IEL symmetry restored.

Test coverage: 2 unit tests in `lib/kels/src/types/iel/sync.rs` test module — contested-divergent partitioning order + linear-passthrough unchanged.
