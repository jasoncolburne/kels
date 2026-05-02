# [Round-12 review fix → audit confirmed clean] Auth-passing post-SE-divergence event keeps `chain.policy_satisfied=true`

The post-divergence soft-fail propagation rule (round-12 third follow-up commit 1) flips `chain.policy_satisfied=false` only when an auth-related gate (`IelDivergent`, `is_satisfied`, `is_anchored`) FAILS for an event at `version >= diverged_at_version`. An auth-PASSING post-SE-divergent event leaves `chain.policy_satisfied=true`.

Pinned by `upd_post_divergence_auth_pass_advances_ratchet_excludes_from_satisfied` in `lib/kels/src/types/sad/verification.rs`: chain-wide `policy_satisfied` tracks "any auth failures encountered in the walk" — orthogonal to the divergence cutoff. The per-event SAID query (`is_said_satisfied`) is the cutoff-aware signal: post-divergence SAIDs are NOT in `satisfied_saids` even on auth-pass. `is_contested` / `is_decommissioned` carry the divergence-status signal content-based.

A strict reading of the design's "verification doesn't bless" framing would also flip `chain.policy_satisfied=false` for any post-divergence event. Implementation diverged from that strict reading because consumers needing the cutoff signal use `is_said_satisfied` per-SAID; the chain-wide flag is the auth-validity aggregate, not the divergence-status flag.

**Audit (KELS-126, post round-12-third-follow-up commit 2).** All five production consumers of `.policy_satisfied()` in `lib/` and `services/` answer "did any auth check fail during the walk?", never "is this chain trustworthy / non-divergent / non-terminal?". The cutoff/divergence/terminal questions are correctly handled via separate signals (`is_contested`, `is_decommissioned`, per-SAID `is_said_satisfied`, plus the pre-batch `first_divergent_version` / `last_governance_version` snapshots used in the SE/IEL submit handlers' routing matrices).

Production consumer sites:

- `lib/kels/src/sad_builder.rs:320` — `SadEventBuilder::repair` rejects with `KelsError::ChainHasUnverifiedEvents("server-fetched chain reports policy_satisfied=false — will not repair against unverified data")`. Auth-walk-aggregate: any auth failure across the server's view aborts repair (fail-secure).
- `lib/kels/src/sad_builder.rs:332` — symmetric on the owner-local `SelVerification` (`"local store may have been tampered, or KEL anchors are unreachable"`).
- `services/sadstore/src/handlers.rs:1635` — SE Rpr submit gates with `"SE Rpr not anchored under IEL-resolved governance_policy"`. The post-truncation chain is linear from v0 to the Rpr; any auth failure (IelDivergent, is_satisfied, is_anchored) flips the flag and rejects.
- `services/sadstore/src/handlers.rs:1863` — SE Upd/Sea submit gates with `"SE event not anchored under IEL-resolved policy"`. The adjacent comment at lines 1872-1875 explicitly names the auth-walk semantic when feeding the algorithmic-`ContestRequired` check.
- `services/sadstore/src/handlers.rs:2463` — IEL submit gates with `"IEL anchoring not satisfied — {reason}"` via `describe_iel_policy_failure`, which enumerates the per-kind soft/hard mapping (Cnt/Dec on governance soft, Icp on auth_policy soft, Evl hard before reaching this gate).

The two `policy_satisfied: verification.policy_satisfied()` field copies in `lib/kels/src/types/iel/verification.rs:352` and `lib/kels/src/types/sad/verification.rs:146` are verifier-internal — they rehydrate the auth-walk-aggregate state into a resumed verifier across page boundaries; not consumer use.

The negative case is also pinned — the SE Cnt path at `services/sadstore/src/handlers.rs:1665-1669` explicitly comments that it does **not** gate on `policy_satisfied`:

```rust
// Verify chain with new events. Cnt has SOFT governance auth —
// a govfailed Cnt still lands; the verifier surfaces the
// chain-content-based `is_contested=true` and propagates
// `policy_satisfied=false`. We do NOT gate on
// `policy_satisfied` here.
```

Same shape on the SE Dec path and the IEL Cnt/Dec routing branches: SOFT-auth terminals must land regardless of `policy_satisfied`; the chain-content-based `is_contested` / `is_decommissioned` flags carry the terminal signal downstream. No production consumer was found that conflated the chain-wide flag with divergence status. The design contract holds; no behavior or comment changes were needed.

Future additions of `.policy_satisfied()` consumers should preserve this discipline: the flag answers "did any auth check fail in the walk?" If a caller wants "is this chain trustworthy / non-divergent / non-terminal?", it should branch on `is_contested` / `is_decommissioned` (terminal-state) and `is_said_satisfied` (per-SAID cutoff) instead.
