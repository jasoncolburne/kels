# [Gap 11 → #147] est/evl wire-format patterns exempted at `clients/test/scripts/`

A path-scoped exemption via `clients/test/scripts/.terminology-forbidden` dropped the patterns `kels/sad/v1/events/est` and `kels/sad/v1/events/evl` from the lint scope for that subtree (the production root file kept them forbidden). The exemption existed because the test scripts in that directory still hand-built pre-round-12 SEL events: `writePolicy` on `Icp`, `governancePolicy` on `Est`-v1, SEL prefix derived from `(policy_said, topic)` rather than `(identity, topic)`.

#147's test-script migration retired the exemption by rewriting every script that touched IEL/SELs to drive the round-12 CLI surface. The migration removed all inline JSON event construction (no more raw `kels/sad/v1/events/est` / `evl` strings, no more `writePolicy` / `governancePolicy` field assembly) and relies on:

- `kels iel incept --auth-policy --governance-policy --publish` for IEL identity setup (single-endorser or multi-endorser policies via `build_immune_policy` / `build_immune_or_policy` in `clients/test/scripts/lib/test-common.sh`).
- `kels sel incept --identity --initial-content --publish` for the atomic `[Icp, Upd@v1]` inception batch.
- `kels sel update <prefix> <content> --publish` for chain advances.
- `kels sel repair <prefix> [--owner-prefix <kel>] --publish` for divergence repair (no `--owner-prefix`) and silent-extension repair (with `--owner-prefix`, kels-style: builder walks the owner's KEL anchors fresh each call to identify the rogue boundary — no local cache to go stale).
- `kels {iel,sel} submit <said>...` for the multi-device anchor → submit flow.
- `kels kel anchor` retained as the per-device Ixn anchor primitive.

Files migrated:
- `clients/test/scripts/test-sadstore.sh` — scenarios 5 (SEL submission), 7 (divergence + repair), 8 (silent-extension + repair via `--owner-prefix`), 9 (clean state) all rewritten onto CLI flow. Scenarios 1 / 2 / 4 retained their direct-curl negative tests against the SADStore HTTP surface (they exercise server-side API behavior, not CLI flows). Scenario 3 prefix-computation labels updated from "KEL prefix" to "identity".
- `clients/test/scripts/load-sad.sh` — `create_group` rewritten: KEL incept → IEL identity setup → SEL via `sel incept` (atomic `[Icp, Upd]`) followed by zero-or-more `sel update` calls, each anchored and submitted via the new CLI surface.
- `clients/test/scripts/test-exchange.sh` — added a Phase 1b that incepts an IEL identity per actor (Alice, Bob); `exchange publish-key` / `rotate-key` plumbed `--identity`; `exchange lookup-key` switched from KEL prefix to IEL identity; `mail send` plumbed `--recipient-identity` for round-12 encap-key lookup (KEL prefix retained as routing/ESSR-binding identity).
- `clients/test/scripts/lib/test-common.sh` — replaced `build_governance_policy` (curl-driven, pre-round-12 single-endorser shape, no immunity flag) with `build_immune_policy` (CLI-driven, immune); added `build_immune_or_policy` for multi-endorser disjunctive policies (used by scenario 8); added `setup_iel_identity` / `setup_iel_identity_with_policy` / `put_sad_object` helpers.

Files removed:
- `clients/test/scripts/.terminology-forbidden` — gone. The production root `.terminology-forbidden` now governs the subtree without exemption; future regressions on the est/evl strings are caught.

Library/CLI changes that came with the migration:
- `SadEventBuilder::repair` signature gained an optional `Option<&BTreeSet<Digest256>>` argument carrying the owner's anchored SAID set. When `None` and the chain is non-divergent, repair short-circuits to `NothingToRepair` (existing behavior preserved). When `Some`, the builder walks the verified chain forward, finds the first event whose SAID is not in the set, and uses the version-just-before that event as the truncation boundary (silent-extension repair).
- `SadEventBuilder::with_remote_prefix` populates a fresh `InMemorySadStore` with verified events so `repair`'s boundary lookup works in stage-and-exit CLI invocations.
- `cmd_sel_repair(--owner-prefix)` walks the supplied KEL via `verify_key_events_with`, harvests `Ixn` anchor SAIDs into a `BTreeSet`, and threads it into `SadEventBuilder::repair`.
- `clients/cli/src/helpers.rs::exchange_write_policy` removed (no longer used now that round-12 SELs carry no policy fields and mail send uses the `--recipient-identity` IEL prefix for encap-key lookup).

Closed by: KELS-126_sad-event-builder, commit landing #147 (fourth in the stacked sequence: IEL CLI → SEL CLI → Exchange CLI rewrite → test-script migration).
