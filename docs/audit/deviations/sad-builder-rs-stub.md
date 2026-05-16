# [Gap 1 → Gap 5] `sad_builder.rs` stub

Gap 5 shipped the round-12 builder end-to-end:

- Single `incept_chain(identity, topic, initial_content)` atomically stages `[Icp, Upd]` (per the inception batch rule). Drops both pre-round-12 incept paths.
- `update(content)`, `seal()` (replaces `evaluate(...)`), `repair()` (boundary derivation unchanged; identity_event binding via IEL fetch). All async because each fetches the current IEL binding.
- `contest()` and `decommission()` lifecycle ops with pending bundling. `contest` does NOT pre-flight on divergent (Cnt is valid on sealed-divergent — the server routes); `decommission` fail-fasts on any divergent chain (the matrix's RepairRequired/ContestRequired rules don't apply locally).
- `verify_server_chain_pre_action` helper extracted, mirroring `IdentityEventBuilder::verify_server_chain_pre_action`. Used by `repair`, `contest`, and `decommission` for full server-chain pre-flight verification.
- Lower-SAID branch tip rule for `Cnt` on divergent SELs (mirrors IEL's rule at `docs/design/iel/event-log.md:174`).
- **Field surface change**: dropped the Gap-2 `iel_resolver` field from `SadEventBuilder` per the plan's "Don't store a separate `Arc<dyn IelResolver>` field" guidance. The builder constructs an `AnchoredIelResolver` per-call from `sad_client`. This dropped the 4th `iel_resolver` parameter from `new()` and `with_prefix()` — callers updated.
- `flush()` rebuilds the post-repair owner-local rehydrate (mirrors round-10) using a fresh `AnchoredIelResolver` from `sad_client.as_iel_source()`.
- `is_terminal()` accessor added (chain has terminated locally or per the verifier's content-based flags).
- Test module deleted (Gap 10's responsibility) — replaced with a placeholder shim.
