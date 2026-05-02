# [Gap 5 → #147] Exchange CLI commands parked compile-clean since SE rewrite

`cmd_exchange_publish_key` / `cmd_exchange_rotate_key` (clients/cli/src/commands/exchange.rs) returned `Err("parked pending Gap 11 CLI rewrite")` on invocation throughout rounds 11–12. The pre-round-12 flow assembled SE events declaring `write_policy` / `governance_policy` inline at inception and computed the SEL prefix from `(write_policy, topic)`. Round-12 SE chains bind to an existing IEL via the `identity` parameter; `cmd_exchange_lookup_key` and `mail send` had the same pre-round-12 prefix derivation and surfaced wrong prefixes silently against round-12 servers.

#147 closed this by rewiring all three exchange commands onto round-12 primitives. `publish-key` and `rotate-key` now take `--identity <iel-prefix>` (per the design call: identity creation and exchange-key publication are distinct primitives — users who want one-shot ergonomics write a shell wrapper over `kels iel incept` + `kels exchange publish-key --identity $NEW_PREFIX`). The exchange CLI is the single-device ergonomic wrapper; multi-device flows use the generic `kels sel *` + `kels kel anchor` decomposition.

What shipped:

- `cmd_exchange_publish_key` (clients/cli/src/commands/exchange.rs) — generates ML-KEM keypair, posts the `EncapsulationKeyPublication` SAD object, calls `SadEventBuilder::new(...).incept_chain(identity, ENCAP_KEY_KIND, publication_said)` to stage the atomic `[Icp, Upd]`, `publish_pending`s, anchors both SAIDs in the caller's KEL via `KeyEventBuilder::interact`, then `flush()`es. Required args: `--prefix <kel>`, `--identity <iel-prefix>`. Optional: `--algorithm`.
- `cmd_exchange_rotate_key` — symmetric for an existing chain. Computes `sel_prefix = compute_sad_event_prefix(identity, ENCAP_KEY_KIND)`, hydrates via `SadEventBuilder::with_remote_prefix`, stages `Upd`, publishes, anchors, flushes.
- `cmd_exchange_lookup_key` — takes `<iel-prefix>` (positional, replacing the old `<kel-prefix>` arg). Computes the SEL prefix from `(identity, ENCAP_KEY_KIND)`, fetches the chain tip's content SAID, and resolves the publication via `get_sad_object`.
- `exchange_write_policy` helper in `clients/cli/src/helpers.rs` — removed (no longer used now that round-12 SE chains carry no policy fields).

`mail send` (`clients/cli/src/commands/mail.rs`) still uses the same pre-round-12 lookup pattern (`exchange_write_policy(recipient_kel_prefix)` → `compute_sad_event_prefix(write_policy, ENCAP_KEY_KIND)`). Fixing it requires the sender to know the recipient's IEL identity for encap-key lookup; that rewire lands with the test-script migration (#147 commit 4), where `test-exchange.sh` drives the cross-actor mail flow against the new identity-rooted exchange CLI. The `exchange_write_policy` helper in `clients/cli/src/helpers.rs` and the SAID-routing call sites it feeds stay until that migration; this commit retires only the publish/rotate/lookup deviation.

Closed by: KELS-126_sad-event-builder, commit landing #147 (third in the stacked sequence: IEL CLI → SEL CLI → Exchange CLI rewrite).
