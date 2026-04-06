# Branch Audit: KELS-60_exchange (Round 3) — 2026-04-04

Exchange protocol branch: ~9123 insertions / ~2610 deletions across 76 files. Focus on new findings after all 17 findings from rounds 1-2 were resolved. Full read of lib/exchange, services/mail, CLI commands, FFI exchange module, crypto module, gossip state changes, sadstore handler changes, and integration test scripts.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 1        |
| Low      | 0    | 1        |

All 17 findings from rounds 1-2 are resolved.

---

## High Priority

No new high-priority findings.

---

## Medium Priority

### ~~1. No explicit per-message blob size limit on mail send endpoint~~ — RESOLVED

**File:** `services/mail/src/handlers.rs:207-332` and `services/mail/src/server.rs:19-27`

~~The mail send endpoint has no explicit per-blob size limit. It relies solely on Axum's default `Json` extractor body limit (2MB), which is not configurable via KELS environment variables. While the cumulative storage cap (`MAIL_MAX_STORAGE_PER_RECIPIENT_MB`, default 100MB) provides a ceiling, a single request could consume ~1.5MB (the 2MB JSON limit minus base64 overhead) of a recipient's allocation in one shot. An explicit, configurable per-message size limit (e.g. `MAIL_MAX_BLOB_SIZE_KB`) would give operators finer-grained control and make the implicit framework default explicit.~~

**Resolution:** Added `max_blob_size_bytes()` config function (default 1MB, configurable via `MAIL_MAX_BLOB_SIZE_BYTES`), blob size check after base64 decode returning 413 Payload Too Large, and wired the env var through `manifests.yml.tpl` and `project.garden.yml`.

---

## Low Priority

### ~~2. Inline import in `compute_blob_digest` function body~~ — RESOLVED

**File:** `lib/exchange/src/mail.rs:46`

~~The `compute_blob_digest` function imports `use cesr::{Digest, Matter};` inside its body. Per CLAUDE.md, imports should go at the top of the file, not inline in function bodies (unless feature-gated).~~

**Resolution:** Moved `use cesr::{Digest, Matter};` to the file's top-level imports (external crate group).

---

## Positive Observations

- **Gossip multi-topic fix is correct.** The `DisconnectPeer` change in `lib/gossip/src/proto/state.rs:315-324` properly aligns with iroh's upstream semantics: `unwrap_or(false)` prevents disconnecting untracked peers, and `||` implements the "disconnect eagerly, reconnect lazily" pattern. A careful deliberate change.

- **ESSR sender serial verification is well-designed.** The fetch flow in `cmd_exchange_fetch` uses `with_establishment_key_collection` to collect the sender's verification key at the specific `sender_serial` from the envelope, correctly handling the case where the sender may have rotated keys between send and fetch. This avoids the common mistake of verifying against the current key.

- **Cumulative storage cap enforcement is thorough.** The `local_storage_for_recipient` method uses `SUM(blob_size)` with both `source_node_prefix` and `recipient_kel_prefix` filters, correctly scoping the cap to per-node-per-recipient storage without counting gossip-replicated metadata from other nodes.

- **CLI refactoring preserves behavior cleanly.** The extraction of commands into `commands/kel.rs`, `commands/exchange.rs`, `commands/cred.rs`, etc. with shared helpers in `helpers.rs` significantly improves navigability (main.rs went from ~1800 to ~576 lines) while maintaining the exact same public CLI surface.

- **SADStore handler logging improvement is valuable.** The `match` refactoring in `services/sadstore/src/handlers.rs` replaces a silent `if let` chain with explicit debug logging for all three cases (published, no Redis, no effective SAID), which will help debugging gossip propagation issues in production.

- **FFI payload memory management is correct.** The `kels_essr_open` function properly transfers payload ownership via `Box::into_raw` / `std::mem::forget`, and the corresponding `kels_essr_open_result_free` correctly reconstructs with `Vec::from_raw_parts(ptr, len, len)` — capacity equals length since it came from `into_boxed_slice()`.
