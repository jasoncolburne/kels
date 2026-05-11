# Branch Audit: KELS-60_exchange (Round 5) — 2026-04-04

Exchange protocol branch: ~10362 insertions / ~3213 deletions across 115 files. Focus on new findings after all 22 findings from rounds 1-4 were resolved. Full read of lib/exchange, services/mail, services/gossip (sync, gossip_layer, bootstrap, lib, types), CLI commands, FFI exchange module, crypto module, test scripts, and migration.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 0        |
| Low      | 2    | 0        |

All 22 findings from rounds 1-4 are resolved.

---

## High Priority

No new high-priority findings.

---

## Medium Priority

No new medium-priority findings.

---

## Low Priority

### 1. `ack` handler silently swallows DB errors on delete

**File:** `services/mail/src/handlers.rs:488`

`state.repo.messages.delete(said).await.unwrap_or(false)` treats DB errors as "not deleted" — the ack count decrements but no error is surfaced. The identical pattern was fixed for `delete_expired` in round 4 (finding #3) with `match` + `warn!()` logging. While the user gets a count back and can retry, transient DB errors (connection drops, lock timeouts) remain invisible in logs.

**Suggested fix:** Replace `unwrap_or(false)` with an explicit `match` that logs a warning on `Err`, consistent with `delete_expired`.

### 2. Mail gossip feedback loop prevention cache keys are format-mismatched

**File:** `services/gossip/src/sync.rs:241,588`

`handle_mail_announcement` (line 588) inserts cache key `"mail:{said}"` (just the SAID string). `run_mail_redis_subscriber` (line 241) checks cache key `"mail:{payload}"` (the full JSON-serialized `MailAnnouncement`). These will never match each other.

Not a current bug because the `replicate`/`remove` mail endpoints don't publish to Redis, so the feedback loop this guards against doesn't exist today. However, the cache key mismatch defeats the defensive protection — if Redis publishing were later added to those endpoints, the loop would go undetected.

**Suggested fix:** Align cache key format between both paths. Extract the SAID from the announcement in `run_mail_redis_subscriber` and use `"mail:{said}"` consistently, or serialize in `handle_mail_announcement` and use `"mail:{json}"` consistently.

---

## Positive Observations

- **Test common library extraction is excellent DRY cleanup.** `test-common.sh` consolidates ~30 helper functions (`run_test`, `wait_for_convergence`, `fetch_all_events`, `get_kel_hash`, etc.) that were previously duplicated across test scripts. Clean API with consistent color output and timeout semantics.

- **Mail gossip integration is well-coordinated.** The three-layer flow — Redis subscriber → gossip broadcast → peer sync handler → mail client replicate/remove — is cleanly separated. The `GossipCommand::Mail` variant and `MailAnnouncementReceived` event type slot in naturally alongside the existing KEL and SAD gossip paths.

- **GossipCommand rename from `AnnounceKel`/`AnnounceSad` to `Kel`/`Sad`/`Mail` is cleaner.** The shorter, consistent naming reduces verbosity and makes the three-topic symmetry clear.

- **Bootstrap and SADStore logging improvements aid operational debugging.** The SAD pointer chain preload now reports a chain count (`"SAD pointer chain preload complete: 42 chains synced"`), the SADStore publish handler uses a `match` with debug logging for all three cases (published, no Redis, no effective SAID), and bootstrap KEL syncs demote from `info!` to `debug!` to reduce noise.

- **All prior findings resolved comprehensively across four rounds.** The cumulative storage cap, sequential blob writes, sender serial lookups, file permissions, blob size limits, ack caps, import ordering, GC blob digest fix, and unchecked string slicing — all 22 findings across rounds 1-4 are fully addressed.

- **ESSR protocol and mail service are production-ready quality.** After five rounds of audit, the core security properties (authentication, rate limiting, integrity verification, sender privacy, key rotation) are all solid. The remaining findings are defensive code quality issues, not correctness or security bugs.
