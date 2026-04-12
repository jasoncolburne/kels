# Branch Audit: KELS-107_single-node-mail (Round 2) — 2026-04-12

Branch enables single-node mail deployment (no Redis/gossip), fixes rand advisory (RUSTSEC-2026-0097), adds `--mail-url` CLI override. ~335 lines changed across 25 files. All 4 findings from round 1 are resolved.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 3        |
| Low      | 0    | 2        |

---

## Medium Priority

### ~~1. garden.yml comment references nonexistent wait-for-redis initContainer~~ — RESOLVED

**File:** `services/mail/manifests-node.yml.tpl`

~~The comment says "In federated deployments, the wait-for-redis initContainer handles startup ordering." However, `manifests-node.yml.tpl` had no `wait-for-redis` initContainer — only `wait-for-postgres`, `wait-for-minio`, and `wait-for-identity`. Other services (kels, gossip) did have one.~~

**Resolution:** Added `wait-for-redis` initContainer to `manifests-node.yml.tpl`, matching the pattern in kels and gossip manifests.

### ~~2. CLI fetch with `--mail-url` bypasses source node validation~~ — RESOLVED

*From round 1.* **Resolution:** Print line added when registry lookup is skipped.

### ~~3. Identity service enabled for registry environments unnecessarily~~ — RESOLVED

*From round 1.* **Resolution:** Comment updated to reflect actual deployment scope.

---

## Low Priority

### ~~4. Test script header echo lines not indented in federated block~~ — RESOLVED

*From round 1.* **Resolution:** Indented.

### ~~5. Standalone manifest duplicates 140 lines from node manifest~~ — RESOLVED

*From round 1.* **Resolution:** Accepted — follows existing project convention.

---

## Positive Observations

- **ThreadRng removal is thorough and consistent.** Every direct use of `ThreadRng`/`thread_rng()` was replaced — `StdRng::from_os_rng()` in the gossip library (where the RNG is held in state), `OsRng` in the gossip service sync loops (where it's a one-shot `choose()`). A grep confirms zero remaining code references to `ThreadRng` or `thread_rng`.

- **Advisory exceptions are precise and well-documented.** Each `deny.toml` exception for RUSTSEC-2026-0097 includes a comment explaining the transitive dependency path (`sqlx-postgres`) and why the advisory doesn't apply ("we don't use ThreadRng"). No blanket ignores.

- **CLI `--mail-url` follows established patterns.** The new `mail_url` field/method pair exactly mirrors the existing `kels_url` and `sadstore_url` patterns — `Option<String>` field, `fn mail_url()` method with `unwrap_or_else` fallback to `base_domain`. Consistent API surface.

- **Test script `FEDERATED` gating is minimal and correct.** Only the three sections that truly require a second node (Phase 3b key lookup, Phase 7 cross-node gossip, and `CLI_B` setup) are gated. Everything else — KEL creation, key publication, ESSR send, inbox check, fetch/decrypt, ack — runs in both modes.

- **`rand` dependency cleanly removed from CLI.** The `rand = "0.8"` dependency in `clients/cli/Cargo.toml` was unused (no `use rand` in any CLI source file) and was removed. No dead dependencies left behind.

- **Standalone manifest correctly omits Redis while preserving identity.** The standalone manifest has `IDENTITY_URL` (needed for node prefix) but no `REDIS_URL` — exactly the right env var delta for a single-node deployment.
