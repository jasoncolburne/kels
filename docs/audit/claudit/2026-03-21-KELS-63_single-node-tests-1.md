# Branch Audit: KELS-63_single-node-tests (Round 1) — 2026-03-21

Single-node standalone deployment mode: 22 files changed, ~933 diff lines. Redis made optional, standalone K8s manifests, CHAR(44)→TEXT migrations, test script fixes, new load test script, Makefile targets for `test-node` and `test-federation`.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 2        |
| Low      | 0    | 2        |

---

## High Priority

No high-priority findings.

---

## Medium Priority

### ~~1. Garden ternary may eagerly resolve `actions.run.federation-read-urls.outputs.log` in standalone mode~~ — RESOLVED

**File:** `services/kels/garden.yml:39`

~~The `federationRegistryUrls` variable uses a ternary expression that references `actions.run.federation-read-urls.outputs.log`. Concern was that Garden might eagerly evaluate both branches, failing in standalone mode.~~

**Resolution:** The `federation-read-urls` script (`scripts/federation-read-urls.sh`) safely handles the missing `.kels/federated-registries.json` file by outputting an empty string and exiting 0. Even if Garden evaluates the action, it produces empty output. Downstream, `main.rs` filters empty strings from `FEDERATION_REGISTRY_URLS`, resulting in an empty `registry_urls` vec. The entire chain is safe.

### ~~2. Standalone manifest readiness probe uses `/health` instead of `/ready`~~ — RESOLVED

**File:** `services/kels/manifests-standalone.yml.tpl:48-52`

~~The readiness probe checks `/health` instead of `/ready`. In standalone mode `/ready` always returns `200`, so it would be safe but provides no real benefit — both succeed immediately. In federated mode, using `/ready` as a readiness probe would deadlock: kels waits for gossip to set `kels:gossip:ready`, but gossip needs kels to be routable, which requires passing the readiness probe.~~

**Resolution:** Won't fix. `/health` is correct and consistent across both manifest templates. No practical benefit to changing it.

---

## Low Priority

### ~~3. Inline `use redis::AsyncCommands` import inside function body~~ — RESOLVED

**File:** `services/kels/src/handlers.rs`

~~Three `use redis::AsyncCommands;` imports were placed inside function bodies (`ready()`, `get_verified_peer()`, `refresh_verified_peers()`). None were in feature-gated blocks, violating the CLAUDE.md import convention.~~

**Resolution:** Moved `use redis::AsyncCommands` to the top-level imports in Group 2 (external crates). Also moved `use kels::...` from Group 2 to Group 3 (local/repo imports) where it belongs per CLAUDE.md.

### ~~4. Standalone manifests missing rate-limiting environment variables~~ — RESOLVED

**File:** `services/kels/manifests-standalone.yml.tpl`

~~The standalone template only set `RUST_LOG`, `DATABASE_URL`, and `KELS_TEST_ENDPOINTS`, missing the rate-limiting env vars present in the federated template.~~

**Resolution:** Added `KELS_MAX_SUBMISSIONS_PER_PREFIX_PER_MINUTE`, `KELS_MAX_WRITES_PER_IP_PER_SECOND`, `KELS_IP_RATE_LIMIT_BURST`, and `KELS_NONCE_WINDOW_SECS` to the standalone manifest.

---

## Positive Observations

- **Clean Redis optionality via `Option` types.** The `AppState` fields `kel_cache` and `redis_conn` are wrapped in `Option`, and all call sites use `if let Some(ref ...)` with let-chains. This is idiomatic Rust and avoids any feature-flag complexity — the same binary works in both modes, selected purely by environment.

- **Correct fail-secure behavior for peer verification in standalone mode.** The `list_prefixes` handler explicitly returns `ApiError::forbidden("Peer verification unavailable in standalone mode")` when Redis is unavailable, rather than silently allowing unauthenticated access. This follows the project's fail-secure principle.

- **CHAR(44)→TEXT migration is a sound simplification.** The CESR encoding of ML-DSA keys and signatures produces values longer than 44 characters, making the previous `CHAR(44)` constraints incorrect for the new post-quantum algorithms. Using `TEXT` removes the length constraint entirely, which is appropriate since validation happens at the application layer (CESR parsing), not at the database layer.

- **Test script `sort_by(.label)` fix is correct.** The previous `sort_by(.publicKey)` was broken because the signature JSON structure changed to use `label` instead of `publicKey` as the key identifier. This fix ensures deterministic signature ordering for hash comparison across nodes.

- **Good separation of `test-node` and `test-federation` targets.** Splitting the monolithic `test-comprehensive` into `test-node` (~2 min) and `test-federation` (~22 min) provides a fast feedback loop for changes that only affect core KEL logic, without requiring a full federation deployment.

- **Well-scoped standalone environment configuration.** The Garden environment correctly disables identity, gossip, redis, and registry services via `disabled: ${var.envType == "standalone"}`, preventing unnecessary resource consumption and startup failures from missing dependencies.
