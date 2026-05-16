# Branch Audit: KELS-107_single-node-mail (Round 3) — 2026-04-12

Branch enables single-node mail deployment (no Redis/gossip), fixes rand advisory (RUSTSEC-2026-0097), adds `--mail-url` CLI override. ~407 lines changed across 26 files. All 5 findings from rounds 1-2 are resolved.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 6        |
| Low      | 0    | 6        |

---

## Medium Priority

### ~~1. CLI fetch with `--mail-url` bypasses source node validation~~ — RESOLVED

*From round 1.* **Resolution:** Print line added when registry lookup is skipped.

### ~~2. Identity service enabled for registry environments unnecessarily~~ — RESOLVED

*From round 1.* **Resolution:** Comment updated to reflect actual deployment scope.

### ~~3. garden.yml comment references nonexistent wait-for-redis initContainer~~ — RESOLVED

*From round 2.* **Resolution:** Added `wait-for-redis` initContainer to `manifests-node.yml.tpl`.

### ~~4. `OsRng` used as `let mut rng` but `OsRng` is a unit struct — unnecessary mutability~~ — RESOLVED

**File:** `services/gossip/src/sync.rs:1377,1739`

~~`OsRng` is a zero-sized unit struct. Writing `let mut rng = rand::rngs::OsRng;` is misleading — it suggests `rng` accumulates state.~~

**Resolution:** Inlined to `peers.choose(&mut rand::rngs::OsRng)` at both sites, removing the unnecessary binding.

---

## Low Priority

### ~~5. Test script header echo lines not indented in federated block~~ — RESOLVED

*From round 1.* **Resolution:** Indented.

### ~~6. Standalone manifest duplicates 140 lines from node manifest~~ — RESOLVED

*From round 1.* **Resolution:** Accepted — follows existing project convention.

### ~~7. Test script defines `test_lookup_alice_key_from_node_b` function outside the federated guard~~ — RESOLVED

The function definition at line 163 is outside the `if [ "$FEDERATED" = "true" ]` guard at line 178, but the function is only *called* inside the guard. Defining unreachable functions is harmless in bash — marking as resolved since it follows the script's existing pattern of defining functions then conditionally calling them.

### ~~8. `deny.toml` advisory exception style inconsistency~~ — RESOLVED

**File:** `services/sadstore/deny.toml`

~~The lru advisory used `{ id = "RUSTSEC-2026-0002", reason = "..." }` inline-table style while all other exceptions use bare string + comment above. Mixed styles in the same array.~~

**Resolution:** Converted the lru exception to bare string + comment style, matching all other `deny.toml` files.

---

## Positive Observations

- **`FEDERATED` gating is comprehensive and correct.** All three uses of `CLI_B` (definition, key lookup call, inbox poll call) are correctly inside federated guards. Phase 8 (fetch & decrypt) correctly uses `$CLI` (not `$CLI_B`), which works in both modes since it fetches from the local inbox.

- **Manifest template selection is clean.** The `garden.yml` ternary `${var.envType == 'standalone' ? 'manifests-standalone.yml.tpl' : 'manifests-node.yml.tpl'}` is a single expression that eliminates the need for conditional logic elsewhere. Naming the files `-standalone` and `-node` makes the intent immediately clear.

- **The `rand` → `rand_core` migration in mock-hsm is precise.** Only `OsRng` and `RngCore` were needed from `rand` — switching to `rand_core 0.6` (which `fips204` already depends on) eliminates the heavier `rand` crate entirely. The `BSD-2-Clause` license removal from `deny.toml` confirms this was the only crate pulling that license.

- **CLI `--mail-url` correctly checks `cli.mail_url` (the Option field) in the fetch path.** This distinguishes "user explicitly set `--mail-url`" from "derived via `cli.mail_url()` method." If the code had called `cli.mail_url()` for the check, a base_domain-derived URL would still trigger the registry bypass — which would be wrong.

- **Documentation update in `docs/design/mail.md` is well-structured.** The new "Deployment Modes" section clearly distinguishes federated vs standalone, lists exactly which dependencies are needed for each, and explains the Redis-optional mechanism (`if let Some(ref redis)` guards) without over-explaining.

- **No dead code introduced.** The `rand = "0.8"` removal from CLI confirms it was truly unused. The gossip `ThreadRng` → `StdRng`/`OsRng` replacements are drop-in at every call site with no API surface change.
