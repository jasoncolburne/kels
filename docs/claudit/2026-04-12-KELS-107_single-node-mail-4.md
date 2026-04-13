# Branch Audit: KELS-107_single-node-mail (Round 4) — 2026-04-12

Branch enables single-node mail deployment (no Redis/gossip), fixes rand advisory (RUSTSEC-2026-0097), adds `--mail-url` CLI override. ~936 diff lines across 27 files. All 12 findings from rounds 1-3 are resolved.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 0        |
| Low      | 0    | 0        |

---

No new findings. The branch is clean after three rounds of fixes.

---

## Positive Observations

- **Manifest pair is correctly differentiated.** `manifests-node.yml.tpl` has 4 initContainers (postgres, minio, identity, redis) and `REDIS_URL` in env. `manifests-standalone.yml.tpl` has 3 initContainers (no redis) and no `REDIS_URL`. The env var delta is exactly one line — minimal divergence surface.

- **Garden dependency graph handles the Redis optionality correctly.** Removing `deploy.redis` from `garden.yml` dependencies and relying on the `wait-for-redis` initContainer in the node manifest is the right approach — Garden can't express conditional dependencies on `envType`, so the initContainer provides the ordering guarantee in federated mode while allowing standalone to skip Redis entirely.

- **`mail_url` field vs method distinction is used precisely.** The four non-fetch commands (send, inbox, ack, publish-key) all use `cli.mail_url()` (the method, which falls back to base_domain). Only the fetch command checks `cli.mail_url` (the raw Option field) to decide whether to skip the registry lookup. This prevents a base_domain-derived URL from accidentally triggering the bypass.

- **Test script standalone mode is self-contained.** When `FEDERATED=false`, the CLI is configured with explicit `--kels-url`, `--sadstore-url`, and `--mail-url` flags, avoiding any reliance on DNS-based subdomain routing that wouldn't exist in a single-node deployment. The `CLI_B` variable is never defined in this path, and all three references to it are correctly guarded.

- **Advisory exception comments form a consistent pattern across all deny.toml files.** Every RUSTSEC-2026-0097 exception follows the same template: `# rand 0.8 unsoundness in ThreadRng — transitive dep via sqlx-postgres; we don't use ThreadRng`. This makes it trivial to grep and bulk-remove them when sqlx upgrades.

- **The `StdRng::from_os_rng()` choice in the gossip library is correct for long-lived state.** The HyParView `State` struct holds the RNG across many shuffle rounds. `StdRng` (a CSPRNG seeded from OS entropy) is appropriate here — it provides deterministic-per-seed behavior for testing while remaining cryptographically secure in production. The gossip service's one-shot `choose()` calls correctly use the lighter `OsRng` instead.
