# Branch Audit: KELS-107_single-node-mail (Round 1) — 2026-04-12

Branch enables single-node mail deployment (no Redis/gossip), fixes rand advisory (RUSTSEC-2026-0097), adds `--mail-url` CLI override. ~263 lines added across 24 files.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 2        |
| Low      | 0    | 2        |

---

## Medium Priority

### ~~1. CLI fetch with `--mail-url` bypasses source node validation~~ — RESOLVED

**File:** `clients/cli/src/commands/exchange.rs:451-478`

~~When `--mail-url` is set, the fetch command skips the registry lookup entirely and uses the provided URL. This means `message.source_node_prefix` is never checked — the client fetches from whatever URL was configured, regardless of which node the message metadata says holds the blob. In standalone mode this is correct (only one node), but if a user sets `--mail-url` in federated mode, they'd silently skip the source-node routing check.~~

~~This was discussed and accepted during the session — the blob is content-addressed, signed, and encrypted, so a wrong node can't forge a valid response. Noting for documentation: the `--mail-url` override implicitly means "trust this endpoint for all fetches."~~

**Resolution:** Added a print line when the registry lookup is skipped: `"Using configured mail URL (skipping registry lookup)"`.

### ~~2. Identity service enabled for registry environments unnecessarily~~ — RESOLVED

**File:** `services/identity/garden.yml:5,26`

~~The `disabled` lines were removed entirely, meaning identity now builds and deploys in all environments. The comment says "Identity is needed in all non-registry environments" but the implementation enables it for registry too. Registry environments already had identity enabled (the original `disabled` was only for standalone), so this is not a regression — but the comment is misleading about the intent.~~

**Resolution:** Updated comment to: "Identity deploys in all environments (registry for member KEL, nodes for gossip, standalone for mail)".

---

## Low Priority

### ~~3. Test script header echo lines not indented in federated block~~ — RESOLVED

**File:** `clients/test/scripts/test-exchange.sh:43-46`

~~The echo lines inside the `if` block aren't indented. Every other `if` block in the script indents its body with 4 spaces.~~

**Resolution:** Indented the two echo lines with 4 spaces.

### ~~4. Standalone manifest duplicates 140 lines from node manifest~~ — RESOLVED

**File:** `services/mail/manifests-standalone.yml.tpl`

~~The standalone manifest is a near-exact copy of the node manifest, differing only in: no `REDIS_URL` env var, and `IDENTITY_URL` is present in standalone (added during this branch). The Service and Ingress sections (lines 112-150) are identical. This is consistent with how `services/kels/` handles it (separate `manifests-standalone.yml.tpl` vs `manifests.yml.tpl`), so it follows the existing pattern — but it's worth noting the duplication cost if more env vars diverge over time.~~

**Resolution:** Accepted as-is — follows existing project convention (`services/kels/` uses the same pattern). No code change.

---

## Positive Observations

- **Security-first reversal on default digest.** The initial approach used `cesr::Digest256::default()` as a standalone node prefix. This was caught mid-session as a security concern (non-unique prefix = no trust anchor for routing), and correctly reverted to require the identity service everywhere. Good instinct to not ship a convenience shortcut that undermines the routing trust model.

- **Clean gossip opt-out via existing patterns.** The `Option<ConnectionManager>` pattern for Redis was already in place. All three gossip publish sites were already guarded with `if let Some(ref redis)`. The branch confirms this works rather than adding new machinery — minimal code change for the mail service itself.

- **Registry lookup bypass is well-scoped.** The CLI fetch change checks `cli.mail_url` (the `Option` field, not the method) to distinguish "user explicitly set a URL" from "derived from base_domain." This avoids accidentally skipping the registry when the URL was just derived from defaults.

- **rand advisory handled at the right layers.** Direct dependencies (`cesr`, `mock-hsm`) were fixed by switching to `rand_core 0.6`. Crates that genuinely need `rand`'s higher-level API (`gossip`, `kels-core`) were pinned to `>= 0.9.3`. Transitive deps through `sqlx-postgres` got targeted exceptions. No blanket ignore.

- **Test parametrization is non-invasive.** The `FEDERATED` variable gates only the cross-node tests (phases 3b and 7) without restructuring the script. Existing federated behavior is untouched — `FEDERATED` defaults to `true`.

- **Makefile typo fix.** `text-exchange.sh` → `test-exchange.sh` caught as a drive-by. Small but would have caused a confusing failure in CI.
