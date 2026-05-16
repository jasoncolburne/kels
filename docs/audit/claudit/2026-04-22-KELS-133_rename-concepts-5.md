# Branch Audit: KELS-133_rename-concepts (Round 5) — 2026-04-22

Branch `KELS-133_rename-concepts` vs `main`: 87 files, 3007 insertions / 2439 deletions. Cold re-read after `/clear`, focused on areas the prior four rounds touched least: the SAD transfer/verification API surface, the sibling design doc whose accessor list was asserted to be complete in round 4, and user-facing log/prose that kept "chain record" / "chain update" wording after the rename to "SAD event" / "SAD Event Log". Total resolved cumulatively across rounds 1–4: 24.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 2        |
| Low      | 0    | 3        |

Cumulative across rounds 1–5: 29 resolved.

---

## Medium Priority

### ~~1. `docs/design/sad-events.md:119` accessor list is missing `establishment_version()` — the same defect round 4 fixed in the sibling `sadstore.md`~~ — RESOLVED

**File:** `docs/design/sad-events.md:119`; struct at `lib/kels/src/types/sad/event.rs:296-358`; sibling at `docs/design/sadstore.md:92`

~~Round 4 finding #2 identified that `docs/design/sadstore.md:92` was missing three accessors (`policy_satisfied`, `last_governance_version`, `establishment_version`) added by the governance-policy work. The resolution note for that finding asserts:~~

> ~~The sibling doc (`docs/design/sad-events.md:119`) enumerates the full list~~

~~It does not. Current text at `sad-events.md:119`:~~

```
Accessors: `current_record()`, `current_content()`, `prefix()`, `write_policy()`,
`topic()`, `policy_satisfied()`, `last_governance_version()`.
```

~~That's seven accessors. The struct at `event.rs:296-358` exposes eight. After round 4's fix, `sadstore.md:92` lists all eight. `sad-events.md:119` still lists seven. The two design docs now disagree on the token's accessor surface — the exact inverse of the round 4 finding.~~

**Resolution:** Appended `, \`establishment_version()\`` to the accessor list at `sad-events.md:119` and added a cross-reference back to `sadstore.md#verification`, symmetric to sadstore's existing pointer here for the governance-accessor semantics. Both design docs now enumerate the full eight-accessor surface.

### ~~2. SAD transfer functions are singular (`verify_sad_event`, `forward_sad_event`) where KEL siblings are plural (`verify_key_events`, `forward_key_events`) — asymmetric public API~~ — RESOLVED

**File:** `lib/kels/src/types/sad/sync.rs`; `lib/kels/src/lib.rs`; `lib/kels/src/client/sadstore.rs`; `services/sadstore/src/handlers.rs`; `services/sadstore/src/server.rs`; `lib/ffi/src/sad.rs`; `lib/ffi/src/lib.rs`; `clients/cli/src/commands/{sel,exchange,mail}.rs`; `services/gossip/src/{sync,bootstrap}.rs`

~~KEL-side paging infrastructure uses plural naming across the board: `transfer_key_events`, `verify_key_events`, `forward_key_events`. The SAD-side equivalents ended up singular, even though each pages through *many* events and takes `Vec<SadEvent>` or returns `SadEventPage`. The private helper `send_divergent_sad_events` (line 287) is plural — an internal acknowledgment that the function handles multiple events. The public API is not. The URL paths are already plural (`/api/v1/sad/events`), the types are plural-valued, and round 1 explicitly renamed the response type to `SubmitSadEventsResponse` for exactly this reason: parallelism with `SubmitKeyEventsResponse`. The rename committee recognized the symmetry but didn't carry it to the transfer functions.~~

**Resolution:** Renamed throughout the call graph. Two distinct conventions apply by role:

**Plural `sad_events`** — functions that traffic in event batches (analogous to `key_events`):
- `lib/kels/src/types/sad/sync.rs`: `transfer_sad_event` → `transfer_sad_events`, `verify_sad_event` → `verify_sad_events`, `forward_sad_event` → `forward_sad_events`
- `SadStoreClient`: `submit_sad_event` → `submit_sad_events`, `fetch_sad_event` → `fetch_sad_events`, `verify_sad_event` → `verify_sad_events`
- Handler: `submit_sad_event` → `submit_sad_events`, `get_sad_event` → `get_sad_events`
- FFI: `kels_sad_submit_event` → `kels_sad_submit_events`, `kels_sad_fetch_event` → `kels_sad_fetch_events` (C ABI break — contained within the repo; Swift client rebuilds from the cbindgen header)
- FFI tests: `test_sad_{submit,fetch}_event_*` → `test_sad_{submit,fetch}_events_*`

**`sel_` prefix** — functions operating on the SEL (SAD Event Log) as a whole concept, rather than on the events within it:
- `SadStoreClient`: `fetch_sad_event_effective_said` → `fetch_sel_effective_said`, `fetch_sad_event_prefixes` → `fetch_sel_prefixes`, `fetch_sad_event_repairs` → `fetch_sel_repairs`, `fetch_sad_event_repair_records` → `fetch_sel_repair_events`
- Handler: `get_sad_event_effective_said` → `get_sel_effective_said`, `list_sad_event_prefixes` → `list_sel_prefixes`, `get_sad_event_repairs` → `get_sel_repairs`, `get_sad_event_repair_records` → `get_sel_repair_events`, `test_list_sad_event_prefixes` → `test_list_sel_prefixes`

`sad_event_exists` kept singular — it checks whether *one* event exists by SAID, so singular is correct. All Axum route registrations in `server.rs`, the `lib.rs` crate-root re-exports, the `lib/ffi/src/lib.rs` FFI re-exports, and every caller in the CLI, FFI tests, gossip bootstrap, gossip sync, and gossip anti-entropy loops updated. `make clippy` and `make test` both pass; the `make deny` failure is an unrelated `rustls-webpki` RUSTSEC-2026-0104 advisory preexisting on this branch.

Post-fix grep for `(transfer|verify|forward|fetch|submit|get|list)_sad_event\b|kels_sad_(submit|fetch)_event\b|test_sad_(submit|fetch)_event\b|test_list_sad_event_prefixes` across the tree (excluding `docs/claudit/**`) returns zero hits.

---

## Low Priority

### ~~3. `PolicyChecker::satisfies` docstring says "last checkpoint version" where the tracked field is role-named `last_governance_version`~~ — RESOLVED

**File:** `lib/kels/src/types/sad/verification.rs:20-22`

~~The trait doc enumerates the branch-state fields whose advances are gated on the returned value. Three of the four items are role-named (`tracked write_policy`, `tracked governance_policy`, `establishment version`). The fourth is mechanism-named (`last checkpoint version`). The actual field is `last_governance_version` — role-named, matching the struct field at `verification.rs:87` and the public accessor at `event.rs:340`. Same mechanism-for-role slip the round 3 sweep resolved in shell scripts, Rust handlers, and test comments.~~

**Resolution:** `last checkpoint version` → `last governance version` in the docstring at `verification.rs:22`. All four items in the gated-field enumeration are now role-named, matching the fields themselves.

### ~~4. Stale "chain update" log/prose in the SADStore handler and gossip lib~~ — RESOLVED

**File:** `services/sadstore/src/handlers.rs:1526`, `:1531`, `:1536`, `:1542`; `services/gossip/src/lib.rs:571`

~~Five string/comment remnants still described the SEL gossip path as "chain update" after the rename established "SEL update". Initial finding flagged three; scanning the surrounding block surfaced two more (`Skipping chain publish` debug logs at `:1536` and `:1542`).~~

**Resolution:**
- `handlers.rs:1526`: `"Failed to publish chain update: {}"` → `"Failed to publish SEL update: {}"`
- `handlers.rs:1531`: `"Published chain update to Redis"` → `"Published SEL update to Redis"`
- `handlers.rs:1536`: `"Skipping chain publish: no Redis connection"` → `"Skipping SEL publish: no Redis connection"`
- `handlers.rs:1542`: `"Skipping chain publish: no effective SAID"` → `"Skipping SEL publish: no effective SAID"`
- `gossip/src/lib.rs:571`: `// Start SAD Redis subscriber (listens for SAD object and chain updates)` → `// Start SAD Redis subscriber (listens for SAD object and SEL updates)`

The log lines now align with the `sel_updates` Redis channel name they reference; `docs/gossip.md:108-109` and the publisher at `handlers.rs:1521` already used the current terminology.

### ~~5. `SADSTORE_MAX_RECORDS_PER_EVENT_LOG_PER_DAY` env var documented as "Max chain records per prefix per day" — description hadn't caught up to the variable name~~ — RESOLVED

**File:** `docs/design/sadstore.md:195`; `services/sadstore/src/handlers.rs:137`

~~Round 2 finding #2 renamed the Garden/manifest/env-var identifiers to carry the "event log" concept end-to-end, but the canonical description in `sadstore.md:195` and the adjacent handler doc comment at `handlers.rs:137` still said "chain records" — creating an internal contradiction in a single config-table row.~~

**Resolution:**
- `sadstore.md:195`: description column changed from "Max chain records per prefix per day" to "Max SAD events per SEL prefix per day".
- `handlers.rs:137`: doc comment changed from "Max chain records per prefix per day. Low — chains represent stable state." to "Max SAD events per SEL prefix per day. Low — SELs represent stable state."

Env var name, consumer call, Garden variable, manifest reference, and now the description + doc comment all carry the same SEL / SAD event terminology.

---

## Positive Observations

- **Rounds 1–4 cumulative resolutions all hold under cold reading.** Fresh greps for `SadPointer`, `SadChain`, `checkpoint_policy`, `SadGossipMessage`, `SubmitPointersResponse`, `:repair` Redis suffix, `?repair=true` query param, `cp_said`, `chain_cp_said`, `CHECKPOINT_POLICY_SAID`, `test_event_kind_`, `test_sad_gossip_message`, and `kels/v1/` test topics all returned zero hits outside `docs/claudit/**` at round-5 start. The 24 cumulative findings remained fixed; round 5 surfaced five new stragglers (two medium, three low), all now resolved.

- **`SadAnnouncement` wire type is the cleanest form possible.** Three fields per `Event` variant (`prefix, said, origin`), two per `Object` (`said, origin`), no `#[serde(default)]` attributes, no back-compat aliases, no `:repair` suffix. The `services/gossip/src/types/sad.rs` test round-trips both variants exactly. Any simpler and the contract loses information; any richer and stale docs start accumulating.

- **`SelVerifier` defense-in-depth R5/R6 gates are exhaustively tested.** The five tests at `verification.rs:727-939` cover every branch-state advance gated on the soft-wp flag, including the chain-wide-vs-branch-scoped divergent-Est asymmetry that the `establishment_version()` docstring calls out. A subtle invariant has a loud, principled test signal behind it.

- **Finding #2's `sel_` vs `sad_events` split is principled, not arbitrary.** Functions that traffic in event batches keep `sad_events` (`submit_sad_events`, `fetch_sad_events`, `get_sad_events`, `verify_sad_events`, `forward_sad_events`, `transfer_sad_events`, `kels_sad_submit_events`, `kels_sad_fetch_events`). Functions that operate on the SEL as a whole concept — its effective SAID, its prefix listing, its repair history — got the `sel_` prefix (`fetch_sel_effective_said`, `list_sel_prefixes`, `get_sel_repairs`, `get_sel_repair_events`, `test_list_sel_prefixes`). Reading a call site now tells you whether the operation is event-level or SEL-level without looking up the signature.

- **`AGENTS.md` Core Concepts section reads as a terminology dictionary.** Post-rename, a newcomer can read the ten entries under "Core Concepts" and get the complete role/mechanism split (Prefix, SAID, KEL, Divergence, Effective SAID, Policy, Credentials, Exchange, Federation, **SAD Event Log**) without any ambiguity. The SAD Event Log entry at line 59 anchors the term and points to `docs/design/sad-events.md`.

- **CLI subcommand split is stable.** `kels-cli {kel,sel,sad,exchange,mail,cred,dev,adversary}` at `clients/cli/src/main.rs:52-87` reads as an ontology: identity lifecycle, SEL protocol, SAD object protocol, ML-KEM key protocol, ESSR messaging, credentials, dev-tools. The `sel submit/get/prefix` subcommands at `clients/cli/src/commands/sel.rs` are each three lines of glue — all the heavy lifting is in `kels_core`, so the CLI layer stays thin.

- **SQL schema and FK graph are uniformly renamed end-to-end.** `services/sadstore/migrations/0001_initial.sql` uses `sad_events` / `sad_event_archives` / `sad_event_repairs` / `sad_event_repair_records` with FKs that follow the parent-table renames. The `#[storable(table = "...")]` attributes on the Rust structs all line up.

- **`submit_sad_events` handler's verify-then-extend flow is a compact audit target.** `services/sadstore/src/handlers.rs` puts the entire submit pipeline — advisory lock, dedup, rate limit, repair auto-detection, two-path verification (normal vs repair), establishment-seal check, save, publish — in one function. The repair path's four gates all appear in sequence so a reader can trace the trust model without jumping files.
