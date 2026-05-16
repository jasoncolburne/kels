# Branch Audit: KELS-133_rename-concepts (Round 11) — 2026-04-23

Branch `KELS-133_rename-concepts` vs `main`: 114 files, 4046 insertions / 2627 deletions. No commits since round 10 (`git log 46b50d0..HEAD` empty at audit time; working tree clean). Cold re-read after `/clear`, focused on surfaces that prior rounds either explicitly deferred or swept only partially — specifically: (a) the `services/gossip/src/types/sad.rs` announcement type that round 10 named as "out of scope for this pass," (b) the `clients/test/scripts/test-sadstore.sh` shell-variable and banner drift that rounds 9 and 10 never scoped (round 9 #1 swept `load-sad.sh` but not this file), and (c) the `docs/endpoints.md` SADStore endpoint table and notes (rounds 8 #5 and 9 #7 swept sibling prose but not the table rows themselves). Rounds 1–10 cumulatively resolved 63 findings.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 1        |
| Low      | 0    | 2        |

Cumulative across rounds 1–10: 63 resolved. Round 11 surfaces 3 new open findings: 1 medium (gossip announcement-type rustdoc drift — round 10 explicitly deferred this site), 2 low (test-script variable/banner drift and endpoints.md endpoint-table drift). None of these contradict a prior round's explicit preservation judgment — each is at a surface no prior round swept to completion, and in two cases the user pushed back in earlier rounds that "file not in diff / out of scope" is a weak reason.

---

## Medium Priority

### ~~1. `SadAnnouncement::Event::prefix` rustdoc says `"The event prefix that was updated."` — inconsistent with its own sibling field and the containing variant's renamed vocabulary~~ — RESOLVED

**File:** `services/gossip/src/types/sad.rs:21`

~~The enum variant containing this field is `SadAnnouncement::Event`, documented at `:19` as `"A SAD Event Log was updated."`. The sibling field at `:23-24` reads `"The SAID of the latest SAD event."` — already role-named. But the `prefix` field at `:21` still says `"The event prefix that was updated."` — the pre-round-10 short form. Round 10's finding #8 established `"SEL prefix"` as the canonical discovery-narrative form (resolved at `lib/exchange/src/key_publication.rs:13` and `docs/design/exchange.md:91`), and the round 10 summary-prose explicitly listed this file as "not in scope of any round-10 finding — out of scope for this pass." Two subsequent positive-observation-style claims and the round 10 tail grep both noted this was the last residual `"event prefix"` short-form site outside `docs/claudit/**` and explicit-preservation contexts.~~

~~The announcement type is used for on-the-wire gossip between peers (topic `kels/sad/v1`, visible to all federation nodes), but the rustdoc is not itself wire-format — the field is serde-named `prefix` via `rename_all = "camelCase"`. Only the documentation disagrees with its siblings.~~

**Resolution:** `/// The event prefix that was updated.` → `/// The SEL prefix that was updated.` at `services/gossip/src/types/sad.rs:21`. Matches the sibling field at `:23-24` (`"The SAID of the latest SAD event."`) and round 10's canonical `"SEL prefix"` form. `make check` passes cleanly.

---

## Low Priority

### ~~2. `clients/test/scripts/test-sadstore.sh` — `CHAIN_PREFIX` shell variable (9 sites), `"Scenario 5: Chain Record Submission via CLI"` banner, and `"build chain events"` prose~~ — RESOLVED

**File:** `clients/test/scripts/test-sadstore.sh:226, 228, 229, 253, 254, 255, 258, 269, 273, 292, 299`

~~Round 9 #1's resolution text explicitly listed the files it swept for `chain_prefix` → `sel_prefix` ("confirmation sweep surfaced the same pattern in four additional files… `services/sadstore/src/handlers.rs` (14 sites…), `clients/cli/src/commands/exchange.rs`, `clients/cli/src/commands/mail.rs`, `clients/test/scripts/load-sad.sh`") but did not include `test-sadstore.sh`. A tree-wide `git grep -n 'chain_prefix\|chain prefix\|Chain Prefix\|CHAIN_PREFIX'` excluding `docs/claudit/**` shows 9 hits in `test-sadstore.sh` and zero elsewhere — this file is the sole remaining outpost for the `chain_prefix` identifier family. Two adjacent sites carry the same-class drift:~~

~~- **`:226, :228`** — `"# Scenario 5: Chain Record Submission via CLI"` / `"=== Scenario 5: Chain Record Submission via CLI ==="` — `"Record Submission"` is pre-round-9 vocabulary; the scenario's actual CLI invocation at `:289` is `kels-cli ... sel submit`, and the round 9 #3 resolution renamed the analogous CLI output string to `"N SAD event(s) submitted"`. The banner should match.~~
~~- **`:229`** — `"Create a KEL, build chain events, submit via CLI, fetch via CLI"` — `"chain events"` is the structural-short form; the rest of the sentence is role-named. Per round 10's positive observation #2, the structural `"event chain"` phrasing is principled when describing shape, but in this sentence the parallelism to `submit via CLI` / `fetch via CLI` calls for the role name (`build SAD events`).~~

~~For contrast, the user-visible `echo`s at `:254-255` already read `"SEL prefix: $CHAIN_PREFIX"` / `"SEL prefix computed"` — the output is role-named but the variable holding the value is still shell-style `CHAIN_PREFIX`. The round 9 #1 rubric ("function parameters, for-loop bindings, struct-destructure binding, all format-string arguments") calls for shell-variable renames of this form.~~

**Resolution:**
- `sed -i '' 's/CHAIN_PREFIX/SEL_PREFIX/g' clients/test/scripts/test-sadstore.sh` — renamed all 9 variable references uniformly (lines 253, 254, 255, 258, 269, 273, 292, 299).
- `:226, :228` — `"Chain Record Submission"` → `"SAD Event Submission"` (via `replace_all`; updates both the section divider comment and the `echo` banner in one pass).
- `:229` — `"build chain events"` → `"build SAD events"`.

Structural uses preserved per the stated rubric: `:107` (`wait_for_chain_propagation`), `:257` (`"Chain does not exist yet"`), `:294` (`"Chain fetched via CLI (sel get) with 2 events"`), `:298` (`"Chain propagated to node-b"`) — all describe SEL shape/state as bare nouns. Post-fix grep `CHAIN_PREFIX\|Chain Record\|chain events` on the file returns zero hits. Shell-only change; no `make` run required for the script fixes.

### ~~3. `docs/endpoints.md:145-160` — SADStore endpoint table and notes carry pre-rename vocabulary in route descriptions and client-workflow prose~~ — RESOLVED

**File:** `docs/endpoints.md:145, 146, 149, 150, 157, 160`

~~Round 9 #7 swept the SADStore section *lead paragraph* (`:136`, `"authenticated chained records (PostgreSQL)"` → `"authenticated SAD Event Logs (PostgreSQL)"`), and round 8 #5 swept the inline notes below the table. The table rows and trailing notes at `:145-160` were the middle layer between them and were not swept in either round. Six sites:~~

~~- **`:145`** — `POST /api/v1/sad/events` description: `"Submit chain event(s) (\`Vec<SadEvent>\`) — each record's SAID must be anchored…"` — parenthetical type `Vec<SadEvent>` is role-named but the English prefix `"chain event(s)"` and the mid-phrase `"each record's SAID"` are both pre-rename.~~
~~- **`:146`** — `POST /api/v1/sad/events/fetch` description: `"Fetch chain;"` — `"chain"` as bare noun for the returned content should be `"SAD Event Log"` (the type returned is `SadEventPage`).~~
~~- **`:149`** — `POST /api/v1/sad/events/repairs` description: `"Get paginated repair records; ... returns SadEventRepairPage"` — the returned rows are `SadEventRepair` structs, so the English should read `"repair entries"` or `"SAD event repair records"` (disambiguating "records" from the pre-rename SAD-record usage). Borderline; the structural term `"repair records"` is defensible per round 10 positive-observation #2, but the mixed vocabulary (English says "records", struct says `SadEventRepair`) calls for a minor alignment.~~
~~- **`:150`** — `POST /api/v1/sad/events/repairs/records` description: `"Get archived records for a specific repair; ... returns SadEventPage"` — returns are `SadEvent` items, so the English `"archived records"` should read `"archived SAD events"` to match the returned `SadEventPage` items.~~
~~- **`:157`** — Notes paragraph: `"Verifies event SAID, verifies write_policy via KEL-anchoring (endorsers required by the policy must have anchored the record's SAID…)"` — `"the record's SAID"` is pre-rename; the surrounding prose says `"event SAID"` and `"write_policy"`. Should read `"the event's SAID"`.~~
~~- **`:160`** — Notes paragraph: `"Chain events reference content in MinIO via content_said. Client workflow: POST content first, then POST chain event."` — `"chain event"` (twice) is the pre-rename short form; round 9 #3/#4's resolutions settled `"SAD event"` as the role-named term. Should read `"SAD events"` / `"POST SAD event"`.~~

**Resolution:** All six sites swept in place:
- `:145` → `"Submit SAD event(s) (\`Vec<SadEvent>\`) — each event's SAID must be anchored via ixn in its endorsers' KELs per \`write_policy\`"`
- `:146` → `"Fetch SAD Event Log; \`SadEventPageRequest\` body (\`prefix\`, \`since\`, \`limit\`); returns \`SadEventPage\`"`
- `:149` → `"Get paginated SAD event repair entries; \`SadRepairsRequest\` body (\`prefix\`, \`limit\`, \`offset\`); returns \`SadEventRepairPage\`"`
- `:150` → `"Get archived SAD events for a specific repair; \`SadRepairPageRequest\` body (\`prefix\`, \`said\`, \`limit\`, \`offset\`); returns \`SadEventPage\`"`
- `:157` — `"the record's SAID"` → `"the event's SAID"`
- `:160` → `"SAD events reference content in MinIO via \`content_said\`. Client workflow: POST content first, then POST SAD event."`

Preserved (already correctly role-named): `:148` `"Tip SAID for sync comparison"`, `:152` `"List SEL prefixes with tip SAIDs"`, `:157` `"Per-SEL-prefix daily rate limited"`, `:158` `SadEventPage` type reference. Doc-only change; no `make` run required.

---

## Positive Observations

- **Round 10's resolutions all hold under cold reading.** Fresh greps for `current_record` (zero outside `docs/claudit/**`), `test_sad_record_` (zero), `"Failed to submit event chain"` (zero), `"Tip record has no content"` (zero), `"Failed to compute event prefix"` (zero), `"the tip record's SAID"` (zero), and `compute_sad_event_prefix(kel_prefix` (zero) all return clean. The 8 findings round 10 resolved are permanently fixed; the rustdoc correctness bug in `key_publication.rs` no longer misdirects consumers, and the `current_record() → current_event()` API rename holds in both the library definition and all 11 call sites.

- **The identifier-level rename is complete across the workspace.** A tree-wide grep of the `SadPointer|sad_pointer|SAD pointer|SadChain|sad_chain|SAD chain|SadRecord|sad_record|SAD record|SAD records|chained record|chained records|preload_sad_records|sad-pointer|sad-record` union (excluding `docs/claudit/**`) returns **zero** hits. Round 11's three open findings are entirely at the docstring/prose layer — a single rustdoc in `services/gossip/src/types/sad.rs`, a test script's variable name and banner, and endpoint-table row descriptions. The renamed-type surface (`SadEvent`, `SadEventKind`, `SadEventVerification`, `SadEventPage`, `SadEventRepair`, `SadEventRepairPage`, `SubmitSadEventsResponse`) reads consistently across library, service, client, FFI, and CLI layers.

- **Round 10's preserved-site rationales are principled, not invented.** The three sites round 10 explicitly preserved — `docs/design/verification.md:11` ("All event prefixes match" in KEL-context), `lib/ffi/src/sad.rs:14` (`"SAD event prefix"` as the fully-qualified form of the ABI function name `kels_compute_sad_event_prefix`), and the `event_prefix` C ABI parameter name at `sad.rs:260` — were each backed by a concrete citation: the KEL-vs-SEL domain split, the ABI-stability constraint for FFI symbols, and the parameter-name-vs-description split documented in round 10 #7's resolution. Round 11's cold re-read confirms each preservation stands on its own merits; no invented rationales.

- **The `services/gossip/src/types/sad.rs` rustdoc is one-line-away from clean.** The surrounding file at `:5-8, :12, :19, :23-26` reads cleanly in post-rename vocabulary (`"Gossip message types for SAD replication"`, `"SEL update announcements on a single topic"`, `"A SAD Event Log was updated"`, `"SAID of the latest SAD event"`). The finding #1 drift is confined to one line on one field — `:21` — with matching `:23-24` already role-named. A `sed -i '' 's/event prefix/SEL prefix/' services/gossip/src/types/sad.rs` resolves it cleanly.

- **The `"repair records"` tension at `docs/endpoints.md:149-150` is a real disambiguation concern.** The table at `:149` returns `SadEventRepairPage` (rows = `SadEventRepair`) while `:150` returns `SadEventPage` (rows = `SadEvent`). Both English descriptions use "records" but for two different Rust types. This isn't a rename oversight so much as an ambiguity the table acquired on this branch — the pre-rename doc had both say "record" because both were "SAD records". Post-rename, the distinction matters, and finding #3's proposed fix (`"repair entries"` vs `"archived SAD events"`) surfaces the type distinction in prose.

- **Test script structural uses are principled.** `test-sadstore.sh`'s five `"Chain"` uses at `:107, :257, :294, :298, :299` (function `wait_for_chain_propagation`, `"Chain does not exist yet"`, `"Chain fetched via CLI"`, `"Chain propagated to node-b"`) all describe SEL shape/state as bare nouns — these are the structural `"chain"` uses rounds 1–10 principledly preserved (per round 10 positive-observation #2). Finding #2's proposed sweep is tightly scoped to the single `"Chain Record Submission"` banner (where "Record" is the pre-rename term), the `CHAIN_PREFIX` variable (where `chain_prefix` was the round 9 #1 rubric), and one `"chain events"` phrase that parallels an adjacent role-named clause. The structural phrases are left alone.

- **Round 11's findings are documentation-layer drift, not correctness bugs.** Finding #1 is a single-line rustdoc on a field name that is itself serde-renamed to `prefix` at the wire. Finding #2 is test-script metadata. Finding #3 is an endpoint table. None of these are reached by build tooling (`make check` / `clippy` / `cargo test`), none affect wire format, and none change runtime behavior. The branch is ship-ready in every respect that tooling can verify; round 11 is the final prose-layer polish pass.

- **The cumulative 63 resolved + 3 open count shows diminishing returns.** Rounds 1–5 resolved 40+ findings (identifier-level type/function renames). Rounds 6–8 resolved ~20 (docstring/prose sweep on the primary surface files). Rounds 9–10 resolved ~15 (local variables, cache-key literals, test names, accessor method rename, and one correctness bug in a rustdoc example). Round 11 surfaces 3 — and two of them are at surfaces round 10 either explicitly deferred (gossip announcement) or that rounds 8/9 swept partially and didn't re-scope (endpoints.md table rows). The rename is effectively complete at every layer tooling can measure; the remaining drift is human-readable-only and touches no runtime path.
