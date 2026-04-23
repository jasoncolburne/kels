# Branch Audit: KELS-133_rename-concepts (Round 9) — 2026-04-23

Branch `KELS-133_rename-concepts` vs `main`: 110 files, 3687 insertions / 2559 deletions. No commits since round 8 (`git log 3c553b0..HEAD` empty at audit time). Cold re-read after `/clear`, focused on surfaces prior rounds kept sweeping but never fully drained of rename drift — specifically: live code identifiers (variables, function names) that the docstring-focused rounds skipped, CLI user-facing output strings, module-level `SadEvent*` type rustdocs the mass-rename left with stale prose, and the one-line section leads in design docs whose tables/routes were renamed correctly but whose lead paragraphs were missed. Total resolved cumulatively across rounds 1–8: 45. All 10 round-9 findings resolved in-place; cumulative across rounds 1–9: 55.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 2        |
| Low      | 0    | 8        |

Round 9 surfaced 10 new findings — 2 medium, 8 low — all rename stragglers in surfaces the prior eight rounds either didn't reach (live variable names and function names in `services/gossip/src`) or swept partially (CLI output strings, type-level rustdoc, design-doc section leads, verifier error strings, top-level `README.md` and `docs/deployment.md`). Findings #9 and #10 were added during review when the original round-9 resolution invented unsupported preservation rationales for both surfaces; the user pushed back and the sweeps were then applied. All resolved. Cumulative across rounds 1–9: 55 resolved.

---

## Medium Priority

### ~~1. `chain_prefix` variable name used pervasively in `services/gossip/src/sync.rs` — sibling function names are role-named (`handle_sel_announcement`, `fetch_sel_effective_said`), but the `Digest256` variable passed around is still `chain_prefix`~~ — RESOLVED

**File:** `services/gossip/src/sync.rs:376, 380, 451, 463, 469, 476, 484, 491, 545, 551, 562, 570, 1477, 1483, 1542, 1557, 1682, 1684, 1688, 1694`

~~Prior rounds swept this module's docstrings and inline comments for `"chain prefix"` prose (round 8 #2 fixed the three stragglers at `:1493, :1525, :1537`). Variable names were not audited. The live code carries the old vocabulary at ~20 sites: function parameters on `handle_sel_announcement` and `record_sad_stale_prefix`, for-loop bindings, struct-destructure bindings, tracing field key name (`chain_prefix = %chain_prefix`), and format-string arguments. The role/mechanism split rounds 4–8 enforced across docstrings and error strings — `"SEL prefix"` for the role — was contradicted at the call-site level.~~

**Resolution:** `sed -i '' 's/chain_prefix/sel_prefix/g' services/gossip/src/sync.rs` — mechanical rename at all 20 sites (function parameters, for-loop bindings, struct-destructure binding, two tracing-field key names, all format-string arguments). Post-fix grep `chain_prefix services/gossip/src/sync.rs` returns zero hits.

A confirmation sweep surfaced the same pattern in four additional files not originally called out (the [thorough-renames] rubric says one-pass global): `services/sadstore/src/handlers.rs` (14 sites in `submit_sad_events` and helpers), `clients/cli/src/commands/exchange.rs` (three variable bindings + one `println!` `"Chain Prefix:"` label the round 8 #2 sweep missed), `clients/cli/src/commands/mail.rs` (two variable bindings), `clients/test/scripts/load-sad.sh` (three shell-variable bindings). All swept in the same pass. The stray `println!("  Chain Prefix: {}", sel_prefix)` at `exchange.rs:273` was additionally rewritten to `"  SEL Prefix:  {}"` to match the vocabulary of its surrounding labels (`"KEL Prefix:"`, `"Algorithm:"`, `"Key SAID:"`).

Post-fix tree-wide grep `chain_prefix` excluding `docs/claudit/**` returns zero hits. `make` passes cleanly (build + clippy + all test suites green).

### ~~2. Function name `preload_sad_records` and its one-line docstring are stale — the body was renamed to SEL/SAD Event vocabulary but the entry-point identifier was not~~ — RESOLVED

**File:** `services/gossip/src/bootstrap.rs:230, 234`; called from `services/gossip/src/lib.rs:427, 722`

~~The function's body was fully renamed on this branch — it calls `fetch_sel_prefixes`, `fetch_sel_effective_said`, `forward_sad_events`, and logs `"Preloading SAD Event Logs from {} Ready peer(s)..."`. The sibling function is correctly named `preload_sad_objects`. But the Layer-2 entry point was still `preload_sad_records`, with a one-line summary docstring `"Preload SAD records from Ready peers."` — contradicting every other identifier and log message in the renamed body.~~

**Resolution:** User renamed `preload_sad_records` → `preload_sad_events` at the definition (`bootstrap.rs:234`) and both call sites in `lib.rs` (lines 427, 722). The one-line docstring at `bootstrap.rs:230` was also updated to `"Preload SAD events from Ready peers."`.

Post-fix sweep surfaced three additional same-class stragglers adjacent to the call sites in `services/gossip/src/lib.rs` — all swept in the same pass:
- `lib.rs:420` — inline comment `"// Preload KELs, SAD objects, and SAD records from Ready peers"` → `"...and SAD events from Ready peers"`.
- `lib.rs:715` — `info!("First peer connected — preloading KELs, SAD objects, and SAD records...")` → `"...and SAD events..."`.
- `lib.rs:723` — `error!("SAD record preload failed: {}", e)` → `error!("SEL preload failed: {}", e)` (mirrors the warn! form at `lib.rs:428` that the user's original fix already used).

Post-fix grep `preload_sad_records` returns zero hits; function name, docstring, inline comments, and both log messages at the call sites now agree.

---

## Low Priority

### ~~3. CLI success/error messages in `cmd_sel_submit` say `"SAD record(s)"` — user-visible output drift from the renamed subcommand~~ — RESOLVED

**File:** `clients/cli/src/commands/sel.rs:21, 25`

~~The surrounding code is consistently role-named (subcommand `Sel::Submit`, client call `submit_sad_events`, JSON parse context `"Failed to parse SadEvent JSON"`), but the error context and the success println used `"SAD record(s)"` — the pre-rename term.~~

**Resolution:** `"Failed to submit SAD records"` → `"Failed to submit SAD events"` at line 21; `"{} SAD record(s) submitted"` → `"{} SAD event(s) submitted"` at line 25. The CLI output now reads `N SAD event(s) submitted`, matching the subcommand help text and the `SadEvent` type name.

### ~~4. `cmd_sel_prefix` error context says `"Failed to compute SAD prefix"` — but the function name is SEL-scoped and the call is `compute_sad_event_prefix`~~ — RESOLVED

**File:** `clients/cli/src/commands/sel.rs:46`

~~The error context `"Failed to compute SAD prefix"` used a term that doesn't exist in the vocabulary — SAD objects have a SAID (not a prefix), and the thing being computed is specifically the SEL prefix. This was a pre-rename `"SAD pointer prefix"` phrase that survived the rename as the literal `"SAD prefix"`.~~

**Resolution:** `"Failed to compute SAD prefix"` → `"Failed to compute SEL prefix"`. Now matches the subcommand help text at `main.rs:281` (`"Compute a SEL prefix from a write policy SAID and topic"`) and the canonical vocabulary.

### ~~5. `SadEventPage` rustdoc references `"the chain API"` — no such concept in the post-rename vocabulary~~ — RESOLVED

**File:** `lib/kels/src/types/sad/event.rs:363`

~~`"the chain API"` was pre-rename phrasing for what's now the SAD Event Log API / the routes under `/api/v1/sad/events`. Round 7 #4 fixed the module-level doc for this file but this type-level docstring was missed.~~

**Resolution:** `/// A page of stored SAD events returned by the chain API.` → `/// A page of stored SAD events returned by the SAD Event Log API.`. Matches the renamed routes in `server.rs` (`/api/v1/sad/events/fetch` returns `SadEventPage`).

### ~~6. `SubmitSadEventsResponse` docstring says `"Response from event chain submission."` — stale pre-rename phrasing~~ — RESOLVED

**File:** `lib/kels/src/types/sad/request.rs:44`

~~The type is `SubmitSadEventsResponse`, returned by the `/api/v1/sad/events` endpoint, but the rustdoc labelled it `"event chain submission"` — old phrasing. Companion types in the same file (lines 22, 30) were already correctly role-named.~~

**Resolution:** `/// Response from event chain submission.` → `/// Response from SAD event submission.`. Now matches the type name and the sibling docstrings in the same file.

### ~~7. `docs/endpoints.md:136` section-lead paragraph says `"authenticated chained records (PostgreSQL)"` — prior rename fixed every route/table row in the same section but missed the lead~~ — RESOLVED

**File:** `docs/endpoints.md:136`

~~The branch diff swept this doc's API tables and notes to `"SAD events"` / `"SEL"` (round 8 #5 fixed the inline notes), but the section lead paragraph — the first sentence a reader sees under `## SADStore` — still said `"authenticated chained records (PostgreSQL)"`. Same drift class as `docs/design/sadstore.md:10` that round 8 #4 fixed on a sibling landmark sentence.~~

**Resolution:** `"authenticated chained records (PostgreSQL)"` → `"authenticated SAD Event Logs (PostgreSQL)"`. The section lead now matches the post-round-8 form of `sadstore.md:10`, and the tables/notes below it.

### ~~8. Gossip sync log message and cache-key literal use `"SAD record"` — one user-visible warning, two load-bearing cache-key strings~~ — RESOLVED

**File:** `services/gossip/src/sync.rs:155, 491, 500`

~~Two cache-key format strings (`"sad-record:{}"`, `"sad-record:{}:{}"`) were the load-bearing dedup keys between the Redis pub/sub receiver (line 155) and the gossip handler (line 491), which must agree to prevent a feedback loop. Both purely in-process (`Arc<RwLock<HashMap>>`); renaming both atomically is safe. Line 500 was a user-visible `warn!` log using `"SAD record sync"`.~~

**Resolution:** Renamed both cache-key literals in lockstep — `"sad-record:"` → `"sad-event:"` at `sync.rs:155` and `sync.rs:491` (applied as a single atomic pair; the feedback-loop dedup continues to match because both keys live in the same process and both were updated together). Updated the warn! log at `sync.rs:500` (`"Failed to build HTTP client for SAD record sync"` → `"...for SAD event sync"`). Post-fix grep `sad-record` across `services/gossip/src/` returns zero hits.

### ~~9. Verifier error strings use `"SAD record {}"` — added during review after user pushback on an invented preservation rationale~~ — RESOLVED

**File:** `lib/kels/src/types/sad/verification.rs:120, 129, 211, 218, 226, 251, 268, 293, 300, 337, 400`

~~The first draft of this round's resolution claimed these strings were deliberately preserved as a "storage-layer generic term" with prior-round precedent. That rationale was not supported by anything in rounds 1-8 — round 8 #2 swept the `"chain prefix"` / `"chain topic"` halves of lines 120 and 129 but left `"SAD record {}"` at the start of the same messages alone as a scoped fix, not as a principled preservation. Line 211 (`"Non-inception SAD record {} has no previous event"`) mixed old and new vocabulary in one sentence; line 400 (`"Empty SAD record chain"`) combined them in one phrase. The type being described is `SadEvent`; `"SAD record"` is stale.~~

**Resolution:** `sed -i '' 's/SAD record/SAD event/g' lib/kels/src/types/sad/verification.rs` swept 11 error-string sites. Post-fix reads:
- `:120` — `"SAD event {} prefix {} doesn't match SEL prefix {}"`
- `:129` — `"SAD event {} topic {} doesn't match SEL topic {}"`
- `:211` — `"Non-inception SAD event {} has no previous event"` (the double use of "event" is now type-then-structural, not old-then-new)
- `:218, :226, :251, :268, :293, :300` — `"SAD event {}"` as the subject of each check
- `:337` — `"SAD event {} exceeds checkpoint bound ({} non-checkpoint records, max {})"` — the first `"SAD record"` renamed; `"non-checkpoint records"` preserved as the mechanism-count compound term (matches the constant name `MAX_NON_CHECKPOINT_RECORDS` at `lib/kels/src/lib.rs:137` per the round-3 role/mechanism split)
- `:400` — `"Empty SAD event chain"`

Post-fix grep `"SAD record"` across the verifier module returns zero hits. `make` passes cleanly — no tests asserted on the renamed error substrings.

### ~~10. `README.md` and `docs/deployment.md` carry the "chained records" / "SAD record storage" vocabulary — added during review after user pushback on the "not in branch diff, out of scope" rationale~~ — RESOLVED

**File:** `README.md:71`; `docs/deployment.md:25, 26, 31, 53, 56`

~~The first-draft resolution claimed these files were "not in branch diff, out of scope" — technically true (`git diff main -- docs/deployment.md README.md` empty) but a weak reason to leave stale vocabulary in top-level user-facing docs. The branch's purpose is renaming concepts; the new vocabulary should be reflected wherever it appears, not only where this branch happened to touch lines. `docs/endpoints.md:136` had identical phrasing (`"authenticated chained records (PostgreSQL)"`) and was swept as finding #7 — `README.md:71` is the verbatim twin.~~

**Resolution:**

- `README.md:71`: `"authenticated chained records (PostgreSQL)"` → `"authenticated SAD Event Logs (PostgreSQL)"` — matches the endpoints.md #7 form.
- `docs/deployment.md:25, :53`: `"SAD objects + chained records"` → `"SAD objects + SAD Event Logs"` (applied as a `replace_all` since both lines were identical).
- `docs/deployment.md:26`: `"event, signature, and SAD record storage"` → `"event, signature, and SAD Event Log storage"`.
- `docs/deployment.md:56`: `"KEL storage, SAD record storage, and gossip peer cache"` → `"KEL storage, SAD Event Log storage, and gossip peer cache"`.
- `docs/deployment.md:31`: `"object write, object read, record submission, record repair, paginated record retrieval"` → `"object write, object read, SAD event submission, SEL repair, paginated SEL retrieval"` — additional stragglers surfaced on closer read of the same section.

Post-fix tree-wide grep `"SAD record"|"chained records"` excluding `docs/claudit/**` returns zero hits.

---

## Positive Observations

- **The identifier-level rename is complete across public types.** Fresh greps for `SadPointer`, `SadChain`, `sad_pointer`, `sad_chain`, `SAD pointer`, `verify_sad_pointer`, `forward_sad_pointer`, `transfer_sad_pointer`, `fetch_sad_pointer` all return zero hits outside `docs/claudit/**`. The remaining round-9 drift is at the prose/variable-name layer — the primary type/function names that library consumers and HTTP clients depend on have been fully swept through rounds 1–5.

- **Round 8's six resolved stragglers all hold.** Cold re-read of `services/sadstore/src/handlers.rs:1090, 1708` (Layer 2 section banners), `lib/kels/src/client/sadstore.rs:194` (client section banner), all `"chain prefix"` sites from round 8 #2, `services/sadstore/migrations/0001_initial.sql:49, 52`, `docs/design/sadstore.md:10`, and the round 8 #5/#6 design-doc and test-script stragglers all read with the post-round-8 renamed vocabulary. The 45 cumulative resolved findings remain fixed.

- **Round 8's preserved-structural-chain judgment was principled.** The `"chain" in structural shape` sites that rounds 1-8 explicitly preserved — `repair.rs:8` (`Multiple repairs to the same chain`), `repair.rs:26` (`A page of chain repairs`), `sync.rs:283` (`Event chains have no recovery/contest`), `sync.rs:353` (`chain linkage`), `sad-events.md` section headers describing chain shape — all still read naturally. The round-9 findings (`chain_prefix` variable, `"chain API"`, `"event chain submission"`) are at sites where prior rounds' role/mechanism rubric clearly calls for role naming (role = SEL / SAD event; mechanism = chain structure), not structural preservation.

- **`SadEventKind`, `SadEvent`, `SadEventVerification`, `SadEventPage`, `SadEventRepair`, `SadEventRepairPage`, and `SubmitSadEventsResponse` form a consistent type surface.** All seven primary types in `lib/kels/src/types/sad/` use the renamed `SadEvent*` naming; round-9 finding #5 (on `SadEventPage`) and #6 (on `SubmitSadEventsResponse`) are single-line docstring drift, not type-surface issues. The HTTP API (per `services/sadstore/src/server.rs:29-62`), the client (`SadStoreClient`'s eight Layer-2 methods), the CLI (`SelCommands::{Submit,Get,Prefix}`), and the FFI (`kels_compute_sad_event_prefix`, `kels_sad_fetch_events`, `kels_sad_submit_events`) all read in the same vocabulary.

- **`make` passes cleanly post round-9 fixes.** All ten findings resolved across three passes: (1) the initial 7-finding sweep after the user confirmed finding #2's rename (`chain_prefix` → `sel_prefix` across five files via `sed`, plus docstrings, CLI strings, endpoints.md lead, and additional `lib.rs` log-message stragglers surfaced by post-fix grep); (2) finding #9 after the user pushed back on the invented verifier-error preservation rationale (`sed` across 11 sites in `verification.rs`); (3) finding #10 after the user pushed back on the "not in diff, out of scope" rationale for `README.md` + `docs/deployment.md`. `cargo fmt` re-collapsed two warn! calls that the rename shortened below the line-wrap threshold. Final `make` reports `Finished dev profile` and all test suites pass green (417 tests in kels-core, 73 in sadstore handlers, 53 in policy, etc.). Zero new warnings, zero behavioral changes — the variable rename is purely local and the cache-key renames were done in lockstep within a single process so the in-memory dedup keys continue to match.

- **CLI surface is structurally clean; findings #3/#4 were output-string drift.** `clients/cli/src/main.rs:252-289` (`SadCommands` / `SelCommands` definitions) reads in the correct post-rename vocabulary — subcommand names (`sel submit`, `sel get`, `sel prefix`), help text (`"Submit a SAD event to a SEL"`, `"Fetch and display a SAD Event Log"`, `"Compute a SEL prefix..."`), and dispatcher arms (`SelCommands::Submit` → `cmd_sel_submit`) were all consistent. The round-9 fixes were confined to three `.context(...)` / `println!` calls in `sel.rs` and one stray `"Chain Prefix:"` label in `exchange.rs:273` — the clap-level interface was untouched.

- **Gossip bootstrap progress logs are already role-named.** `services/gossip/src/bootstrap.rs:243, 315` log `"Preloading SAD Event Logs from {} Ready peer(s)..."` and `"SAD Event Log preload complete: {} chains synced"` — both use the renamed vocabulary. The round-9 finding #2 is confined to the function name and its one-line summary docstring; the operator-visible log output is already correct. That means the #2 fix has no operator-visible effect; it's purely a source-code readability improvement.

- **Round-9 findings cluster in exactly the surfaces prior rounds acknowledged deferring.** Rounds 1-5 explicitly focused on type/function identifiers; rounds 6-8 explicitly focused on docstring/prose sweep. Local variable names, cache-key literals, and CLI output strings were never the explicit scope of any prior round's sweep — they're precisely what round 9's cold re-read surfaced. No round-9 finding contradicted a prior round's explicit preservation judgment.

- **Review caught two invented preservation rationales.** The first-draft resolution for this round claimed verifier error strings (`"SAD record {}"`) were a deliberately preserved "storage-layer generic term" with prior-round precedent, and that `README.md`/`docs/deployment.md` were "out of scope" because they weren't in the branch diff. Both rationales were unsupported — round 8 #2's half-sweep of lines 120/129 was a scoped fix, not a principled preservation, and "file not in diff" is a weak reason to leave stale vocabulary in top-level user-facing docs. The user pushed back on both; findings #9 and #10 were added and resolved. Recording the process here as a reminder: when about to claim "this was deliberately preserved", verify the prior round actually said so in its resolution text, not just that it failed to sweep the phrase.

- **Sites genuinely preserved, with precedent citations.** The mechanism-count compound `"non-checkpoint records"` at `verification.rs:337` was left intact when the `"SAD record"` prefix on the same line was swept to `"SAD event"`. Precedent: the constant name `MAX_NON_CHECKPOINT_RECORDS` at `lib/kels/src/lib.rs:137` and the field `records_since_checkpoint` at `verification.rs:60` both use `"records"` as the checkpoint-mechanism count-noun per the round-3 #3 role/mechanism split. The structural `"chain"` uses that rounds 1-8 preserved (`repair.rs:8, :26`, `sync.rs:283, :353`, `sad-events.md` structural headers) remain untouched — all describe structural shape (a SEL is a chain), not a typed slot.
