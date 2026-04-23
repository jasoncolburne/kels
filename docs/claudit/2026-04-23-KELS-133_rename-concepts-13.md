# Branch Audit: KELS-133_rename-concepts (Round 13) — 2026-04-23

Branch `KELS-133_rename-concepts` vs `main`: 114 files, 4301 insertions / 2680 deletions. No code commits since round 12 (`git log 40c877a..HEAD` empty; working tree clean — round 12 commit added the audit doc plus the sweeps it described in `services/sadstore/src/handlers.rs` and `lib/kels/src/types/sad/event.rs`). Cold re-read after `/clear`, focused on the one sizeable untouched surface the prior twelve rounds never scoped for variable-binding / parameter / format-string drift: `lib/kels/src/types/sad/verification.rs` (the primary SAD verifier, ~590 diff lines, ~107 `record` tokens inside the file), plus three tightly-scoped collateral surfaces (the `PolicyChecker` public trait signature and its four impls, `lib/kels/src/types/sad/custody.rs`'s Display messages, and `lib/ffi/src/sad.rs`'s submit/fetch Doxygen). Rounds 1–12 cumulatively resolved 70 findings.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 3        |
| Low      | 0    | 4        |

Cumulative across rounds 1–12: 70 resolved. Round 13 surfaces 7 open findings at surfaces where the round 9 #1 / round 12 #1 rubric ("function parameters, for-loop bindings, struct-destructure binding, all format-string arguments; typed `Vec<SadEvent>` bindings renamed to the role name") was established but never applied. None contradict a prior round's explicit preservation — the count-noun preservations (`records_since_checkpoint`, `non-checkpoint records`, `saw_any_records` — round 9 #9 precedent) remain principled and are not re-opened, and the structural `"event chain"` / `"chained record"` preservations per round 10 positive-observation #2 are respected. Each finding cites a specific prior-round rubric and applies it to a surface no round scoped.

---

## Medium Priority

### ~~1. `PolicyChecker` trait method parameters use the pre-rename token in their public signature~~ — RESOLVED

**File:** `lib/kels/src/types/sad/verification.rs:28-43`; impls at `lib/policy/src/policy_checker.rs:36-70`, `lib/policy/src/identity_chain.rs:124-148`; inline-test impls at `lib/kels/src/types/sad/verification.rs:503-560, 896-906`

~~The trait signature reads:~~

~~```rust~~
~~async fn satisfies(~~
~~    &self,~~
~~    new_record: &SadEvent,~~
~~    previous_policy: &cesr::Digest256,~~
~~) -> Result<bool, KelsError>;~~

~~async fn self_satisfies(&self, record: &SadEvent) -> Result<bool, KelsError>;~~
~~```~~

~~Both parameter names carry the pre-rename vocabulary at the point where the trait is rustdoc'd for external implementors. The type is `&SadEvent`; per the round 9 #1 / round 12 #1 rubric for typed `SadEvent` bindings the role name is `event` / `new_event`. The trait's own rustdoc on the `#[async_trait::async_trait]` block at `:27` also carries the pre-rename phrasing.~~

~~The `AnchoredPolicyChecker` impl at `policy_checker.rs:36-70` replicates the drift verbatim. Both in-file test impls at `verification.rs:503-560, 896-906` use `_: &SadEvent` pattern (unnamed) — those are clean. The policy test impl at `identity_chain.rs:124-148` likewise uses `_: &SadEvent`. Only the canonical live trait sig and the `AnchoredPolicyChecker` impl carry the named parameters.~~

**Resolution:** Renamed trait parameters `new_record` → `new_event` and `record` → `event` in the `PolicyChecker` sig at `verification.rs:34, 42`; swept the five-site rustdoc block on `verification.rs:12-42` (inception-call example, advance-call example, `for this record`/`new_record` references). Renamed the `AnchoredPolicyChecker` impl parameters and body references at `policy_checker.rs:38, 54` (`new_record.said` → `new_event.said`, `record.write_policy`/`record.said` → `event.write_policy`/`event.said`), the `"Icp record missing write_policy"` error string → `"Icp event missing write_policy"`, and the four docstring sites at the file top (`:3`, `:12-16` module-doc + struct-doc enumerating the two code paths). `AcceptLegitEstChecker` inline-test impl at `verification.rs:899` swept in lockstep (`record: &SadEvent` → `event: &SadEvent`, `record.governance_policy` → `event.governance_policy`). `make check` passes cleanly.

### ~~2. `lib/kels/src/types/sad/verification.rs` — file-wide `record` / `records` variable drift untouched by any prior round~~ — RESOLVED

**File:** `lib/kels/src/types/sad/verification.rs:47-375` (verifier body) and throughout the test module `:479-1589`

~~The file has **107** `record` token hits at the variable-binding / for-loop / format-string / rustdoc layer. Rounds 4–6 touched individual docstrings and one correctness finding (last_governance_version semantics, deferred), but no round applied the round 9 #1 / round 12 #1 rubric here. The file sat on 588 diff lines (second-largest changed file after `lib/kels/src/types/mod.rs`). Categories of drift include local bindings on `Vec<SadEvent>` values, single-event bindings on `&SadEvent`, user-visible format strings, docstring prose, and test-module sites.~~

**Resolution:** Swept the verifier body (`:47-375`):
- Private method `verify_record` → `verify_event`; param `record: &SadEvent` → `event: &SadEvent`; ~7 downstream `record.{verify_said, prefix, said, topic}` → `event.*` references and the single call site at `:376` `self.verify_record(record)` → `self.verify_event(event)`.
- `flush_generation`: `let records = std::mem::take(&mut self.generation_buffer)` → `let events = ...`, subsequent `records.is_empty()` / `records.len()` / `records.iter()` / `records[0]` / `records[div_idx]` / `for record in &records` bindings all swept to `events` / `event`. ~30 downstream `record.{kind, said, version, previous, governance_policy, write_policy, clone, topic}` accesses renamed to `event.*`.
- User-visible format strings: `"Multiple records at version 0"` → `"Multiple events at version 0"` (`:160`), `"Generation at version {} has {} records, max 2 allowed"` → `"Generation at version {} has {} events, max 2 allowed"` (`:200`). `"non-checkpoint records"` at `:337` **preserved** (count-noun per round 9 #9), and the `SadEvent` role prose in other format strings (`"SAD event {} prefix {}..."`, `"SAD event {} exceeds checkpoint bound..."`, etc.) already role-named from prior rounds.
- Docstrings swept: `/// Records buffered for the current generation` → `/// Events buffered...` (`:79`), `/// Verify a single record's SAID` → `/// Verify a single event's SAID` (`:114`), `/// Process a complete generation (all records at the same version)` → `/// Process... (all events...)` (`:137`), `// Max 2 records per generation` → `// Max 2 events per generation` (`:197`), `// Policy check: every v1+ record...` → `// Policy check: every v1+ event...` (`:231`), `// subsequent records` → `// subsequent events` (`:233`), `// Normal record — increment counter` → `// Normal event — increment counter` (`:333`), `/// Verify a page of records incrementally` → `/// Verify a page of events incrementally` (`:371`). Expect() reason `"Icp record must have write_policy..."` → `"Icp event must have..."` at `:183`. Defense-in-depth comments at `:306, :309` (`"driven by this record"` / `"unauthorized record"`) → `"this event"` / `"unauthorized event"`.
- `pub async fn verify_page(&mut self, records: &[SadEvent])` → `events: &[SadEvent]` at `:372` (external param-name change, but callers pass positional arguments).
- Test module (`:479-1589`): swept `test_checkpoint_overdue_at_64` and `test_valid_checkpoint_cycle` (`:1155, 1196`) `let mut records = vec![v0.clone()]` → `let mut events = ...` plus all `records.push(...)` / `verifier.verify_page(&records)` call sites. Swept the four remaining test prose sites: `"// Change governance_policy on an Evl record — valid"` → `"...on an Evl event..."` (`:1238`), `"Any subsequent record on this branch"` → `"Any subsequent event..."` (`:730`), `"branch-state advances driven by the record"` → `"driven by the event"` (`:733`), `"last_governance_version must not advance when the record soft-failed"` → `"when the event soft-failed"` (`:763`), `AcceptLegitEstChecker` comment `"accepts the wp soft check only for records whose"` → `"events whose"` (`:889, 891`).

**Preserved** under round 9 #9 count-noun / verb precedent: `records_since_checkpoint` field (`:60, 191, 257, 334, 355`), `saw_any_records` field (`:83, 102, 374, 398`), `"non-checkpoint records"` format string (`:337`), `"Number of records since the last checkpoint"` docstring (`:59`), and the verb `"it records the result"` at `:70`. Post-fix `grep -E '\brecord\b|\brecords\b' lib/kels/src/types/sad/verification.rs | grep -v 'records_since_checkpoint|saw_any_records|non-checkpoint records|Number of records since|it records'` returns zero hits. `make check` passes cleanly.

### ~~3. `lib/kels/src/types/sad/custody.rs` — `"event records"` in rustdocs and user-visible `Display` impl~~ — RESOLVED

**File:** `lib/kels/src/types/sad/custody.rs:67, 74, 76, 90, 96`

~~Five sites in the one file: `:67` enum-variant rustdoc on `SadCustodyContext::Event`, `:74, :76` error-variant rustdocs on `CustodyValidationError::TtlNotAllowedOnEvent` / `OnceNotAllowedOnEvent`, and `:90, :96` `Display` impl user-visible error messages (propagated out of SADStore's submit path when a caller attaches a ttl/once-carrying custody to an event submission).~~

**Resolution:** All five swept:
- `:67` `"Chained event records — \`ttl\` and \`once\` are rejected."` → `"Chained events — \`ttl\` and \`once\` are rejected."`
- `:74, :76` `"chained event records"` → `"chained events"` in both error-variant rustdocs.
- `:90` Display `"ttl is not allowed on event records — expiring a link in a chain..."` → `"ttl is not allowed on events — expiring a link in a chain..."`
- `:96` Display `"once is not allowed on event records — deleting a link in a chain..."` → `"once is not allowed on events — deleting a link in a chain..."`

The structural `"a link in a chain breaks verification for descendants"` tail on both error messages preserved per round 10 positive-observation #2 (structural chain phrasing describes shape, not a typed slot). `make check` passes cleanly.

---

## Low Priority

### ~~4. `lib/kels/src/types/sad/sync.rs` — post-divergence branch-splitter uses `record` / `records` bindings throughout~~ — RESOLVED

**File:** `lib/kels/src/types/sad/sync.rs:146-340` (sync_sad_chain + separate_branches helpers)

~~The same pattern as finding #2 but confined to this 446-line helper file. ~35 `record` / `records` bindings distributed across `collect_and_transfer_sad_chain` (`:146-269`) and `separate_branches` (`:280-345`) plus user-visible format string shared with verification.rs:200.~~

**Resolution:** Swept `transfer_sad_events` (`:151-278`): `let mut records = ...` → `let mut events = ...` (`:176`), nine subsequent `records.{is_empty, len, iter, last, pop}` / `records[...]` index expressions / `&records` references all swept to `events`. Four `for/closure` `|r|` bindings → `|e|` on `records.last().map(|r| r.said)` / `records.iter().filter(|r| ...)`. Format string `"Generation at version {} has {} records, max 2 allowed"` → `"...has {} events, max 2 allowed"` (`:227`). Rustdoc prose (`:146-149, :175, :189, :212, :261`) swept `"held-back record"` / `"two records at the same version"` / `"remaining records"` / `"post-divergence records"` / `"consecutive records"` / `"final held-back record"` → corresponding `event` / `events` forms.

Swept `send_divergent_sad_events` (`:280-347`): `"Separate post-divergence records"` → `"Separate post-divergence events"` (`:280`), `"Fork record from shorter branch"` → `"Fork event from shorter branch"` (`:286`), `"Divergent chain must have at least 2 records"` → `"...at least 2 events"` (`:295`). Three `for record in post_divergence...` loops → `for event in ...`; ten `record.{previous, said}` field accesses → `event.{previous, said}`. Comments `"Longer chain first as non-divergent appends, then fork record from shorter"` (`:325`), `"Fork record from shorter chain (creates divergence)"` (`:339`), `"The shorter branch is always exactly one record"` (`:340`) → `event` forms.

Swept test module (`:395-524`): `/// In-memory source that serves records in pages` → `"...serves events in pages"` (`:401`), struct field `records: Vec<SadEvent>` → `events: Vec<SadEvent>` (`:403`) and four `self.records.{iter, len}` / `self.records[...]` accesses → `self.events.*`. Method `CollectingSink::all_records` → `all_events` (`:444`) plus the caller at `:503`. Test prose `"two records at v2 (divergence)"` → `"two events at v2"` (`:462`), `"Two conflicting v2 records"` → `"Two conflicting v2 events"` (`:478`), `"All 4 records should be forwarded"` → `"All 4 events..."` (`:505`), `"Both v2 records present"` → `"Both v2 events present"` (`:513`), `"Expected 4 records"` assertion message → `"Expected 4 events"`, two `"missing from forwarded records"` → `"missing from forwarded events"` (`:517, 521`). Struct literal at `:494` `records: vec![v0, v1, v2_a.clone(), v2_b.clone()]` → `events: vec![...]`.

**Preserved** per round 9 #9 precedent: verb form `/// Collecting sink that records all stored pages.` at `:432` (`records` is a verb here, not a noun). Post-fix `grep -E '\brecord\b|\brecords\b' lib/kels/src/types/sad/sync.rs` returns only that one verb-form site. `make check` passes cleanly.

### ~~5. `lib/ffi/src/sad.rs` — Doxygen + local bindings + the C ABI parameter `json_signed_records`~~ — RESOLVED

**File:** `lib/ffi/src/sad.rs:185, 189, 199, 208-216, 243`

~~Doxygen summary + local bindings + user-visible error strings + C ABI parameter name carry the pre-rename short form.~~

**Resolution:** Swept all in-Rust sites:
- `:185` Doxygen `/// Submit SAD event records to a SADStore.` → `/// Submit SAD events to a SADStore.`
- `:243` Doxygen `/// Fetch a page of SAD event records from a SADStore.` → `/// Fetch a page of SAD events from a SADStore.`
- `:208` internal local `let Some(records_str) = from_c_string(json_signed_records)` → `let Some(events_str) = ...`
- `:209` user-visible error `"Invalid records JSON"` → `"Invalid events JSON"`
- `:213` local `let records: Vec<kels_core::SadEvent>` → `let events: Vec<kels_core::SadEvent>`
- `:216` user-visible error `"Invalid records JSON: {e}"` → `"Invalid events JSON: {e}"`
- `:234` call site `client.submit_sad_events(&records)` → `&events`

**Preserved** per round 10 #7 FFI ABI-stability precedent: the C-visible parameter name `json_signed_records` at `:189, 199` remains unchanged (same judgment as `event_prefix` at `:260`) — deferred to a follow-up with user ACK for the ABI churn. The Doxygen param description at `:189` backticks the parameter name verbatim, so the text `\`json_signed_records\`` is also left alone. `make check` passes cleanly.

### ~~6. `docs/design/sadstore.md` — five prose sites with `"event record(s)"` / `"record's SAID"` short forms~~ — RESOLVED

**File:** `docs/design/sadstore.md:10, 16, 23, 53, 62, 148`

~~Six prose sites carrying pre-rename short forms for SAD events.~~

**Resolution:**
- `:10` `"anchor the record's SAID in their KELs"` → `"anchor the event's SAID in their KELs"` (matches `endpoints.md:157` canonical form).
- `:16` `"A chained, self-addressed event record. The v0 (inception) record has \`content: None\` ... Content is added in v1+ records."` → `"A chained, self-addressed event. The v0 (inception) event has \`content: None\` ... Content is added in v1+ events."`
- `:18` `"so inception records produce deterministic prefixes"` → `"so inception events produce deterministic prefixes"` (folded in — same bullet).
- `:23` `"SAID of previous record (None for v0)"` → `"SAID of previous event (None for v0)"`.
- `:53` `"are rejected on event records (structurally incompatible with chained data)"` → `"are rejected on events (structurally incompatible with chained data)"` — matches `custody.rs` fix from finding #3.
- `:62` `"endorsing parties anchor the record's SAID in their KELs"` → `"anchor the event's SAID in their KELs"`.
- `:148` `"Authorization is consumer-side: endorsing parties anchor the record's SAID in their KELs."` → `"...anchor the event's SAID..."` — verbatim twin of `:62`.

**Preserved:** `:25` `"\`topic\` — Record type"` left alone (borderline; `topic` is a string namespace tag and "Record type" reads as "kind-of-entry type", not "SadEvent type"). The structural `"event chains"` / `"A chained, self-addressed event"` framing per round 10 positive-observation #2 preserved throughout. Doc-only change; no `make` run required.

### ~~7. `services/sadstore/src/repository.rs` — rustdoc + typed-`&[SadEvent]` parameter drift on `save_batch`~~ — RESOLVED

**File:** `services/sadstore/src/repository.rs:33, 37-39, 44`

~~Public method `save_batch` and its rustdoc carried pre-rename `records` / "event records" short forms across param, body, and description; the drift propagated to `truncate_and_replace` / `get_repair_records` / other helpers that pass `&[SadEvent]` along.~~

**Resolution:** Swept:
- `save_batch` (`:33-130`): rustdoc `"Store a batch of event records"` → `"Store a batch of events"`, body rustdoc `"If a record in the batch... existing record... the forking record"` → `"If an event in the batch... existing event... the forking event"`. Parameter `records: &[SadEvent]` → `events: &[SadEvent]`; all ~14 downstream `records.{is_empty, iter, len}` / `records[0]` / `for record in records` / `record.{said, version, clone, previous}` / comment `"existing records at the batch's versions"` → `event` / `events` forms.
- `truncate_and_replace` (`:137-254`): param `records: &[SadEvent]` → `events: &[SadEvent]`, 17 downstream sites swept. Rustdoc `"Truncate records at and after..."` → `"Truncate events..."`, `"Archives displaced records"` → `"Archives displaced events"`. `let (new_records, from_version) = ...` → `let (new_events, from_version)`; `"Skip leading records that already exist"` → `"Skip leading events..."`; `"Archive records page-at-a-time"` → `"Archive events page-at-a-time"`; `"Skip records already in archives"` → `"Skip events already in archives"` + `"(stale gossip can re-insert fork records)"` → `"(fork events)"`; inner `for record in &page` → `for event in &page`; `let repair_record = SadEventRepairRecord::create(*repair_said_ref, record.said)` → `event.said`; `let delete_records = verifiable_storage::Delete::<SadEvent>` → `let delete_events`; `for record in new_records` → `for event in new_events`.
- `get_repair_records` (`:424-454`): rustdoc `/// Get archived records for a specific repair` → `/// Get archived events for a specific repair`, internal `let records_query` → `let events_query`, `let records: Vec<SadEvent>` → `let events: Vec<SadEvent>`, tuple return `Ok((records, has_more))` → `Ok((events, has_more))`.
- `last_governance_version` (`:271-289`): `let records: Vec<SadEvent>` → `let events: Vec<SadEvent>`, `records.first().map(|r| r.version)` → `events.first().map(|e| e.version)`.
- `get_stored_in` (`:322-381`): `let mut records: Vec<SadEvent>` → `let mut events`; four `records.{retain, truncate, len}` accesses swept; format string `"Chain integrity violation: {} records skipped at version {} for prefix {} — possible DB tampering"` → `"...{} events skipped..."`; final return `Ok(records)` → `Ok(events)`.
- `list_prefixes` (`:457-534`): `let records: Vec<SadEvent>` → `let events`; `records.into_iter().map(|r| ...)` → `events.into_iter().map(|e| ...)`; `let wrap_records: Vec<SadEvent>` → `let wrap_events`.
- `SaveBatchResult` enum variants (`:13-24`): rustdocs `"Records were accepted"` → `"Events were accepted"`, `"the forking record was inserted"` → `"the forking event was inserted"`, `"Remaining batch records were discarded"` → `"Remaining batch events were discarded"`.

**Preserved:** The constant `ARCHIVED_RECORDS_TABLE` at `:401` stays (SQL table name compound, not a typed `SadEvent` binding — its value `"sad_event_archives"` is post-rename). The `SadEventRepairRecord` type name (round 10 positive-observation count-noun preservation) stays throughout. `make check` passes cleanly.

---

## Positive Observations

- **Round 12's four resolutions all hold under cold reading.** `grep records services/sadstore/src/handlers.rs | head -60` shows only the principled-preserved sites (`reap_expired_records`, `check_prefix_rate_limit` count-noun params, `history.records` Registry API type, the three generic-comment uses at `:537, :882, :1882`). `SADSTORE_MAX_RECORDS_PER_EVENT_LOG_PER_DAY` is accepted as final (finding #12 #2). `"Chain not found"` → `"SAD Event Log not found"` at `handlers.rs:1567, 1579, 1595` (finding #12 #3) holds. `SadEvent::kind` rustdoc at `event.rs:138` reads `"The event kind."` (finding #12 #4). Cumulative 70 permanent fixes.

- **The identifier-level rename remains complete.** Tree-wide `git grep 'sad_record\|SadRecord\|sad-record\|SAD record\|sad_pointer\|SadPointer\|sad-pointer\|SAD pointer\|chain_prefix\|CHAIN_PREFIX\|chained record\|preload_sad_records'` excluding `docs/claudit/**` returns **zero** hits. Every round 13 finding is at the variable-binding / parameter / format-string / docstring layer — the identifier surface (types, functions, routes, CLI subcommands, FFI symbols except the intentionally-preserved `event_prefix` / `json_signed_records` ABI names, SQL table names, Garden build targets) is uniformly renamed.

- **Round 13's concentration in verification.rs is consistent with round-by-round file-sweep patterns.** Rounds 1–3 swept type identifiers tree-wide. Rounds 4–6 swept `event.rs` + design docs. Round 7 swept handler paths. Round 8 swept docs + FFI sibling. Round 9 swept `handlers.rs` variable-bindings (`chain_prefix` family) and four sibling files. Round 10 swept `key_publication.rs` (correctness) + `current_record()` rename + test names. Round 11 swept gossip types + test-sadstore.sh + endpoints.md table. Round 12 swept `submit_sad_events` handler. Round 13 surfaces `verification.rs` (finding #2), which is the one primary-surface file no round scoped for the variable-binding rubric. The pattern holds — each round finds one surface the prior passes didn't reach.

- **Count-noun preservations remain principled.** `records_since_checkpoint: usize` field (`verification.rs:60`), `saw_any_records: bool` field (`verification.rs:83`), `"non-checkpoint records"` format string (`verification.rs:337`), `"Number of records since the last checkpoint"` docstring (`verification.rs:59`), `MAX_NON_CHECKPOINT_RECORDS` const (`lib/kels/src/lib.rs:137`), `max_records_per_prefix_per_day` function name (`handlers.rs:138`), `record_count` / `new_record_count` / `max_records` rate-limit params (`handlers.rs:138, :1134` and `check_prefix_rate_limit` helpers), `SADSTORE_MAX_RECORDS_PER_EVENT_LOG_PER_DAY` env var — all nine sites are count-of-entries measuring, not typed `SadEvent` values. Round 9 #9's precedent ("the noun in the compound is the count of chain entries, not the typed record") continues to cover them. Round 13 is scrupulous about not re-opening any of these.

- **Verb-form `"records"` at `verification.rs:70` is preserved.** `/// The verifier never errors on policy failure — it records the result in` — `"it records"` is 3rd-person-singular-verb, not plural-noun. The post-rename lexicon has no opinion on verb forms. Finding #2's sweep explicitly excludes this line.

- **Structural `"chain"` uses are preserved throughout round 13 findings.** `:67` `"chain linkage"` rustdoc (verification.rs, structural), `:90, :96` `"a link in a chain breaks verification for descendants"` (custody.rs error messages, structural chain description of shape), `:10` `docs/design/sadstore.md` `"Versioned event chains with deterministic prefix discovery"` (structural shape), `:16` `"A chained, self-addressed event record"` (structural adjective describing the `SadEvent` shape — the word `record` is the noun that sweeps, not `chained`). The rubric from round 10 positive-observation #2 is applied uniformly.

- **The `PolicyChecker` trait (finding #1) is the one public-API identifier still carrying pre-rename param names.** A tree-wide grep for trait/impl method signatures containing `record: &SadEvent` or `new_record: &SadEvent` returns exactly the sites in finding #1 (verification.rs:34, :42; policy_checker.rs:38, :54). No other exported trait or `pub fn` has an `&SadEvent` parameter named `record`. Other `pub fn`s that take `&SadEvent` already use role-naming: `SadEvent::verify_said(&self)` (no ambiguity, self-method), `SadEvent::verify_prefix(&self)`, etc. `verify_record` at `verification.rs:115` is `fn verify_record` (private `fn`, not `pub`) and falls under finding #2's rubric as an internal helper.

- **Diminishing returns is evident but the round-13 findings are not trivia.** Finding #2 alone is ~110 concrete edits in a primary-surface file; finding #1 touches a public trait; finding #3 is user-visible error messages. These are the last substantive items. A grep of the tree for variables named literally `record` / `records` returns predominantly the verification.rs + sync.rs sites in findings #2 and #4 plus the principled count-noun preservations — every other occurrence (outside `docs/claudit/**`) is either an identifier from an unrelated type (Registry's `PeerRecord`, `SadEventRepairRecord`, `SadEventRepairRecord` cache keys, KEL's `record.said` variables in `merge.rs` which are on `Event`/`AdditionRecord` types, not `SadEvent`) or the verb form. By round 14, the variable-name surface for SAD Events will be clean.

- **Round 13's findings all cite concrete prior-round rubrics and no invented preservation.** Finding #1 cites rounds 9 #1 and 12 #1; finding #2 cites the same plus round 9 #9 count-noun preservation plus round 10 positive-observation #2 structural preservation; finding #3 cites finding #12 #1 error-string rubric and round 4 sweep of `SadCustodyContext`; finding #4 cites finding #2's rubric plus shares a format string with verification.rs:200; finding #5 cites round 10 #7 FFI rubric for parameter-description vs identifier split; finding #6 cites finding #3 and round 11 #3 `the event's SAID` canonical form; finding #7 cites round 12 #1's rubric on typed `Vec<SadEvent>` → `events`. Preservation judgments (`records_since_checkpoint`, `saw_any_records`, `non-checkpoint records`, `cp_legit`/`cp_attacker`, structural `"chain"`, verb-form `"records"`, FFI ABI names) are each backed by a named precedent, not invented.
