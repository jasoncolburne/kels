# Branch Audit: KELS-133_rename-concepts (Round 14) — 2026-04-23

Branch `KELS-133_rename-concepts` vs `main`: 114 files, 4668 insertions / 2887 deletions. No code commits since round 13 (`git log 7b016be..HEAD` empty; working tree clean — round 13 commit added the audit doc plus the sweeps it described across `verification.rs`, `custody.rs`, `sync.rs`, `ffi/sad.rs`, `sadstore.md`, `repository.rs`, and `policy_checker.rs`). Cold re-read after `/clear`, focused on the public `SadStoreClient` HTTP client (rounds 1–13 never scoped `lib/kels/src/client/sadstore.rs` for the variable-binding / param / rustdoc rubric), the top-of-file surface of `custody.rs` that round 13 #3 did not reach (`:1–:18`), and the canonical `SadEvent` / `Custody` struct rustdocs in `event.rs` / `request.rs` / `repair.rs`. Also swept the two new-in-branch CLI command files (`sel.rs`, modified-in-branch `exchange.rs`) and the in-branch `services/gossip/src/sync.rs` SAD-path comments. Rounds 1–13 cumulatively resolved 77 findings.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 4        |
| Low      | 0    | 14       |

Cumulative across rounds 1–13: 77 resolved.

**Rescission note — round 9 #9 count-noun preservation rule is retired.** After the round 14 initial write, the user reviewed the preservation judgments and rejected them. The rule "when the noun in the compound is the count of chain entries, not the typed record, preserve `records`" is retired for this branch. A subsequent user correction also rejected my follow-on invented `_RECORDS` const-name pattern — the plain rule stands: **anything that is an event should be called an event.** Findings #9–#18 below reverse specific preservations from rounds 9 / 10 / 13 and the initial round-14 preservations. Verb forms (`"it records"`, `"record as stale"`) remain preserved — those were never event references. Non-SAD records (KEL's `RecoveryRecord`, `RaftLogAuditRecord`; Registry's `PeerRecord` / `PeerHistory.records`; gossip allowlist uses of `PeerHistory`; `StorageError::DuplicateRecord` from external crate) also remain untouched — they aren't SadEvents.

**Concept rename layered on top — `checkpoint` → `evaluation`.** The user also introduced a second concept rename on top of the records→events sweep: the "checkpoint" concept (an Evl or Rpr event that evaluates `governance_policy`) is renamed to "evaluation" throughout. This affects `records_since_checkpoint` → `events_since_evaluation`, `MAX_NON_CHECKPOINT_RECORDS` → `MAX_NON_EVALUATION_RECORDS`, user-visible format strings (`"exceeds checkpoint bound"` → `"exceeds evaluation bound"`), error messages, docstrings, test helper names, test method names, test digest labels, design doc prose, and the test-sadstore.sh comments. Finding #10 tracks this sweep.

Round 14 surfaces 18 open findings: #1–#8 apply the round 9 #1 / round 12 #1 / round 13 #2 rubric ("function parameters, typed `Vec<SadEvent>` / `&[SadEvent]` bindings, param names on public methods, rustdoc prose on pub structs / pub methods") to previously-unscoped surfaces; #9–#11 reverse specific preservations per user review (URL path, `checkpoint`→`evaluation` concept, `SadEventRepairRecord`→`SelRepairEvent` type); #12–#18 reverse the initial round-14 invented `_RECORDS` const-name pattern + sweep all remaining SAD-event prose per the "anything that is an event should be called an event" rule. Each finding cites a specific prior-round rubric or user guidance.

---

## Medium Priority

### ~~1. `SadStoreClient` public API: param name `records: &[SadEvent]` on `submit_sad_events` + pre-rename rustdoc on `fetch_sad_events` / `fetch_sel_repair_events` / `as_sad_sink`~~ — RESOLVED

**File:** `lib/kels/src/client/sadstore.rs:44, 196-203, 213-215, 326-334`

~~The `SadStoreClient` is the primary public Rust SDK client.~~

**Resolution:** Swept all five rustdoc / param sites:
- `:44` → `/// Create an \`HttpSadSink\` for this client's events endpoint.`
- `:198-199` → `"each event's SAID must be anchored ... per-event signatures"` in the `submit_sad_events` rustdoc.
- `:201` pub-method param `records: &[crate::SadEvent]` → `events: &[crate::SadEvent]`; `:203` downstream `json(records)` → `json(events)`.
- `:215` `fetch_sad_events` rustdoc `"returns records after this SAID's position"` → `"returns events after this SAID's position"`.
- `:326` `fetch_sel_repair_events` rustdoc `"Fetch archived records for a specific repair"` → `"Fetch archived events for a specific repair"`.

URL path at `:334` rescinded from preservation per finding #9 — swept to `/api/v1/sad/events/repairs/events` in lockstep with the server + docs.

### ~~2. `lib/kels/src/types/sad/custody.rs` — module header + `Custody` struct rustdoc + `ttl` field rustdoc missed by round 13 #3~~ — RESOLVED

**File:** `lib/kels/src/types/sad/custody.rs:1, 5, 13, 18`

**Resolution:** Swept the four sites:
- `:1` → `//! Custody and node set SAD types for per-SAD storage policy.`
- `:5` → `//! referenced by SAID in the parent SAD.`
- `:13` → `/// Per-SAD storage policy.`
- `:18` → `/// - \`ttl\` — seconds until expiry (per-object: \`sad_objects.created_at + ttl\`)` — replacing `per-record` with `per-object` because this specific field applies only in `SadCustodyContext::Object`.

### ~~3. `lib/kels/src/types/sad/event.rs` — pub-struct + pub-method rustdocs on the canonical `SadEvent` and `SadEventVerification` types~~ — RESOLVED

**File:** `lib/kels/src/types/sad/event.rs:118, 122, 154, 315, 353`

**Resolution:** Swept all five sites:
- `:118` → `"inception events are fully deterministic for prefix computation."`
- `:122` → `"anchor the event's SAID in their KELs."`
- `:154` → `"fork bounded to ≤63 events."` (additional site caught during sweep — same rubric as #10's evaluation bound).
- `:315` → `"whenever an Evl event carries a new write_policy"`.
- `:353` → `"where some Est events soft-failed the write_policy check"`.

---

## Low Priority

### ~~4. `lib/kels/src/types/sad/request.rs` — pub struct rustdocs + `#[must_use]` message on `SubmitSadEventsResponse`~~ — RESOLVED

**File:** `lib/kels/src/types/sad/request.rs:7, 8, 30, 47, 62`

**Resolution:** Swept all five sites:
- `:7` → `"bound to a specific object"`; `:8` → `"the object's custody"` (these reference SAD Objects, not SadEvents — used by `SignedSadFetchRequest` per the `:6` context).
- `:30` → `/// Request body for fetching a page of SAD Event Log events.`
- `:47` `#[must_use]` → `"events may be rejected"`.
- `:62` → `/// Request body for fetching archived events of a specific repair.`

### ~~5. `lib/kels/src/types/sad/repair.rs:10` — `"displaced records"` in `SadEventRepair` pub struct rustdoc~~ — RESOLVED

**File:** `lib/kels/src/types/sad/repair.rs:10`

**Resolution:** Rewritten in lockstep with finding #11: `/// The displaced events are linked via \`SelRepairEvent\`.` Both the English noun (`records` → `events`) and the typed identifier (`SadEventRepairRecord` → `SelRepairEvent`) swept.

### ~~6. CLI `sel.rs` + `exchange.rs` typed `Vec<SadEvent>` bindings named `records`~~ — RESOLVED

**File:** `clients/cli/src/commands/sel.rs:14, 19, 25`; `clients/cli/src/commands/exchange.rs:134, 137, 143`

**Resolution:** In `sel.rs`, replaced all three occurrences of `records` with `events` (binding at `:14`, arg at `:19`, and `.len()` access at `:25`). In `exchange.rs`, swept the `let records = vec![...]` binding at `:134` to `events`, the `&records` arg at `:137` to `&events`, and `records[0].prefix` at `:143` to `events[0].prefix`.

### ~~7. `services/gossip/src/sync.rs` — four internal-comment sites referring to `Rpr` / leading `SadEvent`s as "records"~~ — RESOLVED

**File:** `services/gossip/src/sync.rs:448, 490, 505, 506`

**Resolution:** Four `records` → `events` sweeps: `:448` `"Rpr events"`, `:490` `"Rpr events"`, `:505` `"Rpr events"`, `:506` `"leading events"`. Verb-form sites (`:777, :1035, :1892`) left untouched per the `"it records"` verb-form exclusion.

### ~~8. `lib/ffi/src/sad.rs:379, 387` — test-local `records` CString bindings~~ — RESOLVED

**File:** `lib/ffi/src/sad.rs:379-388`

**Resolution:** Renamed both test-local bindings from `records` to `events` in `test_sad_submit_events_null_url` and `test_sad_submit_events_invalid_json`. Consistent with the production-side naming swept in round 13 #5.

### ~~9. URL path `/api/v1/sad/events/repairs/records` → `/repairs/events`~~ — RESOLVED

**File:** `services/sadstore/src/server.rs:55`; `lib/kels/src/client/sadstore.rs:334`; `docs/endpoints.md:150`; `docs/design/sadstore.md:139`

**Resolution:** All four files swept in lockstep — the Axum route registration, the client's `format!` URL template, and both docs table rows now read `/api/v1/sad/events/repairs/events`. The `docs/design/sadstore.md` column description also updated from `"Archived records for a repair"` to `"Archived events for a repair"`. Full `make` build passes; no other code references the old route.

### ~~10. `checkpoint` concept → `evaluation` (field, const, format strings, docstrings, test helpers, design doc, handler errors)~~ — RESOLVED

**File:** widespread — primary sites at `lib/kels/src/lib.rs:134-137`; `lib/kels/src/types/sad/verification.rs:59-60, 83, 102, 191, 257, 273-274, 323, 334-340, 355, 374, 398, 459-498, 564+, 682-683, 722, 737-738, 778-780, 831-834, 855, 870-873, 1012, 1050, 1096, 1114, 1128, 1139-1580`; `lib/kels/src/types/sad/event.rs:73, 148, 246`; `lib/kels/src/types/mod.rs:1572`; `services/sadstore/src/handlers.rs:1301, 1332, 1340, 1347, 1357`; `services/sadstore/src/repository.rs:107, 112`; `docs/design/sad-events.md:29, 38, 40-43, 55, 63, 85-86, 113, 132, 145, 170, 175, 185, 194`; `clients/test/scripts/test-sadstore.sh:405, 418`

The "checkpoint" concept (an event that evaluates `governance_policy` — `SadEventKind::Evl` or `Rpr`) is renamed to "evaluation", aligning the prose with the existing `SadEventKind::evaluates_governance()` method. This rename is layered on top of the records→events sweep:

- **Field:** `records_since_checkpoint: usize` → `events_since_evaluation: usize` (branch-state struct in `verification.rs`).
- **Field:** `saw_any_records: bool` → `saw_any_events: bool` (records→events only; no checkpoint in this name).
- **Constant:** `MAX_NON_CHECKPOINT_RECORDS` → `MAX_NON_EVALUATION_RECORDS` (per user guidance, keeps `RECORDS` count-noun suffix).
- **User-visible format strings:**
  - `verification.rs:337` `"SAD event {} exceeds checkpoint bound ({} non-checkpoint records, max {})"` → `"SAD event {} exceeds evaluation bound ({} non-evaluation events, max {})"`
  - `verification.rs:1190` test assert `err.to_string().contains("checkpoint bound")` → `.contains("evaluation bound")`
  - `verification.rs:855` test assert `"Expected no-checkpoint error..."` → `"Expected no-evaluation error..."`
  - `repository.rs:107, 112` error `"Cannot fork at version {} — sealed by checkpoint at version {}"` → `"...sealed by evaluation at version {}"`
  - `handlers.rs:1340, 1357` `"Cannot repair at version {} — sealed by checkpoint at version {}"` / `"repair must include a checkpoint at or after the divergence point"` → `"sealed by evaluation..."` / `"repair must include an evaluation..."`
- **Docstrings / comments:** `lib.rs:134-136` const rustdoc + three comment lines; `verification.rs:59, 273-274, 323`; `event.rs:73, 148, 246`; `types/mod.rs:1572`; `handlers.rs:1301, 1332, 1347`.
- **Test helpers + test names:** `create_v0_with_checkpoint` → `create_v0_with_evaluation`; `create_v0_no_checkpoint` → `create_v0_no_evaluation`; test names `test_checkpoint_overdue_at_64`, `test_valid_checkpoint_cycle`, `test_v0_no_checkpoint_v1_est_valid`, `test_checkpoint_after_est_accepted`, `test_chain_with_no_checkpoint_rejected_at_finish`, `test_est_at_v1_when_v0_had_no_checkpoint_accepted`, `test_est_at_v1_when_v0_declared_checkpoint_rejected`, `test_upd_at_v1_when_v0_had_no_checkpoint_rejected`, `test_last_governance_version_none_without_evaluated_checkpoint` → corresponding `_evaluation` forms.
- **Test digest labels:** `b"checkpoint-policy"` → `b"evaluation-policy"`; `b"checkpoint-policy-attacker"` → `b"evaluation-policy-attacker"`; `b"checkpoint-policy-legit"` → `b"evaluation-policy-legit"`; `b"new-checkpoint-policy"` → `b"new-evaluation-policy"`; `b"another-checkpoint-policy"` → `b"another-evaluation-policy"`.
- **Design doc (`docs/design/sad-events.md`):** 14 prose sites swept — `"checkpoint records"`, `"non-checkpoint records"`, `"evaluate a checkpoint"`, `"checkpoint bound"`, `"evaluated checkpoint"`, `"checkpoint seal"`, `"checkpoint proof"`, `"pure checkpoint"`, `"checkpoint evaluation semantics"` — to corresponding evaluation forms.
- **Test shell (`test-sadstore.sh:405, 418`):** comments `"no checkpoint — allows fork at this version"` / `"adversary fork — no checkpoint, bounded by governance_policy"` → `"no evaluation"` forms.

**Preserved:** Method name `evaluates_governance()` (already an "evaluation"-family name — doesn't need further rename). Verb form `"the verifier never errors on policy failure — it records the result"` (`verification.rs:70`). `governance_policy` / `last_governance_version` names (these are orthogonal — `governance_policy` is the policy, `evaluation` is the act of evaluating it).

**Suggested fix:** Tree-wide sweep `checkpoint` → `evaluation` / `CHECKPOINT` → `EVALUATION` in the listed sites, with the three exceptions above. Regression-guard with `git grep -i checkpoint` after sweep, filtering for `evaluates_governance` hits.

**Resolution:** Full sweep applied. `lib.rs:137` `MAX_NON_CHECKPOINT_RECORDS` → `MAX_NON_EVALUATION_RECORDS` (const name keeps `RECORDS` per user guidance; rustdoc at `:134-136` swept to `"Maximum non-evaluation records between evaluation events"`). `verification.rs` — field `records_since_checkpoint` → `events_since_evaluation` (6 sites), `saw_any_records` → `saw_any_events` (4 sites), format string `"exceeds checkpoint bound ({} non-checkpoint records, max {})"` → `"exceeds evaluation bound ({} non-evaluation events, max {})"`, `"Expected no-checkpoint error"` / `"checkpoint bound"` / `"Expected checkpoint overdue error"` test asserts swept, struct `AcceptCheckpointRejectWriteChecker` → `AcceptEvaluationRejectWriteChecker` (8 sites), test helpers `create_v0_with_checkpoint` → `create_v0_with_evaluation` and `create_v0_no_checkpoint` → `create_v0_no_evaluation` (~25 call sites), test names `test_checkpoint_overdue_at_64` → `test_evaluation_overdue_at_64` and the other eight test names swept per the mapping, section header `// Checkpoint tracking tests` → `// Evaluation tracking tests`, digest labels `b"checkpoint-policy"` → `b"evaluation-policy"` and the four variants (`-attacker`, `-legit`, `new-`, `another-`) swept.

`event.rs:73` `"reset records_since_checkpoint"` → `"reset events_since_evaluation"`. `event.rs:148` `"pure checkpoint, no policy change"` → `"pure evaluation, no policy change"`. `event.rs:246` `"present = policy evolution, absent = pure checkpoint"` → `"absent = pure evaluation"`. `types/mod.rs:1572` `"pure checkpoint"` → `"pure evaluation"`.

`handlers.rs:1301-1357` — five sites swept: `"Query the checkpoint seal"` → `"evaluation seal"`, `"truncate behind the checkpoint seal"` → `"evaluation seal"`, error string `"sealed by checkpoint at version"` → `"sealed by evaluation at version"`, comment `"include a checkpoint at or after"` → `"include an evaluation at or after"`, error string `"repair must include a checkpoint at or after the divergence point"` → `"repair must include an evaluation at or after the divergence point"`.

`repository.rs:107, 112` — comment `"Reject fork at or before the last checkpoint"` → `"last evaluation"`, error `"sealed by checkpoint at version"` → `"sealed by evaluation at version"`.

`docs/design/sad-events.md` — 14 prose sites swept, including section header `### Checkpoint Bound` → `### Evaluation Bound`, section header `### Checkpoint Seal` → `### Evaluation Seal`, and ASCII-diagram annotations `← pure checkpoint` → `← pure evaluation`.

`clients/test/scripts/test-sadstore.sh:405, 418` — two comment lines swept. **Preserved:** method `evaluates_governance()` (already an evaluation-family name); verb form `"it records the result"` at `verification.rs:70`; `governance_policy` / `last_governance_version` / `establishment_version` names (orthogonal to the evaluation concept). Post-fix `git grep -i checkpoint` returns zero hits outside `docs/claudit/**`. `make` passes cleanly (all test suites green).

### ~~11. `SadEventRepairRecord` → `SelRepairEvent` type rename~~ — RESOLVED

**File:** `lib/kels/src/types/sad/repair.rs:37-47`; `services/sadstore/migrations/0001_initial.sql` (table `sad_event_repair_records`); callers in `services/sadstore/src/repository.rs`; re-export in `lib/kels/src/lib.rs:106`

**Resolution:** Type renamed `SadEventRepairRecord` → `SelRepairEvent` at the definition (`repair.rs:40`), re-export at `lib/kels/src/lib.rs:106`, and all four callers in `services/sadstore/src/repository.rs:5, 229, 433, 437` (use statement, `::create()` call, `Query::<T>::new()`, `fetch` binding). SQL table rename followed: `#[storable(table = "sad_event_repair_records")]` → `#[storable(table = "sel_repair_events")]` at `repair.rs:38`; migration SQL at `services/sadstore/migrations/0001_initial.sql:63, 65, 69` swept (table def + FK + index). Prose at `docs/design/sadstore.md:80` updated: `"sad_event_repair_records links each repair"` → `"sel_repair_events links each repair"`, and the English `"displaced records"` / `"archived records"` surrounding prose in the same paragraph swept to `"displaced events"` / `"archived events"`.

**Preserved:** `ARCHIVED_RECORDS_TABLE` constant at `services/sadstore/src/repository.rs:401` remains (the const-name pattern `_RECORDS_TABLE` mirrors `MAX_NON_EVALUATION_RECORDS` per user guidance that const names keep `RECORDS`). The SQL table name it holds (`"sad_event_archives"`) is already post-rename. Also preserved: `max_records_per_prefix_per_day` function name and the rate-limit param names (`record_count`, `new_record_count`, `max_records`) at `services/sadstore/src/handlers.rs:138, 163, 166, 174, 185, 193, 1212, 1405, 1466, 1484, 1495, 1546`, plus the env-var `SADSTORE_MAX_RECORDS_PER_EVENT_LOG_PER_DAY`. These are not part of this round's scope — flag for a later pass if user wants them swept.

Post-fix `git grep SadEventRepairRecord\|sad_event_repair_records` returns zero hits outside `docs/claudit/**`. `make` build + test suite green.

---

## Follow-up sweep — "anything that is an event should be called an event"

User reviewed the Round 14 preservations and rejected the invented "const keeps `RECORDS`" pattern. The correct rule is plain: anything that is an event should be called an event. The initial guidance on `MAX_NON_EVALUATION_RECORDS` was a typo — the correct form is `MAX_NON_EVALUATION_EVENTS`. All previously preserved `_RECORDS` / `records` / `record` sites that reference SAD events were swept.

### ~~12. `MAX_NON_EVALUATION_RECORDS` → `MAX_NON_EVALUATION_EVENTS`~~ — RESOLVED

**File:** `lib/kels/src/lib.rs:134-137`; `lib/kels/src/types/sad/verification.rs:335, 340`; `docs/design/sad-events.md:38`

**Resolution:** Const renamed and all two call sites updated. Rustdoc at `lib.rs:134-136` swept: `"Maximum non-evaluation records between evaluation events on event chains. MINIMUM_PAGE_SIZE - 1 leaves room for the evaluation event in the page. Unlike KELs (which need 2 slots for rec+rot), event evaluations need only 1 slot."` — first line now says `events` (was `records`).

### ~~13. `ARCHIVED_RECORDS_TABLE` → `ARCHIVED_EVENTS_TABLE`~~ — RESOLVED

**File:** `services/sadstore/src/repository.rs:213, 227, 401, 449`

**Resolution:** Const renamed; all four call sites updated (insert calls × 2, const declaration, query builder). SQL table value `"sad_event_archives"` already post-rename, unchanged.

### ~~14. `get_repair_records` method → `get_repair_events`~~ — RESOLVED

**File:** `services/sadstore/src/repository.rs:425` (definition) + `services/sadstore/src/handlers.rs:1737` (caller) + `services/sadstore/tests/repair_tests.rs` (9 sites)

**Resolution:** Method rename + all callers and test references swept. Module rustdoc at `repair_tests.rs:2` updated to match.

### ~~15. Rate-limit function + params: `max_records_per_prefix_per_day` / `record_count` / `max_records` / `new_record_count` / `SADSTORE_MAX_RECORDS_PER_EVENT_LOG_PER_DAY`~~ — RESOLVED

**File:** `services/sadstore/src/handlers.rs:138-193` (function + params + rustdoc); `services/sadstore/src/handlers.rs:1212, 1405, 1462, 1480, 1491, 1542` (downstream uses); `services/sadstore/manifests.yml.tpl:67-68`; `project.garden.yml:126`; `docs/design/sadstore.md:195`

**Resolution:** All swept to event naming:
- Function `max_records_per_prefix_per_day` → `max_events_per_prefix_per_day`
- Env var `SADSTORE_MAX_RECORDS_PER_EVENT_LOG_PER_DAY` → `SADSTORE_MAX_EVENTS_PER_EVENT_LOG_PER_DAY`
- Params: `record_count` → `event_count`, `max_records` → `max_events`, `new_record_count` → `new_event_count`
- Rustdoc `"Checks whether adding record_count new records"` → `"Checks whether adding event_count new events"`; `"new record count"` → `"new event count"`; `"number of new records"` → `"number of new events"`
- Manifest template (`SADSTORE_MAX_EVENTS_PER_EVENT_LOG_PER_DAY` env var + Garden var `maxEventsPerEventLogPerDay`); `project.garden.yml` variable renamed in lockstep
- Doc table at `sadstore.md:195` env var name swept

### ~~16. `reap_expired_records` TTL reaper + prose for SAD Objects~~ — RESOLVED

**File:** `services/sadstore/src/handlers.rs:62, 64, 72, 80, 98, 102, 795, 860, 881, 882`

**Resolution:** The TTL reaper operates on SAD Objects (Layer 1), not events. Renamed `reap_expired_records` → `reap_expired_objects` at definition + caller; swept surrounding prose to "objects": `"Max expired records to reap"` → `"Max expired objects to reap"`, `"TTL-expired records"` → `"TTL-expired objects"`, `"records created before this time are expired"` → `"objects created before this time are expired"`, `"Find expired records for this custody"` → `"Find expired objects for this custody"`, `"Look up the record in sad_objects"` → `"Look up the object in sad_objects"`, `"TTL check (per-record: ...)"` → `"TTL check (per-object: ...)"`, `"the record becomes inaccessible"` → `"the object becomes inaccessible"`, `"ephemeral records"` → `"ephemeral objects"`, `"Gossip replication decision for a record"` → `"...for an object"`, `"records are accepted but not replicated"` → `"objects are accepted but not replicated"`, `"the record is stored locally"` → `"the object is stored locally"`. Also `"store records in Redis"` (peer-cache context) → `"store entries in Redis"` to avoid "PeerRecord" overloading.

### ~~17. FFI ABI param `json_signed_records` → `json_signed_events`~~ — RESOLVED

**File:** `lib/ffi/src/sad.rs:189, 199, 208`

**Resolution:** C ABI parameter renamed across the Doxygen `@param` reference, the `extern "C"` function signature, and the internal `from_c_string(...)` call. Round 13 #5's FFI ABI-stability preservation explicitly rescinded — same user guidance as findings #9 and #11 (ABI renames land atomically with the KELS-133 branch).

### ~~18. SQL + test-prose sweeps (`repair_tests.rs`, `integration_tests.rs`, `migrations/0001_initial.sql`, `sad-events.md`, `sadstore.md`)~~ — RESOLVED

**File:** `services/sadstore/tests/repair_tests.rs` (multiple test-prose sites); `services/sadstore/tests/integration_tests.rs:419, 431, 436`; `services/sadstore/migrations/0001_initial.sql:14`; `docs/design/sad-events.md` (~20 prose sites); `docs/design/sadstore.md` (~11 prose sites)

**Resolution:** Remaining `record` / `records` prose across test comments + helper param names (`records: &[SadEvent]` → `events: &[SadEvent]` on `save_batch_txn` and `truncate_and_replace_txn`), `(records, has_more)` tuple binding in `test_get_repair_events_nonexistent`, `let records = vec![event]` in integration test + downstream `.json(&records)` → `events`. SQL migration inline comment `-- record kind` → `-- event kind`. Design doc prose swept comprehensively: `sad-events.md` §Threat Model, §Divergence Model, §Repair, §Verification, §Handler Flow, §Event Kinds (renamed from `§Record Kinds`), §write_policy per kind — all uses of `record`/`records` referring to SadEvents swept; `sadstore.md` §Topic, §Prefix Derivation, §Custody, §Divergence, §Repair, §Ephemeral Objects — all SadEvent references swept, SAD-Object references swept to `object`/`objects`.

---

**Cumulative:** 18 findings resolved in round 14. Total rounds 1–14: 95 resolved. Post-fix `git grep -iE '\brecord\b|\brecords\b|RECORDS|checkpoint|SadEventRepairRecord|repairs/records'` outside `docs/claudit/**` returns only verb-form uses (`"it records"`, `"record as stale"`), PeerRecord / PeerHistory (Registry/KEL types unrelated to SAD), `StorageError::DuplicateRecord` (external crate error variant), KEL-related `RecoveryRecord` / `RaftLogAuditRecord`, `verify_records()` on PeerHistory, and `state.record()` verb form on ExpansionState — all intentional preservations. Full `make` (fmt, deny, clippy, test, build) green.

---

## Positive Observations

- **Round 13's seven resolutions all hold under cold reading.** `git grep -E 'new_record:|record: &SadEvent' lib/ services/ clients/` returns zero hits in non-test code; the `PolicyChecker` trait signature carries `new_event: &SadEvent` / `event: &SadEvent` throughout. `verification.rs` tree-wide grep for `\brecord\b` yields only the preserved count-noun sites (`records_since_checkpoint` field, `saw_any_records` field, `"non-checkpoint records"` format string, `"Number of records since"` docstring, verb form `"it records"`) — every sweep target in round 13 #2 is resolved. `sync.rs` and `custody.rs` landed clean as well. Cumulative 77 permanent fixes.

- **The identifier-level rename remains complete.** Tree-wide `git grep 'sad_record\|SadRecord\|sad-record\|SAD record\|sad_pointer\|SadPointer\|sad-pointer\|SAD pointer\|chain_prefix\|CHAIN_PREFIX\|chained record\|preload_sad_records\|sad_records\|SadRecords'` excluding `docs/claudit/**` returns **zero** hits after 13 rounds. Every round 14 finding is at the variable-binding / parameter / format-string / rustdoc-prose layer — the identifier surface is uniformly renamed.

- **Count-noun preservation rule rescinded in full; "event means event" is the rule.** The round 9 #9 rubric has been retired for this branch (see rescission note in the Summary section). My initial round-14 follow-on — that const names kept `_RECORDS` — was also invented, not user-directed, and the user rejected it on review. The correct rule is plain: anything that is an event should be called an event. Sites now swept: `MAX_NON_EVALUATION_EVENTS`, `events_since_evaluation`, `saw_any_events`, `ARCHIVED_EVENTS_TABLE`, `SADSTORE_MAX_EVENTS_PER_EVENT_LOG_PER_DAY`, `max_events_per_prefix_per_day`, `event_count` / `new_event_count` / `max_events` params, `get_repair_events`, `SelRepairEvent`, URL path `/repairs/events`. Verb forms (`"it records"`, `"record as stale"`) and non-SadEvent types (`RecoveryRecord`, `RaftLogAuditRecord`, `PeerHistory.records`, `StorageError::DuplicateRecord`) remain preserved independently — they aren't events.

- **Round 14's sweep of the public SDK client (finding #1) is the last substantial public-API surface.** Tree-wide `git grep 'pub async fn.*: &\[SadEvent\]' lib/` returns `submit_sad_events(&self, records: &[crate::SadEvent])` at `sadstore.rs:201` as the sole `pub async` method with a `&[SadEvent]` parameter literally named `records`. Other `pub` methods that take `&[SadEvent]` already use the role naming (`forward_sad_events` / `verify_page` — the latter was renamed in round 13 #2). The `PolicyChecker` trait (round 13 #1) was the last public trait; `SadStoreClient::submit_sad_events` is the last public free-standing async method.

- **URL path `/repairs/records` is now on the sweep list (finding #9).** Rounds 11–13 preserved it as ABI, but user confirmed `/repairs/events` is the right form. Coordinated edits across `services/sadstore/src/server.rs:55`, `lib/kels/src/client/sadstore.rs:334`, `docs/endpoints.md:150`, `docs/design/sadstore.md:139`. No gossip peer compatibility concern — the sweep lands atomically with the rest of KELS-133 before any production deploy.

- **`SadEventRepairRecord` → `SelRepairEvent` is on the sweep list (finding #11).** Round 10 preserved the name as a count-noun compound; user reversed that. The SQL table `sad_event_repair_records` follows to `sel_repair_events`. The twin `ARCHIVED_RECORDS_TABLE` const is flagged for user confirmation in finding #11's preservation note — keeping the `RECORDS` suffix for parallel structure with `MAX_NON_EVALUATION_RECORDS`.

- **Structural `"chain"` / `"chained"` uses are preserved throughout round 14 findings.** `:16` `"A chained, self-addressed event"` in `docs/design/sadstore.md` (round 13 #6 sweep), `custody.rs:90, :96` `"a link in a chain breaks verification for descendants"` (structural, per round 13 #3), `services/gossip/src/sync.rs:505` `"fetch full chain"` (structural — it's the SadEvent chain, the word `chain` describes shape). Round 14 findings apply the sweep to `records` / `"records"` prose only, not to `chain` or `chained`.

- **Round 14's findings all cite concrete prior-round rubrics and no invented preservation.** Finding #1 cites round 13 #1 (public-trait param rubric) and round 13 #5 / #6 canonical forms (`events endpoint`, `event's SAID`). Finding #2 cites round 13 #3 with an explicit note that round 13 #3's resolution was scoped to `:67–:96` only. Finding #3 cites round 13 #1 (`"Icp record missing write_policy"` → `"Icp event missing write_policy"` precedent for `Evl record` / `Est record`). Finding #4 cites round 13 #6 (`"the event's SAID"` canonical) and finding #2 in this round (`SAD Event Log records` → canonical `... events`). Finding #5 cites round 10 positive-observation count-noun preservation for `SadEventRepairRecord`. Finding #6 cites round 13 #2 (typed `Vec<SadEvent>` → `events`). Finding #7 cites round 13 #7 (`"Skip leading records"` → `"Skip leading events"`). Finding #8 cites round 13 #5 FFI sweep + round 13 #2 typed-bindings rubric. URL-path preservation at finding #1's `:334` cites round 10 #7 FFI ABI precedent.

- **Diminishing returns was overtaken by two bigger renames mid-round.** Findings #1–#8 were the diminishing-returns tail; findings #9–#11 added a URL-path rename, the `checkpoint` → `evaluation` concept rename, and the `SadEventRepairRecord` → `SelRepairEvent` type rename in response to user guidance delivered mid-round. The combined round-14 sweep is substantially larger than round 13 in code-site count — roughly 100+ touched sites across ~15 files plus two SQL migrations — but remains narrow in semantic risk: all changes are renames, no behavior changes, no new guards, and the test suite (~1000 tests across the workspace) passes unchanged.

- **Round 14 resolves all 18 of its own findings.** Cumulative across rounds 1–14: 95 resolved findings. Full `make` passes (fmt, deny, clippy, test, build) after the sweep. Post-fix `git grep -iE 'checkpoint|SadEventRepairRecord|sad_event_repair_records|repairs/records|MAX_NON_\w*RECORDS|ARCHIVED_RECORDS_TABLE|max_records|record_count|json_signed_records'` outside `docs/claudit/**` returns zero hits. Remaining `\brecord\b|\brecords\b` hits in non-claudit locations are all verb forms (`"it records"`, `"record as stale"`), non-SadEvent domain types (PeerRecord, RecoveryRecord, RaftLogAuditRecord), or external error variants (`DuplicateRecord`). The rename surface for KELS-133 is clean.
