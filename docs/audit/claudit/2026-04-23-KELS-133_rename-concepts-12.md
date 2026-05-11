# Branch Audit: KELS-133_rename-concepts (Round 12) — 2026-04-23

Branch `KELS-133_rename-concepts` vs `main`: 114 files, 4046 insertions / 2635 deletions. No commits since round 11 (`git log 926fdd5..HEAD` empty at audit time; working tree clean). Cold re-read after `/clear`, focused on `services/sadstore/src/handlers.rs` — a file round 9 #1 swept only for `chain_prefix` → `sel_prefix` (14 sites) and has otherwise never been scoped — plus three collateral surfaces (half-renamed env var, short-form drift in `lib/ffi/src/sad.rs` module doc, and one field rustdoc in `SadEvent`). Rounds 1–11 cumulatively resolved 66 findings.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 1        |
| Low      | 0    | 3        |

Cumulative across rounds 1–11: 66 resolved. Round 12 surfaces 4 new open findings, all resolved in this round. None contradict a prior round's explicit preservation judgment — each is at a surface no prior round scoped. Diminishing-returns territory: the identifier-level rename has been complete for several rounds, and runtime behavior is unaffected by any round-12 finding.

---

## Medium Priority

### ~~1. `submit_sad_events` handler in `services/sadstore/src/handlers.rs` — `records` parameter, loop bindings, `new_record_count` local, and four user-visible error strings still carry the pre-rename vocabulary~~ — RESOLVED

**File:** `services/sadstore/src/handlers.rs:1134, 1138, 1141-1143, 1147, 1149, 1158-1160, 1163, 1168-1169, 1173, 1180, 1190-1191, 1195, 1212, 1247, 1249-1251, 1268, 1275, 1291, 1297-1298, 1316-1317, 1321, 1350, 1362, 1398, 1405, 1408, 1419, 1423, 1450, 1466, 1470, 1483, 1487, 1495, 1544, 1546`

~~Round 9 #1's resolution text stated its sweep of this file covered "14 sites in `submit_sad_events` and helpers" — those 14 sites were specifically `chain_prefix` → `sel_prefix` (the `git show 7860d3d` diff confirms: `chain_prefix` was the only token renamed in that commit's touches to this file). The `records` / `new_records` / `new_record_count` / `record_count` variable family and the surrounding error strings and docstrings were never in the round-9 rubric.~~

~~The function signature at `:1147` is `Json(records): Json<Vec<kels_core::SadEvent>>` — the parameter name `records` predates the type rename. Round 9 #1's own stated rubric (function parameters, for-loop bindings, struct-destructure binding, all format-string arguments) calls for role naming of the parameter when the type is a concrete typed `Vec<SadEvent>`. The sibling parameter `Json(request): Json<kels_core::SadEventPageRequest>` at `:1553` is already role-named; only the submit-path parameter remains on the old form.~~

~~Concrete sites grouped by class:~~

- ~~**Parameter and primary local bindings** — eleven places where the variable is literally `records: Vec<SadEvent>`.~~
- ~~**Derived local `new_records`** — nine sites carrying `new_records: Vec<SadEvent>`.~~
- ~~**Counter local `new_record_count`** and adjacent `record_count` / `new_record_count` function params — count-noun form, preserved per round 9 precedent.~~
- ~~**User-visible error strings** — four HTTP 4xx/5xx response bodies.~~
- ~~**Docstrings and prose** — thirteen comment/docstring/log sites inside the one handler.~~

**Resolution:** Swept via targeted `Edit` calls in `services/sadstore/src/handlers.rs`:

- Function rustdoc (`:1134-1143`) — `"Submit SAD event records"` → `"Submit SAD events"`; `"new records in context"` → `"new events in context"`; the three `"record"`/`"records"` uses in the Rpr-path paragraph → `"event"`/`"events"`.
- Parameter rename — `Json(records): Json<Vec<kels_core::SadEvent>>` → `Json(events)` at `:1147`; 11 downstream binding sites swept (`events[0]`, `events.iter()`, `for r in &events`, `events.iter().find(...)`, `for event in &events`, `events.iter().map(...)`, `events.iter().filter(...)`, `truncate_and_replace(&mut tx, &events)`, `events.first()`).
- Inner binding — `let new_records: Vec<kels_core::SadEvent>` → `let new_events`; all nine downstream references swept (`new_events.is_empty()`, `new_events.len()`, `new_events.iter()`, `verify_page(&new_events)`, `save_batch(&mut tx, &new_events, ...)`, `new_events.len() as u32`).
- Counter preserved — `new_record_count` / `record_count` left as-is per the round 9 `non-checkpoint records` count-noun rationale; the count-of-entries mechanism compound stays even though the typed `Vec<SadEvent>` variables switched to `events` naming.
- User-visible error strings — `"All records must have the same prefix"` → `"All events must have the same prefix"`; `"Record SAID verification failed"` → `"SAD event SAID verification failed"`; `"Too many records for this SEL prefix"` → `"Too many events for this SEL prefix"` (at `check_prefix_rate_limit` line 175); `"Record verification failed"` → `"SAD event verification failed"`.
- Docstrings/comments — thirteen sites swept (`"All records must..."`, `"Verify SAID integrity for all records"`, `"just the first record"`, `"Dedup first: filter out records..."`, `"Historical Rpr records dedup out..."`, `"Detect repair from post-dedup records..."`, `"Repair path: truncate/archive first, then verify remaining + repair records"`, `"Now verify the entire chain (post-truncation + repair records)..."`, `"establishment record at version"`, `"Normal path: verify existing chain + new records..."`, `warn!("Failed to store records: ...")`, `"Accrue only actual new records to prefix rate limit"`).
- Adjacent shadow-bindings swept for consistency — `get_sad_events` at `:1566-1577` (the `Ok(records) if records.is_empty()` match-arm shadow) and `get_repair_records` at `:1744-1753` (the `Ok((records, has_more))` → `Ok((events, has_more))` destructure plus `"Failed to get repair records"` → `"Failed to get repair events"`).

Post-fix `grep records services/sadstore/src/handlers.rs` returns only the principled preserved sites: `reap_expired_records` (Layer 1 sad_objects generic/count-noun), `check_prefix_rate_limit` docstrings + `record_count`/`max_records` / `new_record_count` count-noun parameters (rounds 9 precedent), peer-history `history.records` (unrelated Registry API type), and the three generic-comment uses at `:537, :882` (Layer 1 SAD object / `once` ephemeral-records context). `make check` and `make clippy` both pass cleanly.

---

## Low Priority

### ~~2. Env var `SADSTORE_MAX_RECORDS_PER_EVENT_LOG_PER_DAY` is half-renamed on this branch — `POINTER` → `EVENT_LOG` was applied, but `RECORDS` → `EVENTS` was not~~ — RESOLVED

**File:** `services/sadstore/src/handlers.rs:139`; `services/sadstore/manifests.yml.tpl:67`; `docs/design/sadstore.md:195`

~~The pre-branch name was `SADSTORE_MAX_RECORDS_PER_POINTER_PER_DAY`. The branch renamed the middle segment (`POINTER` → `EVENT_LOG`) but left `RECORDS` intact, producing the mixed-vocabulary `SADSTORE_MAX_RECORDS_PER_EVENT_LOG_PER_DAY`. The env var's own docstring at `handlers.rs:137` reads `"Max SAD events per SEL prefix per day"` — the comment uses `"SAD events"` but the identifier uses `"RECORDS"`. The sibling env var in the same file (`SADSTORE_MAX_WRITES_PER_IP_PER_SECOND`) reads consistently.~~

~~This is operator-visible (via `manifests.yml.tpl`) and crossing the deployment boundary carries a coordination cost — changing the env var name without a fallback would silently reset every deployment's rate limit to the default. Either the current mixed form is accepted as the post-rename name, or a second rename applies (`RECORDS` → `EVENTS`) with ops-team sign-off.~~

**Resolution:** Accepted the env var name `SADSTORE_MAX_RECORDS_PER_EVENT_LOG_PER_DAY` as final (finding's option 1). Rationale: `RECORDS` in this identifier functions as the chain-entry count-noun — the compound reads `"max [records per event log] per day"`, where `records` is the count of chain entries, directly parallel to `MAX_NON_CHECKPOINT_RECORDS` at `lib/kels/src/lib.rs:137` and `records_since_checkpoint` at `lib/kels/src/types/sad/verification.rs:60` (both preserved under the round 3 #3 role/mechanism split and reaffirmed in round 9 #9). The Rust fn name `max_records_per_prefix_per_day` at `handlers.rs:138` also already uses the count-noun form — the env var is consistent with the internal Rust identifier, which is the more important alignment. No code change required; deployment remains unaffected.

### ~~3. `get_sad_events` handler returns `"Chain not found"` / logs `"Failed to get chain"` — refers to the SAD Event Log using the pre-rename short noun~~ — RESOLVED

**File:** `services/sadstore/src/handlers.rs:1567, 1579, 1595`

~~Three sites in two adjacent handlers:~~
- ~~`:1567` `(StatusCode::NOT_FOUND, "Chain not found").into_response()` — user-visible 404 body when an SEL has no events.~~
- ~~`:1579` `warn!("Failed to get chain: {}", e)` — operator-visible log.~~
- ~~`:1595` `Ok(None) => (StatusCode::NOT_FOUND, "Chain not found").into_response()` — user-visible 404 body in `get_sel_effective_said`.~~

~~Round 9 #7 / round 11 #3 settled the renamed SAD Event Log / SEL vocabulary on `docs/endpoints.md`; these two error responses are the user-visible counterparts. The `"chain"`-as-structural-noun preservation (round 10 positive-observation #2) applies where the prose describes the shape (`"event chain"`, `"Event Chains have no recovery/contest"`), but `"Chain not found"` is specifically referring to the typed SEL not the structural chain — the user asked for a specific SEL by prefix and got a 404.~~

**Resolution:**
- `:1567` `"Chain not found"` → `"SAD Event Log not found"` (swept; also folded in the local shadow-binding fix in the adjacent `Ok(events) => ...` arm so the paging bind reads `Ok(events) if events.is_empty()` / `let events: Vec<_> = events.into_iter().take(...)` / `SadEventPage { has_more, events }` with struct-field shorthand instead of the `events: records` rename-in-rewrap).
- `:1579` `"Failed to get chain"` → `"Failed to get SAD Event Log"`.
- `:1595` `"Chain not found"` → `"SAD Event Log not found"` in `get_sel_effective_said`.

Matches the endpoints-doc form (`docs/endpoints.md:146`, fixed in round 11 #3) and the CLI help (`"Fetch and display a SAD Event Log"`).

### ~~4. `SadEvent::kind` rustdoc says `"The kind of this event record."` — the type being described is `SadEvent`, and the `record` noun is the pre-rename residue~~ — RESOLVED

**File:** `lib/kels/src/types/sad/event.rs:138`

~~Field rustdoc immediately above `pub kind: SadEventKind`. The surrounding field rustdocs in the same struct at `:136` (`"The topic of this event chain"` — structural `"event chain"`, principled), `:140` (`"SAID of the content object in the SAD store (None for v0 inception)"`), and `:143` (`"SAID of the custody SAD (optional, controls readPolicy/nodes for the chain)"`) are either role-named or structurally bare. The `"event record"` token in `:138` is the last bit of the pre-rename phrasing in this struct's field docs.~~

~~Analogous sites in the same file:~~
- ~~`:78` `/// True for repair records (Rpr only).` — method `is_repair` on `SadEventKind`; pre-rename vocabulary.~~
- ~~`:83` `/// True for inception records (Icp only).` — same method family.~~

~~All three can sweep to `"event"` in one pass. Note `:154` `"has their fork bounded to ≤63 records"` preserves correctly — that's the mechanism-count compound (round 9 #9 precedent, aligned with `MAX_NON_CHECKPOINT_RECORDS`).~~

**Resolution:**
- `:78` — `/// True for repair records (Rpr only).` → `/// True for repair events (Rpr only).`
- `:83` — `/// True for inception records (Icp only).` → `/// True for inception events (Icp only).`
- `:138` — `/// The kind of this event record.` → `/// The event kind.`

`:154`'s `"has their fork bounded to ≤63 records"` preserved (mechanism-count compound per round 9 #9 precedent). Doc-only change; `make check` passes cleanly.

---

## Positive Observations

- **Round 11's three resolutions all hold under cold reading.** The gossip announcement rustdoc at `services/gossip/src/types/sad.rs:21` now reads `"The SEL prefix that was updated."` — matches the sibling at `:23-24` and round 10's canonical form. `test-sadstore.sh`'s `CHAIN_PREFIX` variable, `"Chain Record Submission"` banner, and `"chain events"` prose are gone (`git grep CHAIN_PREFIX\|Chain Record\|chain events clients/test/scripts/test-sadstore.sh` returns zero hits). `docs/endpoints.md:145-160` table and notes read consistently in the renamed vocabulary. The 66 cumulative resolved findings are permanently fixed.

- **The identifier-level rename remains complete.** A tree-wide `git grep 'SadPointer\|sad_pointer\|SAD pointer\|SadChain\|sad_chain\|SAD chain\|SadRecord\|sad_record\|SAD record\|chained record\|chain_prefix\|CHAIN_PREFIX\|preload_sad_records\|sad-record:\|sad-pointer'` excluding `docs/claudit/**` returns zero hits. Every pre-rename type name, function name, snake_case identifier, cache-key literal, and test-script variable has been swept. The round-12 findings are exclusively at the docstring / prose / variable-name layer inside handlers and adjacent files — the public surface is clean.

- **The `records` stragglers in `submit_sad_events` (finding #1) are confined to one handler.** A grep of `records` in `services/sadstore/src/handlers.rs` returns a high density in `submit_sad_events` (`:1144-1549`) and a surprising shadow-binding in `get_sad_events` (`:1566-1577` flips `events` → `records` → `events` across three lines), then scattered uses in `reap_expired_records` and the rate-limit helpers where `records` is a count-noun (principled per the round 9 `non-checkpoint records` precedent). The finding is real but tightly scoped; a single file's sweep closes it.

- **The half-renamed env var (finding #2) is the only post-rename mixed-vocabulary identifier.** Every other env var in the tree uses either fully-renamed or pre-rename-preserved naming. `SADSTORE_MAX_WRITES_PER_IP_PER_SECOND` uses plain words; `SADSTORE_IP_RATE_LIMIT_BURST` is semantic; `SADSTORE_MAX_OBJECT_SIZE` is semantic. The odd-one-out is `MAX_RECORDS_PER_EVENT_LOG` which is specifically the branch's rename target. Resolving it either way (accept as final or rename to `EVENTS`) restores consistency.

- **The `"Chain not found"` error string (finding #3) is the only user-visible HTTP response body that still uses the pre-rename noun.** A grep of `"Chain"` across service handlers shows it confined to `sadstore/src/handlers.rs:1567, 1579, 1595` and two non-user-visible comments. All other 4xx/5xx response bodies in `sadstore/src/handlers.rs` already use `"SAD event"` / `"SEL"` vocabulary (`"All records must have the same prefix"` from finding #1 being the other exception).

- **`SadEvent::kind` rustdoc drift (finding #4) is the last docstring residue inside the primary `SadEvent` struct.** The 160-line struct definition at `lib/kels/src/types/sad/event.rs:113-157` reads cleanly in post-rename vocabulary at every other docstring. Finding #4's three sites (`:78, 83, 138`) are the remaining pre-rename short-form uses on the type's own file; the field/method rustdocs elsewhere (`:115-116, 118, 121-122, 140, 143, 146-149, 152-156`) already use the renamed vocabulary.

- **Round 12 does not repeat the invented-preservation pattern from round 9.** Each finding cites a specific rubric from prior rounds (round 9 #1 for the variable-name sweep scope; round 9 #9's `non-checkpoint records` count-noun preservation; round 9 #7 / round 11 #3 for the SAD Event Log vocabulary on user-visible HTTP responses; round 10 positive-observation #2 for structural `"event chain"`). Sites genuinely preserved on prior rounds (`non-checkpoint records`, `event chain` adjective, FFI ABI parameter names) are not re-opened.

- **Cumulative 66 resolved + 4 open shows the curve is flattening hard.** Rounds 1–5 resolved 40+ (identifier renames). Rounds 6–8 resolved ~20 (docstring/prose sweep on primary files). Rounds 9–10 resolved ~15 (local variables, cache keys, accessor method, one correctness bug). Round 11 resolved 3 (two out-of-scope prior-round sites + one endpoint table). Round 12 finds 4 — a medium + three lows, all at surfaces prior rounds never scoped. The cumulative chart is asymptotic; by round 13–14 there will likely be nothing left that isn't structurally principled preservation. The branch is ship-ready at every layer that tooling can verify and at every user-visible surface except the four small drift sites above.
