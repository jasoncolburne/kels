# Branch Audit: KELS-133_rename-concepts (Round 10) — 2026-04-23

Branch `KELS-133_rename-concepts` vs `main`: 113 files, 3887 insertions / 2610 deletions. No commits since round 9 (`git log 7860d3d..HEAD` empty at audit time). Cold re-read after `/clear`. Rounds 1–9 cumulatively resolved 55 findings across type/function identifiers, docstrings, error strings, CLI output, SQL/migration banners, design-doc prose, and top-level user docs. Round 10's focus: surfaces prior rounds did not reach — (a) the `compute_sad_event_prefix` *rustdoc call form* in `lib/exchange/src/key_publication.rs` (no round covered it), (b) the public **`current_record()`** accessor on `SadEventVerification` and its referencing sites in `docs/design/{sad-events,sadstore}.md`, (c) the four `test_sad_record_*` test function names in `lib/kels/src/types/sad/event.rs` (the only `sad_record` residue left in the tree), and (d) stragglers in `clients/cli/src/commands/exchange.rs` and design docs carrying the `"event prefix"` / `"tip record"` / `"event chain"` short forms where rounds 8–9 settled on `"SEL prefix"` / `"tip event"` / `"SAD events"`.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 1        |
| Medium   | 0    | 2        |
| Low      | 0    | 5        |

Cumulative across rounds 1–9: 55 resolved. Round 10 surfaces 8 new open findings: 1 high (`key_publication.rs` rustdoc arg mismatch — correctness, not just vocabulary), 2 medium (`current_record()` public API name drift; four `test_sad_record_*` test fns), 5 low (CLI error strings + design-doc/FFI short-form stragglers). None of these contradict a prior round's explicit preservation judgment — each is at a surface no prior round scoped.

---

## High Priority

### ~~1. `EncapsulationKeyPublication` rustdoc example passes `kel_prefix` to `compute_sad_event_prefix` — signature takes `write_policy`, not `kel_prefix`~~ — RESOLVED

**File:** `lib/exchange/src/key_publication.rs:13-14`

~~The type-level rustdoc says:~~

~~```rust~~
~~/// Anyone can discover the key by computing the deterministic event prefix:~~
~~/// `compute_sad_event_prefix(kel_prefix, ENCAP_KEY_KIND)`.~~
~~```~~

~~But the function's actual signature at `lib/kels/src/types/sad/event.rs:164-167` is `compute_sad_event_prefix(write_policy: cesr::Digest256, topic: &str)`. The real discovery flow (per `docs/design/exchange.md:91` and the live CLI code) is a two-step derivation: derive `write_policy = endorse(kel_prefix).said`, then call `compute_sad_event_prefix(write_policy, topic)`. Passing `kel_prefix` directly (as the rustdoc example suggests) would compute an entirely different prefix that no SEL on the network actually uses.~~

**Resolution:** Rewrote the rustdoc example as the correct two-step form:

```rust
/// Anyone can discover the key by computing the deterministic SEL prefix:
/// derive `write_policy = endorse(kel_prefix).said`, then call
/// `compute_sad_event_prefix(write_policy, ENCAP_KEY_KIND)`.
```

`write_policy` now appears as the first argument, matching the function signature. Also swept the `"deterministic event prefix"` → `"deterministic SEL prefix"` short-form drift on the same line (finding #8's key_publication.rs half). `make check` passes cleanly.

---

## Medium Priority

### ~~2. `SadEventVerification::current_record()` accessor name contradicts its rustdoc and return type — `pub` API drift~~ — RESOLVED

**File:** `lib/kels/src/types/sad/event.rs:299`; call sites at `lib/kels/src/types/sad/verification.rs:577, 631, 936, 1134, 1150, 1228, 1246, 1309, 1351, 1552`; `lib/policy/src/identity_chain.rs:90`; referenced by name in `docs/design/sad-events.md:119` and `docs/design/sadstore.md:92`

~~The method signature, return type, and rustdoc all use the renamed vocabulary (`/// The latest verified event in the chain.` → `pub fn current_record(&self) -> &SadEvent`) but the method name itself is `current_record`. The internal field is `tip: SadEvent`. The sibling accessor is `current_content()`. The two design docs explicitly reference it by name in the accessor list. Per round 9 #9's rubric ("the type being described is `SadEvent`; `"SAD record"` is stale"), the `record` token in the method name is the last bit of old vocabulary in an otherwise-renamed accessor.~~

**Resolution:** Renamed `current_record()` → `current_event()` at the definition (`event.rs:299`). Swept all 11 call sites in lockstep: 10 test sites in `lib/kels/src/types/sad/verification.rs` (`sed -i '' 's/current_record(/current_event(/g'`) and 1 call site in `lib/policy/src/identity_chain.rs:90`. Updated both design-doc accessor lists (finding #6's coordinated updates): `docs/design/sad-events.md:119` and `docs/design/sadstore.md:92` — both now start with `current_event()`. Post-fix `git grep current_record` across the tree (excluding `docs/claudit/**`) returns zero hits. `make check` passes cleanly.

### ~~3. Four `test_sad_record_*` test function names — the only `sad_record` residue left on the branch~~ — RESOLVED

**File:** `lib/kels/src/types/sad/event.rs:403, 420, 445, 464`

~~Four test function names (`test_sad_record_inception_no_content`, `test_sad_record_chain_increment`, `test_sad_record_verify_said`, `test_sad_record_verify_prefix`) were the only `sad_record` / `SAD record` residue left in the tree after round 9 — a tree-wide `git grep "sad_record|SadRecord|sad-record|SAD record"` (excluding `docs/claudit/**`) returned exactly these four hits. The test bodies themselves are role-named correctly (`SadEvent::create`, `event.kind`, `event.version`); the names were the last outpost.~~

**Resolution:** `sed -i '' 's/test_sad_record_/test_sad_event_/g' lib/kels/src/types/sad/event.rs` swept all four test function names in one pass. Post-fix grep confirms the four renamed functions: `test_sad_event_inception_no_content` (line 403), `test_sad_event_chain_increment` (line 420, preserves `chain` as structural per the round 1–8 rubric), `test_sad_event_verify_said` (line 445), `test_sad_event_verify_prefix` (line 464). No callers exist — tests are invoked by `#[test]` discovery, not by name. Post-fix tree-wide grep `sad_record\b` returns zero hits.

---

## Low Priority

### ~~4. CLI `cmd_exchange_publish_key` / `cmd_exchange_rotate_key` / `cmd_exchange_lookup_key` error contexts use `"event prefix"` / `"event chain"` / `"Tip record"`~~ — RESOLVED

**File:** `clients/cli/src/commands/exchange.rs:139, 198, 243, 259`

~~Four `anyhow::Context` / `anyhow!` strings carried pre-round-9 short forms: `:139` `"Failed to submit event chain"` (round 9 #3 analog), `:198, :243` `"Failed to compute event prefix"` (round 9 #4 analog), `:259` `"Tip record has no content"`.~~

**Resolution:**
- `:139` — `"Failed to submit event chain"` → `"Failed to submit SAD events"` (matches round 9 #3's form in `sel.rs:21`).
- `:198`, `:243` — `sed -i '' 's/Failed to compute event prefix/Failed to compute SEL prefix/g'` — both swept (matches round 9 #4's form in `sel.rs:46`).
- `:259` — `"Tip record has no content"` → `"Tip event has no content"`.

Post-fix grep on the file confirms four renamed strings at the originally-flagged line numbers.

### ~~5. Design-doc "tip record" prose — three sites referring to the SEL tip with pre-rename vocabulary~~ — RESOLVED

**File:** `docs/design/sad-events.md:68, :113`; `docs/design/sadstore.md:69`; `docs/design/exchange.md:93`

~~Four design-doc prose sites carried the `"tip record"` short form: `sad-events.md:68` and `sadstore.md:69` (`the tip record's SAID`, verbatim twins), `sad-events.md:113` (`Per-branch state: tip record, ...`), `exchange.md:93` (`The tip record is always the current key.`). For contrast, the KEL-side design docs uniformly use `"tip event"` (`merge.md:21`, `reconciliation.md:83, :85`, `endpoints.md:48`, `gossip.md:47, :252`). The post-rename SEL doc should match.~~

**Resolution:**
- `sad-events.md:68` / `sadstore.md:69`: `the tip record's SAID` → `the tip event's SAID` (matches `endpoints.md:48`'s form verbatim).
- `sad-events.md:113`: `tip record` → `tip event` in the per-branch-state bullet.
- `exchange.md:93`: `The tip record is always the current key.` → `The tip event is always the current key.` Adjacent finding #8 prose on the same paragraph (`exchange.md:91` — `"latest record"` → `"latest event"`, `"Anyone computes the event prefix offline"` → `"Anyone computes the SEL prefix offline"`) was folded in together.

### ~~6. Design doc + `sadstore.md` accessor-list prose reference `current_record()` — will need updating together with finding #2~~ — RESOLVED

**File:** `docs/design/sad-events.md:119`; `docs/design/sadstore.md:92`

~~Both docs spell out the `SadEventVerification` accessor list verbatim starting with `current_record()`. If finding #2 is resolved by renaming the method to `current_event()`, both accessor lists must be updated in the same pass.~~

**Resolution:** Both accessor lists updated to start with `current_event()` in lockstep with the finding #2 method rename. Additionally, `sadstore.md:92`'s trailing sentence `"not the tip record's raw field"` → `"not the tip event's raw field"` per finding #5's rubric. Both docs now reference only the renamed accessor; grep `current_record` across `docs/` returns zero hits outside `docs/claudit/**`.

### ~~7. `lib/ffi/src/sad.rs` Doxygen + error strings use `"event prefix"` short form~~ — RESOLVED

**File:** `lib/ffi/src/sad.rs:1, 23, 271`

~~Three FFI sites carried the `"event prefix"` short form that rounds 8–9 settled as `"SEL prefix"`: `:1` module doc, `:23` return-value doc on `kels_compute_sad_event_prefix`, `:271` error string from `kels_sad_fetch_events`.~~

**Resolution:**
- `:1` — `(event prefix computation, SAD object and event CRUD)` → `(SEL prefix computation, SAD object and event CRUD)`.
- `:23` — `The computed event prefix string` → `The computed SEL prefix string` (matches `:247`'s already-renamed param description).
- `:271` — `"Invalid event prefix"` → `"Invalid SEL prefix"`.

**Preserved:** The C ABI parameter name `event_prefix` at `:260` (exposed by cbindgen in the generated header) was deliberately **not** renamed — the finding's scope explicitly recommended leaving the parameter name alone without user ACK for the ABI churn. The parameter-description comment at `:247` was already `"The SEL prefix"` (fixed in round 8 #2), so the generated C header's identifier-versus-description split is maintained.

### ~~8. `lib/exchange/src/key_publication.rs:13` and `docs/design/exchange.md:91` reference "event prefix" in the discovery narrative~~ — RESOLVED

**File:** `lib/exchange/src/key_publication.rs:13`; `docs/design/exchange.md:91`

~~Two sites described the SEL-prefix discovery flow using the short form `"event prefix"`: `key_publication.rs:13` (same line as finding #1's correctness bug — vocabulary half of the same line) and `exchange.md:91` (`Anyone computes the event prefix offline`).~~

**Resolution:**
- `key_publication.rs:13` — folded into finding #1's rewrite; the new rustdoc reads `"the deterministic SEL prefix"` (not `"event prefix"`).
- `exchange.md:91` — `"Anyone computes the event prefix offline"` → `"Anyone computes the SEL prefix offline"`. Also swept the trailing `"Query any SADStore node for the latest record"` → `"...for the latest event"` per finding #5's KEL-parallel rubric (`docs/gossip.md:252` uses `"latest event"` in the analogous narrative).

Post-fix tree-wide grep `"event prefix"` (excluding `docs/claudit/**`) returns three hits: `docs/design/verification.md:11` (KEL-context, explicitly preserved), `lib/ffi/src/sad.rs:14` (`"SAD event prefix"` fully qualified, preserved), `services/gossip/src/types/sad.rs:21` (not in scope of any round-10 finding — out of scope for this pass).

---

## Positive Observations

- **The identifier-level rename is very nearly complete.** Round 10's only hard-drift identifier findings are the four test function names (finding #3) and the single `current_record()` accessor (finding #2). Every other public type, function, route, CLI subcommand, FFI symbol, migration table name, and Garden build target already reads in the renamed vocabulary. Round 9's positive observation #1 was close to correct — just one method and four test names short.

- **The `"event chain"` / `"event chains"` structural phrasing is principled.** `services/sadstore/src/repository.rs:13` (`/// Result of a \`save_batch\` operation on an event chain.`), `lib/kels/src/types/sad/event.rs:136` (`/// The topic of this event chain`), `lib/exchange/src/key_publication.rs:1` (`referenced by SadEvent chains`), `docs/design/sadstore.md:10` (`Versioned event chains...`) — all describe structural shape (a SEL **is** an event chain), not a typed slot. The round 10 findings on `exchange.rs:139` (`"Failed to submit event chain"`) and `sad-events.md:13` are at sites where the role name "SAD events" is called for (the submit call is literally `submit_sad_events`), not the structural "event chain". Prior rounds' preservation judgment (round 6 #5, round 8 #6) continues to hold.

- **Round 9's resolutions all hold under cold reading.** Fresh greps for `chain_prefix` (zero outside `docs/claudit/**`), `"SAD record {}"` in `verification.rs` (zero), `"chained records"` in `README.md`/`docs/deployment.md` (zero), the `"Chain Prefix:"` CLI label (zero), the `preload_sad_records` function name (zero), the two `sad-record:` cache-key literals (zero) — round 9's 10 findings remain fixed.

- **The `test_*` test function names are the only `sad_record` residue.** A tree-wide `git grep "sad_record\|SadRecord\|sad-record\|SAD record\|SAD records\|SAD Records"` excluding `docs/claudit/**` returns exactly the four hits in finding #3 and nothing else. This means the rename is complete at the **source-level** for the `sad_record` identifier family — only the test-name bucket remains.

- **The rustdoc-example correctness bug (finding #1) is isolated.** The incorrect `compute_sad_event_prefix(kel_prefix, ...)` call form appears in exactly one place: the `EncapsulationKeyPublication` rustdoc at `key_publication.rs:13`. Every live call site in the workspace (`exchange.rs:94-97, 192-198, 239-243`, `lib/ffi/src/sad.rs:53`, the tests) derives `write_policy` correctly before calling. So no runtime code is wrong — only the documentation example. A downstream consumer following the docstring verbatim would fail early at discovery, making the bug self-limiting in practice.

- **`docs/design/sad-events.md` (renamed from `sad-pointers.md`) reads internally consistent with the narrative.** The 205-line doc covers threat model → governance → divergence → repair → verification → handler flow → record kinds cleanly, and the "tip record" drift at `:68, :113` is isolated — all other references to the SEL tip use "tip" as a bare noun or "tip event" implicitly. The repair section (`:71-96`), verification section (`:98-119`), and handler flow (`:121-162`) all read in the post-rename vocabulary.

- **FFI vocabulary is mostly clean; finding #7 is tail drift.** `lib/ffi/src/sad.rs` exports six role-named C symbols (`kels_compute_sad_event_prefix`, `kels_sad_fetch_events`, `kels_sad_post_object`, `kels_sad_submit_events`, `kels_sad_fetch_object`, `kels_sad_fetch_custody`) and the Doxygen param descriptions for the SEL prefix argument read as `"The SEL prefix"` (line 247, fixed in round 8 #2). Only the module-level summary (`:1`), the return-value doc for `kels_compute_sad_event_prefix` (`:23`), and one error string (`:271`) use the pre-rename short form — and even those share the file with six cleanly-renamed doc comments that the prior rounds swept.

- **No invented preservation rationales in this round.** Each finding's scope is bounded by a concrete rubric: finding #1 is a correctness bug (wrong argument, not vocabulary), finding #2 matches round 9 #9's "the type being described is `SadEvent`" test, finding #3 follows round 8's test-name-sweep precedent, finding #4 directly mirrors rounds 9 #3 and #4's resolutions, finding #5 follows the KEL-side "tip event" canonical form, findings #6–#8 are follow-on consequences of #2 and the round 8–9 `"SEL prefix"` canonical. No sites preserved without a named rubric citation.
