# Branch Audit: KELS-133_rename-concepts (Round 1) — 2026-04-21

Branch `KELS-133_rename-concepts` vs `main`: 80 files changed, 2285 insertions / 2206 deletions. Pure rename: `checkpoint_policy` → `governance_policy`, `SadPointer*` → `SadEvent*`, `EventKind` → `KeyEventKind`, `SadChain*` → `Sel*`, `CustodyContext` → `SadCustodyContext`, URL paths `/sad/pointers/*` → `/sad/events/*`, SQL table renames, CLI restructure into `kel/sel/sad/exchange/mail` subgroups. Focus: completeness of the rename (missed identifiers), consistency of the CLI restructure, SQL migration integrity, wire-format consistency.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 1        |
| Low      | 0    | 5        |

---

## Medium Priority

### ~~1. `SubmitPointersResponse` type was missed by the rename~~ — RESOLVED

**File:** `lib/kels/src/types/sad/request.rs:47-52`; usages at `lib/kels/src/lib.rs:109`, `services/sadstore/src/handlers.rs:1280`, `1493`, `1551`

~~The struct `SubmitPointersResponse` — the wire-contract response for submitting SAD events — retained the "Pointers" nomenclature. Its `#[must_use]` attribute also leaks this through compiler warnings (`"SubmitPointersResponse.applied must be checked — records may be rejected"`). The rename regex (`\bSadPointer`) required the `Sad` prefix and so missed this identifier, which has no prefix. The wire contract itself is unaffected (JSON fields are `applied` and `divergedAt`, so no wire change is needed), but the Rust identifier and compiler warning text sit inconsistently next to the sibling `SubmitEventsResponse` (KEL) also exported from `lib.rs`.~~

**Resolution:** Renamed the struct to `SubmitSadEventsResponse` (avoiding the collision with the KEL `SubmitEventsResponse`). Updated the `#[must_use]` message, the `lib.rs` re-export, and all three call sites in `services/sadstore/src/handlers.rs`. No wire-format change.

---

## Low Priority

### ~~2. Doc comments still describe `governance_policy` as "the checkpoint policy"~~ — RESOLVED

**File:** `lib/kels/src/types/sad/event.rs:150-154`, `services/sadstore/migrations/0001_initial.sql:15`

~~After the role/mechanism split, the field name `governance_policy` captures the authority role while "checkpoint" is reserved for the mechanism. But two doc comments still name the field as "the checkpoint policy":~~

- ~~`event.rs:150`: `/// SAID of the checkpoint policy — a higher-threshold policy that bounds ...`~~
- ~~SQL migration line 15: `governance_policy TEXT  -- SAID of checkpoint policy (higher threshold than write_policy)`~~

~~This contradicts the very rename we just did (the entire point was that role-naming reads as intent, mechanism-naming reads as mechanism).~~

**Resolution:** Both comments now read "governance policy" instead of "checkpoint policy". The SAD Rust struct doc and the SQL column comment are now consistent with the role-naming the rename established.

### ~~3. Encapsulation widening: `exchange_write_policy` promoted from private to `pub(crate)` so `mail.rs` can import it~~ — RESOLVED

**File:** `clients/cli/src/commands/exchange.rs:16`, imported by `clients/cli/src/commands/mail.rs:11`

~~To support the CLI restructure (mail commands extracted from exchange.rs), `exchange_write_policy` changed from `fn` (private) to `pub(crate) fn`. `mail.rs` now does `use crate::commands::exchange::{exchange_write_policy, kem_key_path, load_decap_key};` — a cross-module dependency from mail (a task-level subgroup) back to exchange (a protocol-level subgroup). That's an inverse conceptual dependency. Per `feedback_encapsulation.md` (don't over-export; keep internals `pub(crate)`), `pub(crate)` is the correct scope, but the helper would be better located in `helpers.rs` or a shared `exchange_keys` module so mail doesn't reach into exchange.~~

**Resolution:** `exchange_write_policy` moved to `clients/cli/src/helpers.rs:117` where both `exchange.rs` and `mail.rs` now import it via `use crate::helpers::*`. Removes the mail→exchange cross-module dependency.

### ~~4. Error message mixes role field name with mechanism noun~~ — RESOLVED

**File:** `lib/kels/src/types/sad/verification.rs:416-419`

~~The error reads: `"SAD Event Log has no governance_policy — at least one checkpoint is required"`. The first clause uses the role-named field, the second clause uses the mechanism-named noun without saying what sort of thing "a checkpoint" is in this context. A reader has to already know that governance_policy is what a checkpoint evaluates against.~~

**Resolution:** Rewritten to `"SAD Event Log has no governance_policy established — Icp or Est must declare one"`. The inline comment on the preceding invariant check now also reads "at least one branch must have a governance policy established" (previously said "checkpoint policy"). Test assertion at `verification.rs:1322` still matches on `"no governance_policy"`.

### ~~5. Stale prose in `SadAnnouncement` doc comment~~ — RESOLVED

**File:** `services/gossip/src/types/sad.rs:8`, `19`, `23`

~~The module-level comment still says `"chain update announcements"` and the `Event` variant's doc says `"The SAID of the latest chain event"` and `"A SAD Event Log was updated"` — mix of old "chain" language (OK, a SEL is structurally a chain) and new "SAD Event Log" language. Not a bug, just phrasing drift.~~

**Resolution:** Module doc now reads "SEL update announcements", variant doc says "A SAD Event Log was updated" / "The event prefix that was updated" / "The SAID of the latest SAD event". Consistent SEL / SAD Event terminology throughout.

### ~~6. `SadAnnouncement` test has a "Backwards compatibility" comment that no longer reflects a real compat concern~~ — RESOLVED

**File:** `services/gossip/src/types/sad.rs:79-92`

~~The test comment `"Backwards compatibility: messages without repair field default to false"` is framed as a back-compat check but really just verifies `#[serde(default)]` behaviour. Given the spec explicitly forbids backwards-compat aliases, the phrasing is misleading — a future reader might think this protects wire compatibility with an older schema, which is not the case.~~

**Resolution:** Removed entirely as part of the `repair: bool` field removal (see Positive Observations below). The test file now contains only the `Object` and `Event` round-trip checks, no legacy-json block.

---

## Positive Observations

- **SadEventPage wire-format rename produces symmetry with KEL.** The spec explicitly renamed `SadPointer*` types to `SadEvent*` and the corresponding URL paths from `/sad/pointers/*` to `/sad/events/*`, but did not call out the struct field `pointers: Vec<SadEvent>`. Renaming it to `events` (scope addition flagged in the implementation report) gives `GET /sad/events/fetch` a response body matching `GET /kels/kel/fetch` — both now return `{ events: [...], hasMore: ... }`. Clients can now treat the two fetch endpoints uniformly.

- **CLI restructure cleanly separates identity / protocol / task.** `kels kel *` (identity lifecycle), `kels sel *` (SEL protocol), `kels sad *` (SAD object protocol), `kels exchange *` (ML-KEM key protocol), `kels mail *` (messaging task). The rationale for splitting `exchange` and `mail` apart (identity-binding future work) is captured in the plan file, so the decision survives beyond this session.

- **`SadCustodyContext` restructure fixes a pre-existing asymmetry.** Before: `CustodyContext::SadObject` (prefix on variant) and `CustodyContext::Pointer` (no prefix). After: `SadCustodyContext::Object` / `::Event`. The prefix lives on the enum name, variants describe the role within SAD land. Much cleaner.

- **SQL migration edited in place (greenfield).** Matches `AGENTS.md`'s explicit rule: "edit migrations in place, no new migration files." Table, column, and index renames are all uniform; FK references (`sad_event_repair_records.repair_said` → `sad_event_repairs(said)`, `event_said` → `sad_event_archives(said)`) correctly follow the parent table renames.

- **Topic-prefix rename (`kels/sad/v1/pointer/*` → `kels/sad/v1/events/*`) aligns with KEL's existing plural `events/*`.** The old SAD topic prefix used singular `pointer/*` while KEL used plural `events/*`. Now both use plural `events/*` — a small consistency win that the plan specifically called out.

- **Final verification sweep is clean.** All 23 old tokens from the plan's step 11 (`SadPointer`, `sad_pointer`, `SadChain`, `sad_chain`, `checkpoint_policy`, `checkpointPolicy`, `/sad/pointers`, `sad_chain_updates`, `sad_chain_stale`, `kels/sad/v1/pointer`, `evaluates_checkpoint`, `last_checkpoint_version`, `build_checkpoint_policy`, `add_checkpoint_declaration`, `add_checkpoint\b`, `\bCustodyContext\b`, `NotAllowedOnPointer`, `\bEventKind\b`, `SadAnnouncement::Pointer`, `"type":\s*"pointer"`, `cmd_sad_chain`, `cmd_sad_submit`, `cmd_sad_prefix`) returned zero hits outside `docs/claudit/**`.

- **Test assertion update preserves intent.** `verification.rs:1322`'s assertion was forced to change from `contains("no checkpoint")` to `contains("no governance_policy")` because the error text changed. The new assertion still gates the same condition (no branch has a governance_policy established) and is arguably more precise — the field name is unambiguous whereas "no checkpoint" could have matched unrelated mechanism wording.

- **`SadAnnouncement::Event` wire-format simplification.** Beyond the round-1 findings, the `repair: bool` field was removed from the `Event` variant, `chain_prefix` renamed to `prefix`, and the `:repair` Redis pub/sub suffix plus all downstream plumbing eliminated. The `#[serde(default)]` attribute, the legacy-JSON back-compat test case, and the strip-`:repair` suffix logic in `services/gossip/src/sync.rs` are all gone. Net effect: the SAD gossip announcement wire contract shrinks from a 4-field struct with a compat shim to a clean 3-field `{ prefix, said, origin }` — the receiving handler auto-detects repair by inspecting `Rpr` records, so the bit on the announcement was redundant.

- **Field rename aligns the gossip announcement with the rest of the rename.** `SadAnnouncement::Event.chain_prefix` → `prefix` drops the "chain" qualifier that predated the SEL renaming; the field is now just the SEL prefix, matching how the field is named everywhere else in the code (`SadEvent.prefix`, `SadEventRepair.event_prefix`, URL path params).
