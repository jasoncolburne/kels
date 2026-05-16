# Branch Audit: KELS-133_rename-concepts (Round 2) — 2026-04-21

Branch `KELS-133_rename-concepts` vs `main`: 82 files changed, ~2464 insertions / 2353 deletions. Round 1 resolved 7 findings (1 Medium + 5 Low + 1 struck in-place). Round 2 focus: stragglers missed by the Round 1 sweep — wire-contract docs, operator config names, FFI/test identifiers, and stale comments that describe removed logic. Total resolved (cumulative across both rounds): 18.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 5        |
| Low      | 0    | 6        |

---

## Medium Priority

### ~~1. `docs/endpoints.md` documents a non-existent `SignedSadEvent` type and wrong auth mechanism~~ — RESOLVED

**File:** `docs/endpoints.md:145`, `148` (second mention of the type), `158`

~~The submit-events row reads:~~

> ~~`POST | /api/v1/sad/events | **KEL signature** | Submit signed chain event(s) (Vec<SignedSadEvent>)`~~

~~Two defects:~~

1. ~~**Type doesn't exist.** `submit_sad_event` in `services/sadstore/src/handlers.rs:1144` takes `Json<Vec<kels_core::SadEvent>>`. A grep shows `SignedSadEvent` has no definition anywhere in the tree — the only occurrences are in `docs/endpoints.md:145` + `:158` and in historical claudit docs. `SignedSadFetchRequest` exists (for fetch), but there is no signed variant of `SadEvent` — the rename replaced `SignedSadPointer` with the bare `SadEvent` (see round-1 note on `SubmitPointersResponse` rename). The docs row references a type the user will search for and not find.~~

2. ~~**Auth mechanism description is wrong.** "KEL signature" implies a signature in the payload that the handler verifies against a KEL. The handler performs no signature verification on the record — it only verifies SAID integrity (`r.verify_said()`) and then runs `SelVerifier` + `AnchoredPolicyChecker`, which enforces authorization via *KEL anchoring* (endorsers must have anchored the record's SAID in their KEL via ixn). Calling this "KEL signature" misleads operators and auditors about the trust model.~~

~~Line 158 compounds both errors in the response-body description:~~

> ~~`POST sad/events/fetch: Returns SadEventPage { records: Vec<SignedSadEvent>, hasMore }`~~

~~The struct is `SadEventPage { events: Vec<SadEvent>, has_more: bool }` (`lib/kels/src/types/sad/event.rs:362-367`) — the field is `events`, not `records`, and the element type is bare `SadEvent`.~~

**Resolution:** Table row auth changed to **KEL anchoring** with a clarifying phrase ("each record's SAID must be anchored via ixn in its endorsers' KELs per `write_policy`"), and the type changed to `Vec<SadEvent>`. Response-shape note rewritten to `SadEventPage { events: Vec<SadEvent>, hasMore }` with the stale "signatures and establishment serials" clause dropped. Notes entry for `POST sad/events` rewritten to describe the actual verification sequence (SAID integrity + `write_policy` via KEL anchoring, with repair auto-detection from `Rpr` records) — no more phantom "signature against owner's KEL" step. Authentication Methods Summary table at line 174-176 had a matching stale "SAD record signature" row; collapsed into the existing "KEL anchoring" row by adding "SAD Event Log records" to the Where-Used column.

### ~~2. Garden variable name `maxRecordsPerPointerPerDay` drifted out of sync with the env var it feeds~~ — RESOLVED

**File:** `project.garden.yml:126`, `services/sadstore/manifests.yml.tpl:67-68`

~~The rename updated the runtime env var name:~~

```
// services/sadstore/manifests.yml.tpl:67
- name: SADSTORE_MAX_RECORDS_PER_EVENT_LOG_PER_DAY
  value: "${var.sadstore.maxRecordsPerPointerPerDay}"
```

~~The consumer is `kels_core::env_usize("SADSTORE_MAX_RECORDS_PER_EVENT_LOG_PER_DAY", 8)` at `services/sadstore/src/handlers.rs:139`. `docs/design/sadstore.md:195` also documents the env var with the new name. But the Garden variable still says `maxRecordsPerPointerPerDay` — so operators reading `project.garden.yml:126` see a Garden knob named after the old "pointer" concept whose value gets plumbed into an env var named after the new "event log" concept. Not broken, but the config graph is self-contradictory in a way that will bite anyone who grep-traces a config value and doesn't find both names on both sides.~~

**Resolution:** Renamed the Garden variable to `maxRecordsPerEventLogPerDay` in both `project.garden.yml:126` and the `${var.sadstore.maxRecordsPerEventLogPerDay}` reference in `services/sadstore/manifests.yml.tpl:68`. Garden variable name, manifest reference, env var name, and consumer `env_usize` call all carry the same "event log" concept label.

### ~~3. Stale gossip-protocol description in `docs/gossip.md` — wrong enum name, wrong variant, wrong wire format~~ — RESOLVED

**File:** `docs/gossip.md:86`, `108-117`, and `docs/endpoints.md:118`

~~Round 1 captured the `SadAnnouncement` variant rename (`Event` / `prefix`) and the removal of the `:repair` suffix on Redis pub/sub messages. `docs/gossip.md` still has:~~

- ~~Line 86: "Message types (KelAnnouncement, **SadGossipMessage**)" — the type was renamed to `SadAnnouncement` (see `services/gossip/src/types/sad.rs:11`). `SadGossipMessage` does not exist in the tree.~~
- ~~Line 109: "`sel_updates` — chain updates (payload: `{chain_prefix}:{effective_said}` or `{chain_prefix}:{effective_said}:repair`)" — the `:repair` suffix was removed (round 1 positive observation). The publisher at `services/sadstore/src/handlers.rs:1519` emits only `"{}:{}"`; the subscriber at `services/gossip/src/sync.rs:176-186` never strips a suffix.~~
- ~~Lines 113-116: the Rust enum snippet uses the old name and the old variant names~~
- ~~`docs/endpoints.md:118`: "SAD store announcements (**SadGossipMessage** JSON: object or chain updates)" — same stale type name; should be `SadAnnouncement`.~~

**Resolution:** `docs/gossip.md:86` updated to `SadAnnouncement`; the sel_updates payload description dropped the `:repair` alternative and uses `{prefix}:{effective_said}`; the Rust enum snippet now reads `SadAnnouncement { Object { said, origin }, Event { prefix, said, origin } }`. `docs/endpoints.md:118` updated to `SadAnnouncement` with text "object or SEL update". Post-fix grep for `SadGossipMessage` and `sad_chain_updates` returns zero hits outside `docs/claudit/**`.

### ~~4. Stale comment in `sync.rs` describes removed `:repair` suffix logic~~ — RESOLVED

**File:** `services/gossip/src/sync.rs:491-493`

~~The `:repair` suffix and the strip logic were both removed during this rename (round-1 positive observation: "the strip-`:repair` suffix logic in `services/gossip/src/sync.rs` are all gone"). The comment above the surviving feedback-loop code still describes the removed behaviour as a current fact. A future maintainer reading this block will look for strip logic, fail to find it, and waste time reconciling comment vs. code.~~

**Resolution:** Comment rewritten per the suggested form: "The SADStore publishes {prefix}:{effective_said} to sel_updates; repairs are auto-detected downstream from Rpr records, not flagged on the message." Now accurately describes the surviving code.

### ~~5. Help text on `kels-cli sel submit` references a type that doesn't exist~~ — RESOLVED

**File:** `clients/cli/src/main.rs:271`

~~The dispatcher at `clients/cli/src/commands/sel.rs:14` parses the file as `Vec<kels_core::SadEvent>` with the error message "Failed to parse SadEvent JSON". The CLI help (shown by `kels-cli sel submit --help`) is the first thing a new operator reads when constructing a submission payload; pointing them at a type the grep will not find in the code or docs is a friction tax they will pay silently.~~

**Resolution:** Help text changed to "Path to JSON file containing SadEvent(s)". Also updated the enclosing `SelCommands::Submit` command summary from "Submit a signed SAD event to a SEL" to "Submit a SAD event to a SEL" — the "signed" qualifier was wrong for the same reason the type name was wrong (the endpoint authorizes via KEL anchoring, not a record-level signature).

---

## Low Priority

### ~~6. FFI test function names still use "pointer"~~ — RESOLVED

**File:** `lib/ffi/src/sad.rs:377-390`

~~The test functions `test_sad_submit_pointer_null_url` and `test_sad_submit_pointer_invalid_json` both call `kels_sad_submit_event` (the renamed FFI entry point). The function under test is `submit_event`, so the test names now lie about their target. Their sibling tests for the fetch path at lines 392, 400 (`test_sad_fetch_event_*`) already use the new name, so the submit-pair is an outlier.~~

**Resolution:** Renamed to `test_sad_submit_event_null_url` and `test_sad_submit_event_invalid_json`. FFI test names are now uniformly `test_sad_{submit,fetch}_event_*`.

### ~~7. Stale FFI doc comment references "pointer chain lookups"~~ — RESOLVED

**File:** `lib/ffi/src/exchange.rs:478`

~~The function returns the string `kels/sad/v1/keys/mlkem` — a SAD Event Log topic string. After the rename, the thing it keys into is a SEL, not a "pointer chain."~~

**Resolution:** Comment now reads "Return the ENCAP_KEY_KIND constant for SADStore SEL lookups."

### ~~8. Test-script variable `CHECKPOINT_POLICY_SAID` mixes role-naming with mechanism-naming~~ — RESOLVED

**File:** `clients/test/scripts/test-sadstore.sh:272-275`

~~The whole point of the role/mechanism split in this branch is to name authority roles as "governance" and reserve "checkpoint" for the evaluation mechanism. The variable holds the SAID of a *governance policy* (it's the return value of `build_governance_policy`), so naming it `CHECKPOINT_POLICY_SAID` puts the wrong label on the slot. The JSON key it feeds — `governancePolicy` — already carries the role name correctly; only the shell variable is wrong.~~

**Resolution:** Renamed `CHECKPOINT_POLICY_SAID` → `GOVERNANCE_POLICY_SAID` and the `--arg cp` / `$cp` pair → `--arg gp` / `$gp` at the v1-submission site. Found and fixed a matching `DIV_CP_SAID` at `test-sadstore.sh:375-380` (same script, divergence-testing subroutine) — renamed to `DIV_GP_SAID` and its `$cp` consumer to `$gp`. Post-fix grep for `CHECKPOINT_POLICY_SAID|CP_SAID|DIV_CP_SAID` across the tree returns zero hits.

### ~~9. Stale TODO comment says "checkpoint policies"~~ — RESOLVED

**File:** `clients/test/scripts/lib/test-common.sh:106`

~~The TODO comment immediately above the renamed `build_governance_policy` function refers to its output as "checkpoint policies". The usage-example variable in the comment above also still uses `CP_SAID`. Both are inside the same 5-line block that was updated to name the function `build_governance_policy`.~~

**Resolution:** TODO updated to "Production governance policies should use higher thresholds than write_policy...". Usage example updated to `GP_SAID=$(build_governance_policy ...)`. Also renamed the function's internal `cp_json` / `cp_said` locals to `gp_json` / `gp_said` so the whole function is internally consistent with the role name.

### ~~10. Grammar nit in endpoints table: "Check if a event exists"~~ — RESOLVED

**File:** `docs/endpoints.md:147`

~~"a event" → "an event". Single-character fix.~~

**Resolution:** Row now reads "Check if an event exists".

### ~~11. Public enum export widens API surface beyond what callers need~~ — RESOLVED (kept public by design)

**File:** `lib/kels/src/lib.rs:107`

~~`SelVerifier` is re-exported at the crate root alongside `SadEvent`, `SadEventKind`, `SadEventPage`, etc. Per `feedback_encapsulation.md` (don't over-export, keep internals `pub(crate)`), I want to flag this as worth a quick check: of the crates outside `lib/kels`, which actually construct a `SelVerifier` directly vs. which just receive a `SadEventVerification` token back?~~

**Resolution:** Keeping `SelVerifier` public, for symmetry with `KelVerifier`. Reasoning:

- `KelVerifier::new` is called directly from services/registry, services/identity, services/gossip, services/sadstore, services/mail, lib/policy, lib/ffi, clients/cli (9 crates outside `lib/kels`). It's a first-class public API.
- `SelVerifier::new` is called directly from services/sadstore (production verifier driver, 2 call sites) and lib/policy (identity_chain tests, 5 call sites). That's two external crates — same structural pattern as `KelVerifier`, just fewer callers today.
- The two verifier types play parallel roles (verify a chain → return a verification token). Demoting one to `pub(crate)` while keeping the other `pub` would break the symmetry that makes the API predictable.

The audit finding explicitly allowed "no action required if public is the intent" — public is the intent, and the symmetry with `KelVerifier` is the deliberate call. No code change.

---

## Positive Observations

- **Round-1 findings all resolved cleanly, no regressions.** Seven findings from round 1 were struck through in-place with resolution notes. Grep for the original round-1 artefacts (`SubmitPointersResponse`, "checkpoint policy" doc prose, `exchange_write_policy` in `exchange.rs`, `"no checkpoint"` error string, `"chain update announcements"` doc, back-compat test) returns zero hits outside `docs/claudit/**`. Fix quality is high.

- **Rename is code-complete across the Rust tree.** `git grep -Ei 'sad_chain|SadChain|sad_pointer|SadPointer'` is empty, `EventKind` → `KeyEventKind` is uniform, and SQL tables + FKs + indexes all align. The remaining stragglers are concentrated in three categories — wire-contract docs, operator config, and FFI/test identifier names — none of which break compilation, and all of which the Rust type system cannot enforce consistency on.

- **SQL schema is minimal and uniform.** `services/sadstore/migrations/0001_initial.sql` uses `sad_events` / `sad_event_archives` / `sad_event_repairs` / `sad_event_repair_records` with FK references that follow table renames (`sad_event_repair_records.repair_said → sad_event_repairs(said)`, `event_said → sad_event_archives(said)`). Greenfield edit-in-place policy preserved.

- **Actual gossip wire type is clean.** `services/gossip/src/types/sad.rs:11-28` is three fields per variant (`prefix, said, origin` for `Event`) with no serde defaults, no legacy compat shims, no `:repair` field. Matches the round-1 positive observation about shrinking the wire contract. The stale description in `docs/gossip.md` (finding #3) is purely a doc-drift issue — the code itself is the clean version.

- **CLI restructure is consistent end-to-end.** `main.rs` subcommand enums (`KelCommands`, `SelCommands`, `SadCommands`, `ExchangeCommands`, `MailCommands`) route one-to-one into `commands::{kel,sel,sad,exchange,mail}::cmd_*` functions. The identity / protocol / task split flagged in round 1 is now visible in the file layout: `kel.rs` (identity), `sel.rs` (SEL protocol), `sad.rs` (SAD object protocol), `exchange.rs` (ML-KEM protocol), `mail.rs` (ESSR messaging task). `exchange_write_policy` correctly moved to `helpers.rs` per round 1.

- **`SadEventKind` / `KeyEventKind` have matching API shape.** Both enums expose `as_str`, `short_name`, `from_short_name` with the same signature patterns. This is a small but real API-symmetry win — future code that wants to handle "any KELS event-style enum" generically has a consistent interface to reach for.

- **Doc comments on `SadEventVerification` preserve the precise "chain-wide vs branch-scoped" semantics.** `lib/kels/src/types/sad/event.rs:343-357` (establishment_version) and `:319-323` (write_policy) both call out the divergent-chain semantics explicitly, including the "gate on `policy_satisfied()` first" caller requirement. This is exactly the kind of non-obvious invariant that deserves a doc comment and would be painful to rediscover.
