# Branch Audit: KELS-133_rename-concepts (Round 4) — 2026-04-22

Branch `KELS-133_rename-concepts` vs `main`: 86 files, 2813 insertions / 2421 deletions. Cold re-read after `/clear` — the prior three rounds ran in the authoring session. Focus: stragglers the authoring-primed passes didn't surface, plus doc accuracy for identifiers that survived the rename but whose surrounding prose did not. Total resolved cumulatively across rounds 1–3: 18.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 2        |
| Low      | 0    | 4        |

Cumulative across rounds 1–4: 24 resolved.

---

## Medium Priority

### ~~1. Stale doc comment on `handle_sel_announcement` describes a `repair` parameter that no longer exists~~ — RESOLVED

**File:** `services/gossip/src/sync.rs:444-448`

~~The function's doc comment reads:~~

```rust
/// Handle a SAD Event Log announcement — fetch the chain if our tip differs.
///
/// When `repair` is true, the origin node repaired a divergent chain. The full
/// chain is fetched (no delta) since repair replaces from the divergence point.
/// The handler auto-detects Rpr records and takes the repair path.
async fn handle_sel_announcement(
    &self,
    chain_prefix: &cesr::Digest256,
    remote_said: &cesr::Digest256,
    origin: &cesr::Digest256,
) {
```

~~There is no `repair` parameter. Round 1's positive observation captured the removal of the `repair: bool` field from `SadAnnouncement::Event` and the companion parameter on the handler. Round 2 finding #4 cleaned up an adjacent stale comment in the same file (`sync.rs:491-493`) but missed this sibling doc block four hundred lines away. The handler body (inside) correctly relies on auto-detection — see the "For repair: fetch full chain — handler auto-detects Rpr records" comment at line 508 — but the outer doc still describes the removed parameter. A maintainer reading "When `repair` is true" will scan the parameter list, not find it, and have to reconcile the comment against the code manually.~~

**Resolution:** Doc rewritten to describe the surviving behavior: "Handle a SAD Event Log announcement — fetch the chain if our tip differs. Delta fetch when the remote effective SAID is a real event; full fetch when it's synthetic (divergent). The receiving SADStore handler auto-detects repair from any `Rpr` records in the submitted batch." Matches the `remote_is_real_event` gate in the body (`sync.rs:521-537`).

### ~~2. `docs/design/sadstore.md` §Verification accessor list is missing three accessors added by the governance-policy work~~ — RESOLVED

**File:** `docs/design/sadstore.md:92`

~~The doc enumerates the `SadEventVerification` token's accessors:~~

> ~~Accessors: `current_record()`, `current_content()`, `prefix()`, `write_policy()`, `topic()`.~~

~~Compared against the struct at `lib/kels/src/types/sad/event.rs:296-358`, the actual accessor surface is: `current_record`, `current_content`, `prefix`, `write_policy`, `topic`, `policy_satisfied`, `last_governance_version`, `establishment_version`. Three accessors — exactly the ones the governance-policy and anchoring-model work added — are missing from the sadstore design doc. The sibling doc (`docs/design/sad-events.md:119`) enumerates the full list; the two docs now contradict each other on what the verification token exposes. Round 3 cleaned up the `?repair=true` / `:repair` suffix references in sadstore.md but didn't re-audit the accessor list against the struct.~~

**Resolution:** Accessor list extended with `policy_satisfied()`, `last_governance_version()`, `establishment_version()`. Added a pointer to `sad-events.md` for the chain-wide vs. branch-scoped semantics of the governance-related accessors. The two design docs now agree on the token's surface.

---

## Low Priority

### ~~3. `SadEventVerification::last_governance_version` doc claims "most recent" but the implementation computes the minimum across records~~ — DEFERRED to #142

**File:** `lib/kels/src/types/sad/event.rs:338-342`; related impl at `lib/kels/src/types/sad/verification.rs:85-87, 311-315`

~~Getter docstring at `event.rs:338`:~~

```rust
/// The version of the most recent evaluated checkpoint, if any.
/// Versions at or before this are sealed by governance_policy.
pub fn last_governance_version(&self) -> Option<u64> { ... }
```

~~But the verifier updates the field via `existing.min(record.version)` (verification.rs:311-315):~~

```rust
if write_policy_satisfied {
    self.last_governance_version = Some(match self.last_governance_version {
        Some(existing) => existing.min(record.version),
        None => record.version,
    });
}
```

~~On a single non-divergent branch with multiple Evl records (e.g., v3 Evl then v5 Evl), this yields `min(3, 5) = 3` — the *earliest* evaluated checkpoint, not the most recent as the docstring promises. The struct-field comment at `verification.rs:85-87` paints over this with "For divergent chains, this is the minimum across branches (weakest seal)", but the `min` in the implementation is applied across *every Evl/Rpr record processed*, not just across tip branches at `finish()` time. For a single-branch chain with two Evl records, the min produces a demonstrably wrong "most recent" value.~~

~~The repository method that returns the same concept from Postgres uses the opposite semantics: `services/sadstore/src/repository.rs:271-289` (`last_governance_version`) does `ORDER BY version DESC LIMIT 1`, i.e., max. So the handler path is:~~

- ~~**Repair path** (`handlers.rs:1302`): reads MAX from DB — "most recent" — used as the repair seal floor~~
- ~~**Normal path** (`handlers.rs:1451`): reads MIN from the verifier token — used as the divergence fork seal floor via `save_batch`~~

~~Two seal floors under the same name, computed with opposite aggregations. No test exercises the single-branch multi-Evl case for the verifier path — `test_last_governance_version_tracked` (verification.rs:1468) has exactly one Evl record, so the min-vs-max difference is invisible to the existing suite. This logic pre-dates the rename branch (identical `existing.min` call on `main` under the old `last_checkpoint_version` name), so it is not a regression — but the rename was an opportunity to notice the docstring-vs-impl contradiction, and the new name `last_governance_version` sits next to a now-mechanism-named repo method with the opposite aggregation, which makes the inconsistency more confusing, not less.~~

**Resolution:** Deferred to #142 (Reconcile `last_governance_version` semantics between verifier and repository). Pre-existing min-vs-max discrepancy; not caused by the rename. Fix requires a design decision on the intended seal-floor semantics and should not be bundled under KELS-133.

### ~~4. Test-script `SAD_KIND` / `DIV_KIND` variables hold a topic string, not a kind~~ — RESOLVED

**File:** `clients/test/scripts/test-sadstore.sh:232, 356`; `clients/test/scripts/load-sad.sh:28`

~~Three shell variables are named `*_KIND` but their values are `kels/v1/test-data`, `kels/v1/test-diverge`, `kels/v1/test-data` — SEL *topic* strings that get passed into `jq` as `topic: $k`. Elsewhere in the same scripts, `SadEventKind` strings (`kels/sad/v1/events/{icp,upd,...}`) are hardcoded inline as `kind: "..."`. The naming mismatch — variables called `KIND` holding topics, variables inline holding actual kinds — was pre-existing but more visible now that the rename made `SadEventKind` a first-class concept with its own enum-parseable namespace.~~

~~Separately, these three topics use `kels/v1/*` rather than the `kels/sad/v1/*` convention that production topics follow (`kels/sad/v1/keys/mlkem` at `lib/exchange`, `kels/sad/v1/identity/chain` at `lib/policy/src/identity_chain.rs:15`, test data at `test-sadstore.sh:192-199` also uses `kels/v1/*`). These are opaque strings from the server's perspective, but the inconsistency makes a grep for "what SEL topics exist" miss them.~~

**Resolution:** Renamed `SAD_KIND` → `SAD_TOPIC` and `DIV_KIND` → `DIV_TOPIC` in `test-sadstore.sh`, updated all `--arg k "$..."` references. Renamed the `KIND` env var and `$KIND` consumers in `load-sad.sh` to `TOPIC`, updated the echo banner and the `export` list at line 201. Also aligned all test topics to the `kels/sad/v1/test-*` convention (`kels/sad/v1/test-mlkem`, `kels/sad/v1/test-other`, `kels/sad/v1/test-data`, `kels/sad/v1/test-diverge`) and retitled the "Different kind -> different chain prefix" test to "Different topic -> different chain prefix". Post-fix grep for `SAD_KIND|DIV_KIND|\bKIND=|kels/v1/` under `clients/test/scripts/` returns zero hits.

### ~~5. `docs/design/exchange.md:91` documents the wrong argument for `compute_sad_event_prefix`~~ — RESOLVED

**File:** `docs/design/exchange.md:91`

~~The rename preserved (and now highlights) a pre-existing documentation error:~~

> ~~**Discovery:** Anyone computes the event prefix offline via `compute_sad_event_prefix(kel_prefix, "kels/sad/v1/keys/mlkem")` ...~~

~~The function's first argument is `write_policy`, not `kel_prefix`. See `lib/kels/src/types/sad/event.rs:162-165`:~~

```rust
pub fn compute_sad_event_prefix(
    write_policy: cesr::Digest256,
    topic: &str,
) -> Result<cesr::Digest256, StorageError>
```

~~And the actual caller in `clients/cli/src/commands/exchange.rs:192-198` does:~~

```rust
let policy = exchange_write_policy(&prefix_digest)?;  // endorse(kel_prefix)
let write_policy = policy.said;
let chain_prefix = kels_core::compute_sad_event_prefix(write_policy, kels_exchange::ENCAP_KEY_KIND)?;
```

~~`write_policy.said` differs from `kel_prefix` (it's the SAID of a single-endorser policy derived from the prefix). A reader who follows the doc will compute a *different* prefix than the CLI does and fail to find the published key. The pre-rename version (`compute_sad_pointer_prefix(kel_prefix, ...)`) had the same defect on main. Rounds 1–3 rewrote docs for terminology but didn't re-check argument names.~~

**Resolution:** Rewrote the Discovery bullet to read: "Anyone computes the event prefix offline: derive `write_policy = endorse(kel_prefix).said`, then call `compute_sad_event_prefix(write_policy, "kels/sad/v1/keys/mlkem")`. Query any SADStore node for the latest record." This matches what `cmd_exchange_publish_key` at `clients/cli/src/commands/exchange.rs:94-97` actually does.

### ~~6. `cmd_exchange_publish_key` sets `governance_policy` equal to `write_policy` — degenerate case that negates the higher-threshold design intent~~ — DEFERRED

**File:** `clients/cli/src/commands/exchange.rs:92-113`; documented in `docs/design/sad-events.md:182-183`

~~The publish-key flow seeds both the Icp's `write_policy` and the Est's `governance_policy` with the same single-endorser policy (`endorse(kel_prefix)`):~~

```rust
let policy = exchange_write_policy(&prefix_digest)?;
let write_policy = policy.said;
let v0 = kels_core::SadEvent::create(..., Some(write_policy), None)?;
let mut v1 = v0.clone();
...
v1.governance_policy = Some(write_policy);  // SAME SAID as write_policy
```

~~The design doc at `docs/design/sad-events.md:7-15` explicitly frames `governance_policy` as "a higher-threshold policy that the adversary is assumed unable to satisfy" — bounding fork length to ≤63 records when the adversary satisfies write_policy but not governance_policy. When `governance_policy = write_policy`, the bound collapses: an adversary who can author any Upd can also author Evl and Rpr, so the 63-record fork bound never binds.~~

~~The chain-shape example in `sad-events.md:182-183` embeds exactly this pattern:~~

```
v0  kind=icp  write_policy=endorse(kel_prefix), topic=kels/sad/v1/keys/mlkem
v1  kind=est  governance_policy=endorse(kel_prefix), content=key_publication_said
```

~~Both the CLI implementation and its documented chain shape make `governance_policy = write_policy`, which is exactly the case the design doc says is inadequate. This predates the rename branch (same code on main, just with the old names), but the rename's explicit role/mechanism split makes the degeneracy more striking — the struct now has clearly-separated role-named fields whose values are set equal.~~

**Resolution:** Deferred. `governance_policy = write_policy` in `cmd_exchange_publish_key` is intentional for the current single-user exchange-key flow. Pattern will be reshaped by the identity-binding rework (tracker #140, specifically #137 exchange-keys sweep) where identity-level governance replaces the degenerate single-endorser policy. Not fixed under KELS-133.

---

## Positive Observations

- **Rounds 1–3 cumulative resolutions all hold.** Fresh greps from a cold session for `SadPointer`, `sad_pointer`, `SadChain`, `sad_chain`, `\bEventKind\b` (outside the identity/server `KeyEventKind::*` match arms), `checkpoint_policy`, `SadGossipMessage`, `SubmitPointers`, `CHECKPOINT_POLICY_SAID`, `chain_cp_said`, `cp_said`, `cp_version`, `:repair`, `\?repair=`, `test_event_kind_`, and `test_sad_gossip_message` all return zero hits outside `docs/claudit/**`. The round-2 and round-3 verification sweeps were thorough — nothing from those rounds regressed, and the straggler set has dropped dramatically.

- **The rename is code-complete in the Rust tree.** `make` builds cleanly; all three public crates (`lib/kels`, `lib/policy`, `lib/exchange`) export the new names; the SQL schema, SADStore handlers, gossip types, FFI, and CLI all use the new identifiers end-to-end. The remaining round-4 stragglers are confined to documentation drift and a parameter doc-comment. No missed identifier causes a compile error or a wire-format inconsistency.

- **Round 3's role/mechanism split holds under fresh reading.** In the cold session, `governance_policy` reads as the authority role, `checkpoint` reads as the evaluation mechanism, and the two never collide in the same slot — e.g., `last_governance_version` is the role-named field, `MAX_NON_CHECKPOINT_RECORDS` is the mechanism-named constant, both accurate and non-overlapping. The error strings at `services/sadstore/src/repository.rs:111-114` (`"sealed by checkpoint at version N"`) correctly keep mechanism-naming where the mechanism-effect is what's being described. Round 3's defense of this split against its own local variables (`gp_version` / `gp_said` renames) reads as correct a week later.

- **`SelVerifier` defense-in-depth gates survive the rename intact.** The three tests at `verification.rs:707-858` (`test_evl_evolution_rejected_does_not_advance_tracked_policy`, `test_evl_rejected_wp_does_not_advance_governance_policy`, `test_est_rejected_wp_does_not_establish_governance_policy`) continue to pin the R5/R6 gates that block unauthorized advances of `tracked_write_policy`, `tracked_governance_policy`, `establishment_version`, and `last_governance_version` when a record soft-fails the wp check. The tests' pre-existing property-naming (`cp_legit`, `cp_attacker` for `governance_policy` attackers) is intentional — mechanism-named *local test variables* are fine where they document the checkpoint-evaluation intent of the attack rather than the role of the data. The rename correctly didn't touch these.

- **`SadEvent::validate_structure` remains the single source of per-kind field invariants.** `lib/kels/src/types/sad/event.rs:201-258` keeps the full matrix of required/forbidden fields per `SadEventKind` variant in one auditable match block, and each branch of `SelVerifier` (verification.rs:257-347) composes cleanly on top without re-deriving the structural rules. A future reader of either file will find the invariants stated exactly once.

- **The SAD gossip wire contract is the cleanest it has been.** `services/gossip/src/types/sad.rs:11-28` now carries three fields per variant (`prefix, said, origin` for `Event`; `said, origin` for `Object`) — no `repair: bool`, no `#[serde(default)]`, no back-compat shim. The minimum-possible contract, which makes the stale doc at `sync.rs:444-448` the only remaining place in the gossip subsystem that mentions a field that doesn't exist.

- **CLI restructure's layered boundaries are observable end-to-end.** From `main.rs` dispatch through `commands::{kel,sel,sad,exchange,mail}` into `kels_core` / `kels_exchange` / `kels_policy`, every file declares at the module level what protocol layer it implements (identity, SEL, SAD object, ML-KEM key, ESSR messaging), and imports match. `helpers::exchange_write_policy` (round 1's relocation) now serves both `exchange.rs` and `mail.rs` symmetrically with no cross-module dependency, as intended.
