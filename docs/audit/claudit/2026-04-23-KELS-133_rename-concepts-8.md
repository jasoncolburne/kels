# Branch Audit: KELS-133_rename-concepts (Round 8) — 2026-04-23

Branch `KELS-133_rename-concepts` vs `main`: 109 files, 3479 insertions / 2514 deletions. No commits since round 7 (`git log 4fb8493..HEAD` empty). Cold re-read after `/clear` focused on surfaces prior rounds explicitly deferred or didn't sweep: the "chain prefix" vocabulary across rustdoc/errors/prose (round 6 #5 and round 7 #3 fixed only typed-field/accessor docstrings, leaving the broader surface), the section-banner comments in the SADStore handler + client, the SQL migration comments, and the docs-vs-code label consistency on the Layer-2 concept. Total resolved cumulatively across rounds 1–7: 39.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 2        |
| Low      | 0    | 4        |

Round 8 surfaced 6 new findings — 2 medium, 4 low — all clustered around the same unresolved pattern: the "SEL prefix" / "SAD Events" terminology that rounds 6-7 settled on for typed slots didn't propagate to the surrounding prose, section banners, SQL comments, error strings, or docs. All resolved. Cumulative across rounds 1–8: 45 resolved.

---

## Medium Priority

### ~~1. Stale "Layer 2: Chain Records" / "Chain Repair History" section banners — three sites where the renamed API section is still labeled with the old concept~~ — RESOLVED

**File:** `services/sadstore/src/handlers.rs:1090`, `services/sadstore/src/handlers.rs:1708`, `lib/kels/src/client/sadstore.rs:194`

~~```rust~~
~~// services/sadstore/src/handlers.rs:1090~~
~~// === Layer 2: Chain Records (Postgres) ===~~
~~```~~
~~```rust~~
~~// services/sadstore/src/handlers.rs:1708~~
~~// === Layer 2: Chain Repair History ===~~
~~```~~
~~```rust~~
~~// lib/kels/src/client/sadstore.rs:194~~
~~// === Layer 2: Chain Records ===~~
~~```~~

~~These are the big visual landmarks that split Layer-1 (SAD object) from Layer-2 (SAD event) logic in each file — the first thing a reader navigating the handler or client module sees when scanning for the submit/fetch/repair paths. They contradict the canonical label the design doc settled on at `docs/design/sadstore.md:129` (`### SAD Events (Layer 2)`) and the route-group comment at `services/sadstore/src/server.rs:38` which reads correctly as `// SAD Event Log records (Layer 2 — Postgres)`.~~

~~Round 7 #5 swept `"chain record(s)"` prose and explicitly verified the post-fix grep returned zero hits, but that sweep matched whole words — the compound phrase `"Chain Records"` in these banners survived because it was embedded in a `=== … ===` decorator that didn't match the `"chain record"` lowercase query. Same for `"Chain Repair History"`.~~

**Resolution:** All three banners fixed per the suggested templates:
- `handlers.rs:1090`: `// === Layer 2: Chain Records (Postgres) ===` → `// === Layer 2: SAD Events (Postgres) ===`
- `handlers.rs:1708`: `// === Layer 2: Chain Repair History ===` → `// === Layer 2: SEL Repair History ===` (mirrors the route-group comment `// SEL repair history` at `server.rs:49`)
- `sadstore.rs:194`: `// === Layer 2: Chain Records ===` → `// === Layer 2: SAD Events ===`

Post-fix grep `Layer 2: Chain|Chain Records|Chain Repair` across the tree (excluding `docs/claudit/**`) returns zero hits. The three section banners now read in the same vocabulary as `server.rs:38` (`// SAD Event Log records (Layer 2 — Postgres)`) and `sadstore.md:129` (`### SAD Events (Layer 2)`).

### ~~2. "chain prefix" in rustdoc and user-facing error/log strings for SEL-scoped operations — the "SEL prefix" vocabulary rounds 6-7 settled on for field/accessor docs didn't propagate to method docs or runtime output~~ — RESOLVED

~~Rounds 6 #5 and 7 #3 established that the SEL's identifier is **"SEL prefix"**, fixing the rustdoc on `SadEventRepair.event_prefix` and `SadEventVerification::prefix()`. Those rounds preserved `"chain prefix"` in a few places where "chain" was defensibly structural (e.g., round 6 #5 left `/// A page of chain repairs.` alone). But the broader surface — rustdoc on methods that take a SEL prefix, error strings a user sees when verification fails, and the CLI success log — is uniformly stale.~~

**File:** `lib/kels/src/client/sadstore.rs:241`, `lib/kels/src/client/sadstore.rs:301`; `services/sadstore/src/repository.rs:35`, `:136`, `:383`, `:403`, `:456`; `services/sadstore/src/handlers.rs:157`, `:175`, `:1158`, `:1287`; `lib/kels/src/types/sad/verification.rs:120`, `:129`; `clients/cli/src/commands/exchange.rs:143`; `lib/ffi/src/sad.rs:247`; `services/gossip/src/bootstrap.rs:232`, `services/gossip/src/sync.rs:1493`, `:1525`, `:1537`

~~The function names use `sel_`, but two `SadStoreClient` rustdocs still described the input as "chain prefix". Five `SadEventRepository` method docs described the prefix as "chain prefix". Four handler sites (rustdoc + 429 response body + inline comments) used "chain prefix". Verifier error format strings emitted `"doesn't match chain prefix/topic {}"` in `KelsError::VerificationFailed` messages. The CLI success log for `exchange publish-key` printed `"Chain prefix: {}"`. The FFI Doxygen param description said "event chain prefix". Four gossip sites (rustdoc + inline comment + runtime `info!` log at `sync.rs:1537`) used "chain prefixes".~~

**Resolution:** Every listed site swept from `"chain prefix"` / `"chain topic"` / `"Chain prefix"` to the role-named `"SEL prefix"` / `"SEL topic"`:

- `lib/kels/src/client/sadstore.rs:241` (`fetch_sel_effective_said` docstring) and `:301` (`fetch_sel_repairs` docstring) → `"SEL prefix"`.
- `services/sadstore/src/repository.rs:35`, `:136` (advisory-lock callers), `:383` (`effective_said`), `:403` (`get_repairs`), `:456` (`list_prefixes`) — all five method docstrings → `"SEL prefix"` / `"SEL prefixes"`.
- `services/sadstore/src/handlers.rs:157` (`check_prefix_rate_limit` rustdoc → `"Per-SEL-prefix"`), `:175` (429 response body → `"Too many records for this SEL prefix"`), `:1158` (inline comment), `:1287` (inline comment).
- `lib/kels/src/types/sad/verification.rs:120` / `:129` — verifier error strings → `"doesn't match SEL prefix {}"` / `"doesn't match SEL topic {}"`.
- `clients/cli/src/commands/exchange.rs:143` — CLI success log → `"Key published! SEL prefix: {}"`.
- `lib/ffi/src/sad.rs:247` — C FFI Doxygen param → `"The SEL prefix"`.
- `services/gossip/src/bootstrap.rs:232` — `preload_sad_records` docstring → `"Lists SEL prefixes from each Ready peer's SADStore"`.
- `services/gossip/src/sync.rs:1493` (rustdoc), `:1525` (inline comment), `:1537` (runtime `info!` log) — all three → `"SEL prefixes"`.

Post-fix grep `chain prefix|Chain prefix|chain topic|Chain topic` across the tree (excluding `docs/claudit/**`) returns only four hits, all in KEL/identity-chain contexts (`lib/policy/src/identity_chain.rs:6`, `:103`; `lib/kels/src/types/federation/voting.rs:116`, `:224`) — deliberately preserved per the finding's scope. `make check` passes cleanly.

---

## Low Priority

### ~~3. SQL migration header comments describe SEL tables as "chains"~~ — RESOLVED

**File:** `services/sadstore/migrations/0001_initial.sql:49`, `:52`

~~```sql~~
~~-- Line 49~~
~~-- Archive tables: copies of events for repaired chains~~

~~-- Line 52~~
~~-- Chain repair tracking: each repair is a first-class entity~~
~~```~~

~~The table names themselves (`sad_event_archives`, `sad_event_repairs`, `sad_event_repair_records`) use the renamed vocabulary; the section-divider comments above them still read "chains" / "Chain repair". Small but noticeable when reading the schema file top to bottom — every other banner (line 4: `-- SAD Event Log events table`; line 20: `-- SAD object index`; line 31: `-- Cached custody SADs ...`) uses the renamed vocabulary, so lines 49 and 52 are the only outliers.~~

**Resolution:**
- Line 49: `-- Archive tables: copies of events for repaired chains` → `-- Archive tables: copies of events displaced by SEL repair`
- Line 52: `-- Chain repair tracking: each repair is a first-class entity` → `-- SEL repair tracking: each repair is a first-class entity`

The migration file's section banners now uniformly use the renamed vocabulary top-to-bottom.

### ~~4. `docs/design/sadstore.md:10` uses "Event Chains" as the Layer-2 label — contradicts "### SAD Events (Layer 2)" header at line 129 of the same doc~~ — RESOLVED

**File:** `docs/design/sadstore.md:10`

~~```markdown~~
~~- **Event Chains** (PostgreSQL) — Versioned chains with deterministic prefix discovery and ...~~
~~```~~

~~This is the very first place in the design doc where the reader sees the Layer-2 concept labeled. By line 129 the doc has switched to `### SAD Events (Layer 2)` (which matches the codebase section banners that finding #1 fixes) and by line 174 the Layer-2 is referenced as "SAD events" / "SEL" interchangeably. Round 7 #4 fixed the module-doc Layer-2 label inside `lib/kels/src/types/sad/event.rs:1-10` to `"SAD events"`, but this same-shape design-doc label was not swept.~~

**Resolution:** Layer-2 bullet rewritten per the suggested form — `- **SAD Event Logs** (PostgreSQL) — Versioned event chains with deterministic prefix discovery and policy-based ownership. Event metadata references content in the SAD store via \`content\`. Authorization is via the anchoring model: ...`. Role-named primary label (`"SAD Event Logs"`), structural-shape descriptor (`"event chains"`), and the following sentence also updated (`"Chain metadata references"` → `"Event metadata references"`). Matches the pattern round 7 #4 settled on for the `event.rs` module doc.

### ~~5. Design doc "chain prefix" prose stragglers~~ — RESOLVED

**File:** `docs/design/sad-events.md:22`, `:127`, `:141`, `:169`; `docs/design/sadstore.md:32`, `:137`, `:215`; `docs/endpoints.md:152`

~~- `sad-events.md:22`: `but this changes the chain prefix` — in the governance-declaration rules.~~
~~- `sad-events.md:127`, `:141`: `Acquire advisory lock on chain prefix` — in the handler-flow step list.~~
~~- `sad-events.md:169`: `Icp`: **required** — seeds the chain prefix (prefix = Blake3 ...)` — in the per-kind matrix.~~
~~- `sadstore.md:32`: `Anyone can compute a chain prefix offline` — in the Deterministic Prefix section.~~
~~- `sadstore.md:137`: `POST /api/v1/sad/events/prefixes | List chain prefixes` — in the API table.~~
~~- `sadstore.md:215`: `compute their key publication chain prefix and look it up on any node` — in the Use Cases section.~~
~~- `endpoints.md:152`: `List chain prefixes with tip SAIDs` — in the endpoints table.~~

~~Prior rounds established "SEL prefix" as the canonical design-doc vocabulary; these seven sites didn't get swept.~~

**Resolution:** `chain prefix` / `chain prefixes` → `SEL prefix` / `SEL prefixes` at all eight listed sites. A confirmation re-read of `docs/endpoints.md` surfaced one additional straggler — `"Per-chain-prefix daily rate limited (default 16/day)"` at the inline notes section — fixed in the same pass (`"Per-SEL-prefix daily rate limited (default 16/day)"`) for sweep completeness, matching the renamed handler doc at `handlers.rs:157`.

### ~~6. Test script "chain prefix" prose — round 7 #5 swept scripts for "chain records" but not "chain prefix"~~ — RESOLVED

**File:** `clients/test/scripts/test-sadstore.sh:197`, `:200`, `:214`, `:252`, `:254`, `:255`, `:388`; `clients/test/scripts/test-sad-consistency.sh:5`, `:7`, `:65`, `:66`, `:80`, `:136`, `:165`, `:166`, `:194`, `:376`; `clients/test/scripts/load-sad.sh:111`, `:116`

~~Representative examples:~~

~~```bash~~
~~# test-sadstore.sh:197~~
~~run_test "Different KEL prefix -> different chain prefix" [ "$PREFIX_A" != "$PREFIX_C" ]~~

~~# test-sad-consistency.sh:5-7~~
~~# For each node with test endpoints, fetches all chain prefixes and SAD object~~
~~# ...~~
~~#   1. All nodes have the same set of chain prefixes~~

~~# load-sad.sh:111-116~~
~~# 3. Compute chain prefix (use kels-cli for correctness)~~
~~# ...~~
~~        echo "ERROR [group $group]: chain prefix computation failed" >&2~~
~~```~~

~~Round 7 #5 did a successful sweep for `"chain records"` across the same scripts. The `"chain prefix"` phrasing is the same class of drift — pre-rename wording that the in-place rename carried over.~~

**Resolution:** `chain prefix(es)` / `Chain prefix(es)` → `SEL prefix(es)` at all listed sites across `test-sadstore.sh`, `test-sad-consistency.sh` (full-file `replace_all` sweep), and `load-sad.sh`. Test run stdout now uses the renamed vocabulary. Section-header comments like `# Scenario 5: Chain Record Submission via CLI` and `run_test "Chain does not exist yet"` at `test-sadstore.sh:226-298` were intentionally left alone — those describe structural nature (a SEL is a chain; asking whether "the chain" exists is a structural question), not a typed slot, which is the same reading round 6 #5 used to preserve `/// A page of chain repairs.`.

---

## Positive Observations

- **Rounds 1–7 cumulative resolutions all hold under cold reading.** Fresh greps for round 1-7 artefacts (`SadPointer`, `sad_pointer`, `SadChain`, `sad_chain`, `checkpoint_policy`, `SadGossipMessage`, `SubmitPointers`, `cp_said`, `cp_version`, `chain_cp_said`, `CHECKPOINT_POLICY_SAID`, `test_event_kind_`, `test_sad_gossip_message`, `(transfer|verify|forward|fetch|submit|get|list)_sad_event\b` singular, `kels/v1/` non-canonical topics, `SignedSadEvent`, `NotAllowedOnPointer`, `CustodyContext::Pointer`, `\ba event\b`, `chain record|Chain record|chain records|Chain records|Chained records`) all return zero hits outside `docs/claudit/**`. The 39 cumulative findings remain fixed; round 8 surfaces 6 new findings all clustered on the `"chain prefix"` / `"Chain Records"` drift the prior rounds explicitly deferred.

- **Section-banner audit is principled.** Finding #1 is 3 sites (two in `handlers.rs`, one in `sadstore.rs`) — the full enumeration from `grep "Layer 2: Chain" | grep -v docs/claudit`. The `services/sadstore/src/server.rs:38` route-group comment reads correctly (`// SAD Event Log records (Layer 2 — Postgres)`) and provides the template for the handler/client fixes. No repository-side banner issues — `services/sadstore/src/repository.rs` has no `Layer 2:` banner and only uses `"chain prefix"` in per-method docstrings (captured in finding #2).

- **`SelVerifier` is structurally complete — verify_record, verify_page, verify_generation, finish.** `lib/kels/src/types/sad/verification.rs:115-450` walks through SAID integrity, prefix/topic consistency, chain linkage, version monotonicity, governance policy lifecycle (declare/evaluate/evolve/bound), soft-fail branch-state gating, and `finish()` enforcement of `governance_policy` establishment. The five R5/R6 defense-in-depth tests at lines 727-939 pin the soft-fail-blocks-advance invariant on every branch-state field. The stragglers in finding #2 are purely in the error format strings (`"chain prefix {}"`, `"chain topic {}"`) — the verification logic itself is role-named throughout.

- **`SadEventRepository` method signatures carry the role name — only the rustdoc is stale.** Every method in `services/sadstore/src/repository.rs` (`save_batch`, `truncate_and_replace`, `effective_said`, `get_repairs`, `get_repair_records`, `list_prefixes`, `last_governance_version`, `exists`) takes typed CESR digests for its prefix parameter. The struct is `SadEventRepository`, the const is `ARCHIVED_RECORDS_TABLE = "sad_event_archives"`, and the result type for `save_batch` is role-named (`SaveBatchResult::Accepted | DivergenceCreated`). Finding #2 is a docstring-only sweep — no call sites break.

- **Route group headers in `server.rs` read clean.** `services/sadstore/src/server.rs:29-62` groups routes with three well-labeled comment banners: `// SAD object store (Layer 1 — MinIO)` (line 33), `// SAD Event Log records (Layer 2 — Postgres)` (line 38), `// SEL repair history` (line 49), `// Listing (authenticated — federation peers only)` (line 58). The label that finding #1 proposes for `handlers.rs:1708` (`// === Layer 2: SEL Repair History ===`) mirrors the server's line-49 label — so the fix has a clear template already in the tree.

- **`docs/design/sad-events.md` is structurally the right shape.** The 205-line doc (`docs/design/sad-events.md`) breaks the SEL specification into Threat Model → Governance Policy Lifecycle → Divergence Model → Repair → Verification → Handler Flow → Record Kinds → Typical Chain Shapes, each section internally coherent. The round 8 findings in this doc (finding #5) are all inside otherwise-clean sections — 4 stragglers across 4 sections, each site is a single prose line.

- **Scripts surface the full load/test/bootstrap flow in one place.** `clients/test/scripts/test-sadstore.sh` (600+ lines) covers every Layer-1 and Layer-2 endpoint plus divergence/repair scenarios end-to-end, and `load-sad.sh` demonstrates the client-side chain-construction recipe. The stragglers in finding #6 are all confined to comment prose and test-name strings; no SQL/shell logic drift.

- **FFI surface uses role names for symbol IDs — only the inline doc is stale.** `lib/ffi/src/sad.rs` exports `kels_compute_sad_event_prefix`, `kels_sad_fetch_events`, `kels_sad_post_object`, `kels_sad_submit_events`, `kels_sad_fetch_object`, `kels_sad_fetch_custody` — all role-named at the C ABI level. The only drift (finding #2 on `lib/ffi/src/sad.rs:247`) is the Doxygen `event_prefix` parameter description — internal to one header-comment block. Downstream Swift consumers rebuilding from cbindgen see the symbol list; no ABI break required for the finding #2 fix.
