# Branch Audit: KELS-126_sad-event-builder (Round 10) — 2026-04-25

Tenth-pass audit of the SadEventBuilder branch after `/clear`. Read every changed source file plus the prior nine round documents to avoid re-finding resolved issues. Cumulative across prior rounds: 60 resolved (10 R1 + 7 R2 + 4 R3 + 4 R4 + 4 R5 + 5 R6 + M1-followup + 4 R7 + 4 R7 final-resolutions + 4 R8 + 3 R9 + 3 R10), 0 open.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 1        |
| Medium   | 0    | 1        |
| Low      | 0    | 1        |

---

## High Priority

### ~~1. `SadEventBuilder::repair` calls `SelVerifier::verify_page` on a fetched tail that doesn't start at v0 — chains longer than `MINIMUM_PAGE_SIZE` cannot be repaired~~ — RESOLVED

**File:** `lib/kels/src/sad_builder.rs:594-606`, `lib/kels/src/types/sad/verification.rs:167-215`

`repair` step 4-5 fetches the chain tail (capped at `MINIMUM_PAGE_SIZE = 64` server-side at `services/sadstore/src/handlers.rs:1632-1633`) and runs a fresh `SelVerifier` over it:

```rust
let fetched_tail = sad_source.fetch_tail(&prefix, crate::MINIMUM_PAGE_SIZE).await?;
// ...
let mut fetched_verifier = SelVerifier::new(Some(&prefix), Arc::clone(checker));
fetched_verifier.verify_page(&fetched_tail).await?;
let fetched_verification = fetched_verifier.finish().await?;
```

For chains with more than 64 total events, `fetched_tail` does not include v0 — it starts at some `v_K > 0`. The verifier's `flush_generation` (`verification.rs:167`) treats the first generation it sees as inception:

```rust
if self.branches.is_empty() {
    if events.len() != 1 { return Err... }
    let event = &events[0];
    event.verify_prefix()?;        // <-- v0-only check
    // seeds branch state from event.write_policy.expect("Icp event must have write_policy ...")
}
```

`event.verify_prefix()` (the derived implementation at `verifiable-storage-rs/lib/verifiable-storage-derive/src/lib.rs:319-328`) blanks `said` and `prefix` and recomputes Blake3 over the full structurally-blanked content. For a non-Icp event the structurally-blanked form differs from v0's (different `version`, `kind`, presence of `previous`/`content`), so the recomputed prefix won't match the chain's actual prefix. `verify_prefix` returns `InvalidSaid("Prefix verification failed: expected ..., got ...")`.

Even if `verify_prefix` were skipped, the branch-state seeding `event.write_policy.expect(...)` would be wrong: only `Icp` carries `write_policy`. A non-Icp first event has `write_policy = None`, so the `expect` fires and the verifier panics (or, post-fix, errors with the message). And `establishment_version = Some(0)` would be wrong for any chain whose Icp didn't declare governance.

**Concrete failure.** Take a chain that's been running long enough to cycle past one Evl: v0 (Icp), v1 (Est), v2..v62 (Upd), v63 (Evl), v64..v100 (Upd). Total 101 events. `fetch_tail(limit=64)` returns events at versions 37..100. The first event in the slice is v37 (an Upd). `verify_page` buffers v37 in generation 37, then on v38's arrival flushes generation 37: `branches.is_empty()` is true, enters inception path, `verify_prefix(v37)` fails. `repair` returns `InvalidSaid` — the user sees a confusing prefix error and cannot proceed.

This bug is not exercised by current tests because every existing test fixture builds short chains:
- `lib/kels/src/sad_builder.rs::build_adversary_extension_fixture` constructs at most 6 events
- `services/sadstore/tests/sad_builder_tests.rs::flush_repair_heals_divergent_chain` runs at 4 events
- `services/sadstore/tests/sad_builder_tests.rs::flush_repair_heals_adversarially_extended_chain` runs at 5 events
- `clients/test/scripts/test-sadstore.sh` Scenarios 7-9 don't reach 64 events

In all of these the tail starts at v0 and the verifier's inception path receives the actual Icp event. The bug surfaces only after a chain has cycled past `MINIMUM_PAGE_SIZE` events — which is the steady state for any long-lived SEL.

**Why this is high.** Repair is the recovery path. A user with a 100-event chain who hits adversarial extension or server-side divergence runs `repair` → gets a confusing `InvalidSaid` error → has no recourse via the documented API. The chain effectively becomes unrecoverable. The exchange-keys flow (`clients/cli/src/commands/exchange.rs`) drives one Upd per rotation, so any operator who has rotated keys ~64 times has a chain that can't be repaired. The threshold isn't hypothetical — `MAX_NON_EVALUATION_EVENTS = MINIMUM_PAGE_SIZE - 1 = 63`, so any chain that has cycled even one governance evaluation has 64+ events.

Note: `with_prefix` (`sad_builder.rs:179-208`) is unaffected because `sel_completed_verification` (`sync.rs:124-170`) walks pages from `offset = 0`, always starting at v0. The `flush()` `was_repair` path also re-hydrates via `sel_completed_verification` from offset 0 (`sad_builder.rs:778-786`), so the post-repair rehydrate is fine. Only the in-flight `repair` step's tail verification is broken.

**Suggested fix.** The repair flow needs per-event integrity verification on the fetched tail without requiring v0 to be present. Three options:

- **(a) Drop the verify_page over the fetched tail; do per-event verify_said + prefix check inline.** Move the M1 sub-finding's per-event check (`verify_said + prefix`, called out in the round-9 resolution doc but not implemented) directly into `walk_back_to_first_owner` immediately after the tail fetch:

  ```rust
  for event in &fetched_tail {
      event.verify_said()?;
      if event.prefix != prefix {
          return Err(KelsError::VerificationFailed(format!(
              "fetched tail event {} prefix {} doesn't match SEL prefix {}",
              event.said, event.prefix, prefix
          )));
      }
  }
  ```

  Drops the chain-level policy verification on the fetched tail. This is acceptable because (1) the per-event SAID + prefix check still catches content forgery (M1's actual concern), (2) the chain-linkage walk via `previous` still works for the bounded `walk_back_to_first_owner` traversal, (3) the server's `is_repair` path runs `verify_existing_chain` over the post-truncation chain anyway — owner is repeating the policy verification the server will redo. The round-9 step (f) "gate on server view's policy_satisfied" was a defense-in-depth addition; without it, the worst case is owner submits a Rpr against a chain whose history fails policy → server rejects with 403/409. No security loss.

- **(b) Fetch the full chain via `verify_sad_events` instead of just the tail.** Restores the round-9 step (f) gate but pays the network cost of pulling the entire chain on every repair. For long-lived chains this is wasteful; the round-9 design specifically chose `fetch_tail` to avoid exactly this.

- **(c) Use `SelVerifier::resume` from owner's local `sad_verification` token, then verify the fetched tail's events that extend past owner's tip.** Restores chain-level verification without the round-trip cost, but only works when the fetched tail's first event is exactly `owner_tip + 1` — which requires careful coordination of `fetch_tail`'s offset (currently it's "last 64," not "everything past owner's tip"). Server would need a `since`-based variant of `fetch_tail`. Larger surface change.

**(a)** is the cleanest. The round-9 design intent ("verify before deciding") is preserved structurally because the per-event SAID check catches the only forgery class M1 was concerned about; the chain-level policy check on server data was always somewhat redundant with the server's own pre-commit verification.

**Regression test.** Build a chain with ≥ 65 events via repeated `update`/`evaluate`, then trigger an adversarial extension and call `repair`. Pre-fix, the test fails with a `verify_prefix` error. Post-fix, the test stages an Rpr at the boundary and `flush()` succeeds.

The round-9 doc's "M1 verify_said + prefix check (preserved sub-finding)" section explicitly named this as a separate per-event check that should live in `walk_back_to_first_owner`. The implementation instead bundled it into `SelVerifier::verify_page`, which doesn't compose with non-v0 starts. Picking that sub-finding back up as a standalone check is option (a) verbatim.

**Resolution (round-10 implementation):** Took option (b) — full chain re-verification at repair time — rather than option (a) (per-event integrity check + drop chain-level verify) because (b) preserves the round-9 design intent ("verify before deciding" applied symmetrically to both data sources) without the cost concern that originally pushed toward `fetch_tail`. Cost is bounded: `verify_sad_events` paginates from v0 forward, but the chain length bound is governance-enforced (≤ governance windows × MAX_NON_EVALUATION_EVENTS), and repair is rare. `repair` (`lib/kels/src/sad_builder.rs:516-720`) now calls `client.verify_sad_events(prefix, checker)` directly — the verifier walks pages from offset 0, so it always sees the inception event, and chain length stops being a hidden cliff. Boundary derives from the verified server view: `server_verification.diverged_at_version()` for A3 (boundary = `d - 1`); owner-tip vs server-tip comparison for linear extension (boundary = owner_tip.version) or `NothingToRepair`. Boundary event is fetched from owner's local store via `sad_store.load_sel_events(prefix, 1, boundary_version)` — owner authored every event from v0 through their tip, so the offset always lands on an owner-authored event. Mirrors KEL's `merge_events` "DB cannot be trusted" pattern. The round-9 `walk_back_to_first_owner` helper is gone (`HashMap` import + `walk_back_to_first_owner` fn removed from `sad_builder.rs`); no callers remained after the rewrite. Unit tests `local_store_offset_returns_boundary_event` and `local_store_offset_unchanged_by_adversary_extension_length` pin the offset-fetch mechanism (replacing the old walk-back tests). Full-stack regression test `flush_repair_heals_long_chain_post_fetch_tail_threshold` (`services/sadstore/tests/sad_builder_tests.rs`) builds a 65-event chain (v0 Icp + v1 Est + v2..v62 Upd + v63 Evl + v64 Upd), triggers an adversarial extension, and asserts `repair` stages an Rpr at v65 with `previous = v64.said`. Pre-fix this fails with `InvalidSaid` at the verifier's inception path; post-fix it succeeds. Test runs in ~185s against testcontainers (slow because of 65 KEL anchors, one per SAD event), well within reasonable bounds for a single regression test.

---

## Medium Priority

### ~~2. `FileSadStore::store_sel_event` does a non-atomic read-modify-write on the per-prefix index file — concurrent writers can lose entries~~ — RESOLVED

**File:** `lib/kels/src/store/sad.rs:225-262`

The file-based store maintains a per-prefix sidecar index (`sel-index/{prefix}.json`) that drives `load_sel_events`. `store_sel_event` reads the index, mutates in memory, then writes it back:

```rust
spawn_blocking(move || {
    let mut entries: Vec<FileSelIndexEntry> = match std::fs::read_to_string(&index_path) {
        Ok(data) => serde_json::from_str(&data)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(...),
    };
    // mutate entries
    // ...
    std::fs::write(&index_path, serialized)
})
```

There is no file lock, no rename-then-replace via temp file, and no fsync. Two concurrent writers on the same prefix can collide:

1. Process A reads index (3 entries).
2. Process B reads index (3 entries).
3. Process A appends entry α, writes 4 entries.
4. Process B appends entry β, writes 4 entries — overwrites A's append.

Result: entry α's SAID-keyed JSON file is on disk (`sad_dir/{α.said}.json` was written by `store_sel_event`'s line 228 `self.store(&event.said, &value).await?` BEFORE the index update), but the index doesn't reference it. Subsequent `with_prefix` returns a chain missing α. Owner-local `SelVerification` covers fewer events than owner actually authored. The prefix-mismatch guard (`requested_prefix`) doesn't fire because the prefix is correct.

Power-failure mid-write produces a similar shape: `std::fs::write` is not atomic on most filesystems — a torn write leaves a corrupt index file. `serde_json::from_str` on the next read returns an error, and `load_sel_events` propagates it as `StorageError`, blocking owner from proceeding even though their data is intact in `sad_dir/*.json`.

**Reachability.** Single-actor CLI usage (one builder per chain, one rotate-key at a time) is unlikely to hit this. But:
- Two terminal sessions running `kels exchange rotate-key` concurrently against the same KEL prefix → two writers on the same SEL prefix index.
- A scheduled rotation cron + a manual rotate firing simultaneously.
- A test harness running multiple flushes in parallel against a shared `FileSadStore` (not `InMemorySadStore`).

The `InMemorySadStore` doesn't have this problem because the `RwLock<HashMap<...>>` serializes the read-modify-write under one critical section (`sad.rs:373-400`).

**Suggested fix.** Either (a) hold a file lock around the read-modify-write (e.g., `fs2::FileExt::lock_exclusive`), or (b) write to a temp file in the same directory and `std::fs::rename` (atomic on POSIX), with an outer file lock to serialize multiple concurrent writers, or (c) move the index to a real database (sqlite). Option (b) with a per-prefix advisory lock file is the standard pattern. Pair the rename with `File::sync_all` on the temp file before rename to survive power loss.

Worth a regression test that spawns two tokio tasks both calling `store_sel_event` 100 times concurrently on the same prefix and asserts the index has all 200 entries afterward. Pre-fix flaky/failing; post-fix deterministic.

**Resolution (round-10 implementation):** Took the in-process variant of (b) — single `tokio::sync::Mutex` per `FileSadStore` instance to serialize the read-modify-write cycle, plus temp-file + `rename` for on-disk atomicity. `FileSadStore` (`lib/kels/src/store/sad.rs:107-153`) gains an `index_lock: tokio::sync::Mutex<()>` field initialized in `new`. `store_sel_event` (`:225-262`) acquires the lock before `spawn_blocking`, holds it across the file I/O, releases on return. The blocking section writes to `{prefix}.json.tmp`, calls `sync_all` on the temp file, then `rename`s — POSIX rename is atomic on the same filesystem, so a torn write or crash leaves either the old or new index file intact. Cross-process synchronization is documented as out of scope (single `FileSadStore` per process is the supported topology); two CLI processes updating the same chain would still race at the OS level, but this is acceptable for the dev/test tier. Concurrency regression test `store_sel_event_concurrent_writers_preserve_all_entries` (`lib/kels/src/store/sad.rs:735-790`) spawns 4 concurrent tasks each writing 50 events on the same prefix (200 total), asserts the post-write index has all 201 entries (200 staged + the v0 seed). Pre-fix this is flaky/failing under the lost-update race; post-fix it's deterministic. No new crate dep — `tokio::sync::Mutex` is already in the closure surface.

---

## Low Priority

### ~~3. `with_prefix` swallows `KelsError::NotFound` from local-store hydration — partial corruption (index entry without payload) silently reports "fresh chain"~~ — RESOLVED

**File:** `lib/kels/src/sad_builder.rs:198-205`, `lib/kels/src/store/sad.rs:291-298` (file backend), `lib/kels/src/store/sad.rs:425-431` (in-memory backend)

`with_prefix` treats any `NotFound` from `sel_completed_verification` as "chain not yet locally inducted":

```rust
match crate::sel_completed_verification(...).await {
    Ok(v) => builder.sad_verification = Some(v),
    Err(KelsError::NotFound(_)) => {}    // silently absorbed
    Err(e) => return Err(e),
}
```

But `load_sel_events` raises `NotFound` for two structurally distinct conditions:

1. **Empty chain.** Index file (`sel-index/{prefix}.json` for file, `sel_index` HashMap for in-memory) doesn't exist or has no entries for this prefix. `sel_completed_verification` sees `saw_any = false` and returns `KelsError::NotFound(prefix.to_string())`. This is the case `with_prefix` intends to handle.

2. **Partial corruption.** Index entry exists but the underlying SAD payload is missing — `chunks.get(&entry.said)` returns `None` for in-memory (`sad.rs:428-429`), or `self.load(&entry.said)` returns `None` for file (`sad.rs:293-295`). Both raise `KelsError::NotFound(entry.said.to_string())`. This indicates the local store is broken (manual filesystem manipulation, partial restore, in-flight crash mid-write between the SAID-keyed store and the index update) — but it's reported with the SAID's qb64 rather than the prefix's, and `with_prefix` happily swallows it.

The user's `with_prefix` call returns Ok with `sad_verification = None` and `requested_prefix = Some(...)`. A subsequent `incept_deterministic` would be rejected (the prefix-mismatch guard fires only when the new chain's prefix differs from the requested prefix — but here the prefixes happen to match because the broken chain IS at this prefix). So they'd hit `require_fresh_builder` failure on `incept_deterministic` once they staged events... actually no, `require_fresh_builder` checks `pending_events.is_empty() && sad_verification.is_some()` — both empty, so a fresh incept proceeds. Owner re-incepts on top of a chain that locally has v0..v_K already; the new v0 SAID conflicts with the existing one in `sad_store.store(&v0.said)` (idempotent overwrite, fine), and on flush the server rejects because v0 already exists. User sees a confusing server-side conflict rather than a clean local-store-corruption message.

**Suggested fix.** Distinguish the two cases. Easiest: introduce a separate error variant (e.g., `KelsError::LocalStoreCorrupt`) and have `load_sel_events` raise it when an index entry has no payload. `with_prefix` then only swallows the "no events" variant and propagates the corruption variant. Alternative: have `sel_completed_verification` only swallow `NotFound` whose body matches the prefix string (the `saw_any = false` case explicitly produces `NotFound(prefix.to_string())`), and propagate any other NotFound. The latter is a one-line check in `with_prefix`:

```rust
Err(KelsError::NotFound(s)) if s == sel_prefix.to_string() => {}
Err(e) => return Err(e),
```

Slightly fragile (string equality). The variant approach is cleaner.

Low priority because the corruption path requires either filesystem-level interference or a crash mid-write between the SAID write and the index update; the typical user never hits it. But when it does fire, the diagnostic is misleading.

**Resolution (round-10 implementation):** Took the variant approach. New `KelsError::SadStorePayloadMissing { prefix: String, said: String }` variant (`lib/kels/src/error.rs:171-180`) — fields are `String` (qb64 encoding) rather than `cesr::Digest256` to keep `KelsError` small enough to pass `clippy::result_large_err`; embedding two Digest256s would balloon every `Result<_, KelsError>` returned by the crate. `SadStore::load_sel_events` raises this variant when an index entry exists but the keyed blob is absent — `FileSadStore` (`lib/kels/src/store/sad.rs:323-345`) and `InMemorySadStore` (`:460-485`) both updated to use `ok_or_else(|| KelsError::SadStorePayloadMissing { ... })` instead of the old `NotFound`. The variant doesn't match the `Err(KelsError::NotFound(_)) => {}` arm in `with_prefix`, so it propagates by structural exhaustion — no string-equality check needed. The empty-chain case (genuine "no events for this prefix") still raises `NotFound(prefix.to_string())` from `sel_completed_verification` and is correctly absorbed. Regression tests: `load_sel_events_raises_payload_missing_on_partial_corruption` (file backend) and `in_memory_load_sel_events_raises_payload_missing_on_partial_corruption` (`lib/kels/src/store/sad.rs:776-820`) — both seed a chain, surgically remove the SAID-keyed payload, and assert the variant fires with the correct prefix and SAID. Pre-fix `NotFound` was returned and silently absorbed by `with_prefix`; post-fix the corruption diagnostic surfaces correctly.

---

## Positive Observations

- **The `SadEventKind::sort_priority` rollout is consistent across every surface that orders events.** The new method (`event.rs:88-112`) is wired into the `FileSadStore` index entries (`store/sad.rs:251-254`), the `InMemorySadStore` index (`store/sad.rs:393-398`), the server repository's `get_stored_in` / `get_stored_tail` / `truncate_and_replace` (`repository.rs:189-193, 326-329, 419-423`), the `since`-cursor strict-greater filter in `get_stored_in` (`repository.rs:443-452`), the verifier's tie-break (`event.rs:484-489`), and the verifier docstring's "expected event ordering" contract (`verification.rs:60-67`). One coherent canonical-ordering invariant across persistence, transport, and verification — a future kind insertion only has to update `sort_priority` and `sort_priority_mapping` and the rest follows.

- **The owner-local `with_prefix` walk + on-demand server consultation in `repair` is the right architectural split.** `with_prefix` is fast and offline; `repair` is the explicit recovery action that pays the cost of consulting the server. Mirrors KEL's `KeyEventBuilder::with_dependencies` (offline) vs. `recover()`/`contest()` (server-consulting). This shape composes cleanly with the round-7 dedup-rate-limit gate (server-side budget enforcement) — a mistakenly-fired repair pays one tail-fetch + one effective-said-fetch, not a full chain re-verification, so a user experimenting with the API doesn't accidentally trip rate limits.

- **The `was_repair` rehydrate via `sel_completed_verification` over the local store eliminates the round-9 doc's "one extra GET" cost.** `sad_builder.rs:756-787` switches the post-flush rehydrate to the local prefix index — owner's pre-repair events plus the freshly-stored Rpr already in the index — so the post-repair token is reconstructed from disk with zero network round-trips. The non-repair branch retains the incremental-absorb fast path. Symmetric, accurate, and the comment reflects the actual cost rather than the original misleading "one GET" framing.

- **The error message for `walk_back_to_first_owner`'s "previous not in store and not in chain map" condition correctly attributes the root cause.** `sad_builder.rs:114-120` says "local cache may be inconsistent with the verified server view" — which is exactly the right diagnostic for the user. A common error mode here would be "prefix index out of sync with payloads"; the message points at that, rather than blaming the server. Mirrors the round-3 docstring discipline of attributing failures to their actual data source.

- **`SelVerifier::resume` divergent-chain rehydration test pair is exhaustive.** `verification.rs:1799-1907` covers both the no-extension round trip (`resume_rehydrates_divergent_token`) and the per-branch-state-survives-and-extends case (`resume_then_extend_preserves_other_branch`). The latter pins the per-branch state via SAID-set assertions on the post-extend `branches()` slice, catching any future regression where resume collapses to a single tip on extension. KEL parity is exercised structurally.

- **The `RepairTestSadSource::fetch_page` exclusive-`since` test is a load-bearing pin.** `sad_builder.rs:1349-1400` exists specifically because the production server's pagination is exclusive (`repository.rs:443-452` strictly-greater on the canonical tuple) and the unit test mock used to be inclusive — an undetected divergence between mock and real behavior would silently mask page-boundary bugs in unit tests. Pinning the contract here keeps mock and real in sync going forward.

---

## Resolutions

### Case taxonomy (mirrors KEL's `merge_events` routing)

When owner submits a non-Rpr event to a SEL:

| # | Server state | Server behavior | Pending outcome |
|---|---|---|---|
| **Normal** | Linear, owner's previous = tip | Append. `applied: true, diverged_at: None`. | Cleared (absorb_pending succeeds). |
| **A1 — overlap (owner caused divergence)** | Linear, owner's previous ≠ tip (server tip is past owner's view) | Insert owner's forking event at owner's claimed version. `applied: true, diverged_at: Some(boundary+1)`. | Cleared. |
| **A3 — already divergent** | Server already has multiple events at some past version | Reject with "Chain is divergent — repair required." | Preserved (flush errored before `absorb_pending`). |

A1 mirrors KEL's `handle_overlap_submission` → `KelMergeResult::Diverged`. A3 mirrors KEL's `handle_divergent_submission` rejecting non-repair events. The "concurrent submission" framing I used previously was a confused description of A1 — the trigger isn't timing, it's owner's view being stale (server has events past where owner thinks the tip is).

### H1 fix — full client-side chain verification at repair time

Replace the round-9/10 `fetch_tail + fresh-verifier-on-page` approach with full client-side chain re-verification, mirroring what `with_prefix` used to do but invoked only at repair time (not at construction):

```rust
let server_verification = client.verify_sad_events(prefix, Arc::clone(&checker)).await?;

// Step (f) — gate on server view's policy.
if !server_verification.policy_satisfied() {
    return Err(KelsError::ChainHasUnverifiedEvents(...));
}

// Boundary derived from verification state.
let boundary_version = match server_verification.diverged_at_version() {
    Some(d) => d - 1,                       // A3 case: divergence at d, boundary is d-1
    None => {
        let server_tip_v = server_verification.current_event().version;
        let owner_tip_v = owner_verification.current_event().version;
        if server_tip_v <= owner_tip_v {
            return Err(KelsError::NothingToRepair);
        }
        owner_tip_v                          // pure linear extension: boundary = owner's tip
    }
};

// Find boundary event (owner's event at boundary_version) in local sad_store.
let boundary_event = self.find_owner_event_at_version(boundary_version).await?;

// Stage Rpr at boundary+1 with previous = boundary.said.
let rpr = SadEvent::rpr(&boundary_event, content)?;
self.pending_events.push(rpr);
```

The H1 bug (fresh verifier on a tail page that starts past v0) disappears because `verify_sad_events` paginates from v0 forward — one page at a time, bounded verifier state across pages — and handles inception correctly. Total work per repair invocation is `O(chain length / page_size)` page fetches; memory is bounded by one page plus the streaming verifier's per-branch state, regardless of chain length. Acceptable because repair is rare. Mirrors KEL's `merge_events` re-verification on every server-side merge ("DB cannot be trusted" — `merge.rs:540-541`), which paginates the same way.

The diverged_at_version signal from the verifier is authoritative: walking v0 forward, the first version with multiple SAIDs is captured exactly when the divergence began. No need for separate boundary-walk algorithms or page-by-page set comparison.

### Pending events handling

Superseded by the design docs. The corrected behaviour is to **bundle** pending events into the repair/contest/decommission batch — `[pending..., Rpr/Cnt/Dec]` — with the terminal/repair event extending the pending tip. Pending is owner-authored work (potentially expensive: a `governance_policy` may have collected hundreds of `ixn` anchors at flush time), and discarding it loses real cost. KEL's `contest` already bundles `find_missing_owner_events()` for the analogous reason; SEL repair adopts the same shape, and KEL `recover`/`contest`/`rotate_recovery` keep theirs. See [sad-event-log.md §Pending events bundling](../design/sel/event-log.md#pending-events-bundling) and [key-event-log.md §Pending events bundling](../design/kel/event-log.md#pending-events-bundling).

### M1 — atomic write for `FileSadStore::store_sel_event`

Replace the non-atomic read-modify-write on `sel-index/{prefix}.json` with file lock + temp-file rename: acquire flock on the index file (or sidecar `.lock`), read existing entries, append new entry, write to `{prefix}.json.tmp`, `rename` to `{prefix}.json`. POSIX rename is atomic on the same filesystem. If `fs2` isn't already a dep, single-process mutex per FileSadStore instance is acceptable (FileSadStore is dev/test-tier; not production-scale).

### L1 — distinguish empty-chain from missing-payload in `with_prefix`

`with_prefix` currently swallows all `KelsError::NotFound` from `sel_completed_verification`, conflating "empty chain" (legitimately no events) with "partial corruption" (index entry exists, blob missing). Add `KelsError::SadStorePayloadMissing { prefix, said }`; `SadStore::load_sel_events` raises it when the index has an entry but the keyed blob is absent. `with_prefix` propagates this variant rather than treating it as empty.

### KEL parity (round-10 addition)

Add client-side server-chain verification to `KeyEventBuilder::recover`, `contest`, and `rotate_recovery`. Same shape as SEL's repair flow — full chain re-verification before constructing the signed event. Refuses with `ChainHasUnverifiedEvents` on signature/structural failure, and refuses on non-empty pending (`PendingEventsBlockRepair`).

For KEL the boundary signal is `kel_verification.diverged_at_serial()` from the verification (KEL's analog of `diverged_at_version`).

Mirrors the SEL flow exactly. Same case taxonomy applies (overlap = owner-caused, already-divergent = rejected).

**Resolution (round-10 implementation):** Added two private helpers on `KeyEventBuilder` (`lib/kels/src/builder.rs:483-528`):

- `require_no_pending_for_repair` — refuses with `PendingEventsBlockRepair` when the builder has a `kels_client` AND `pending_events` is non-empty. Offline builders (`kels_client = None`) bypass the gate; tests/bench rely on accumulating pending on a client-less builder for inspection, and there's no server submit to confuse with stale pending in offline mode.
- `verify_server_chain_pre_repair` — calls `client.verify_key_events(prefix, ..., KelVerifier::new(prefix), page_size, max_pages)` and wraps the verifier error as `ChainHasUnverifiedEvents`. No-ops when `kels_client` is `None`. Defense-in-depth: a buggy/malicious server that mis-handles invalid chains would otherwise be taken at its word when owner extends from `get_owner_tail`.

`recover` (`builder.rs:374-424`), `contest` (`builder.rs:431-479`), and `rotate_recovery` (`builder.rs:334-371`) all call both helpers as their first action (after the `is_decommissioned` gate). Boundary derivation isn't added here because KEL's existing flow signs from `get_owner_tail` and lets the server's merge engine handle divergence resolution — the audit-doc mention of `kel_verification.diverged_at_serial()` was informational; the gate is purely defensive. KEL parity test triplet pinned: `recover_refuses_when_pending_nonempty_and_connected`, `contest_refuses_when_pending_nonempty_and_connected`, `rotate_recovery_refuses_when_pending_nonempty_and_connected` (`lib/kels/src/types/kel/sync.rs:1801-1907`) — each constructs a connected builder, splices in pending events from an offline builder via the new test-only `pending_events_mut_for_test` helper (`lib/kels/src/builder.rs:202-211`), and asserts `PendingEventsBlockRepair`. Plus `recover_bypasses_pending_gate_in_offline_mode` to pin the offline-mode bypass that tests/bench depend on. The existing integration test at `services/kels/tests/integration_tests.rs:823` (offline builder, calls `recover(true)` to inspect dual-signed events) keeps working unchanged.

### Surface area summary

Files touched (round-10):

- `lib/kels/src/error.rs` — two new variants: `PendingEventsBlockRepair`, `SadStorePayloadMissing`. Latter uses `String` fields to keep `KelsError` small under `clippy::result_large_err`.
- `lib/kels/src/sad_builder.rs` — `repair` rewritten to call `client.verify_sad_events`; `walk_back_to_first_owner` and `HashMap` import removed; pending-empty gate added at top.
- `lib/kels/src/store/sad.rs` — `FileSadStore.index_lock` field; atomic write via temp+rename; `load_sel_events` raises `SadStorePayloadMissing` (both backends).
- `lib/kels/src/builder.rs` — `require_no_pending_for_repair` + `verify_server_chain_pre_repair` helpers; `recover`/`contest`/`rotate_recovery` call them; `pending_events_mut_for_test` cfg-gated test helper.
- `lib/kels/src/types/kel/sync.rs` — KEL parity tests.
- `services/sadstore/tests/sad_builder_tests.rs` — long-chain regression test; harness env-var bump for the larger budget; rate-limit test set/restore env var.

`make` clean: fmt + deny + clippy + 25 test groups (455 unit tests in kels-core, 102 in kels-policy, 86 in kels-creds, 73 in kels-mock-hsm, 57 in kels-cli, 53 in kels-exchange, 45 in kels-gossip, 22 in kels-sadstore unit, 20 in kels-mail, 15 in kels-bench, 14 in kels-registry, 13 in kels-identity, 12 in kels-ffi, 10 in sadstore integration tests including the new long-chain repair test, 7 in repair_tests, 5 in kels-core sync) + build all green.

### Owner-vs-adversary discrimination (surfaced during round-10 design)

`services/sadstore/src/repository.rs::truncate_and_replace` archives ALL events at `version >= from_version`, including owner's authentic post-divergence chain; KEL's `archive_adversary_chain` already discriminates but issues one DB query per walk hop. Round-10 lifts both onto a single shape: one page fetch + resume-verifier trust gate + in-memory walkback from `Rpr.previous` (SEL) / `Rec.previous` (KEL). Builder boundary becomes uniform on the SEL side (`boundary = owner_tip.version`); KEL builders chain from `get_owner_tail` and let the merge engine discriminate. The change also introduces SEL `Sea`/`Cnt`/`Dec` kinds and a content-preservation rule (`Upd` is the sole content mutator), and replaces the old L2 pending guard with pending-bundling into the repair/contest/decommission batch.

Full design: [../design/sel/event-log.md](../design/sel/event-log.md) (SEL lifecycle, repair, contest, decommission, evaluation seal, anchor non-poisonability, server case taxonomy) and [../design/kel/event-log.md](../design/kel/event-log.md) (KEL counterpart, `archive_adversary_chain` page+resume-verify backport, recovery/contest/decommission, recovery-revelation seal). Per-kind reference: [../design/sel/events.md](../design/sel/events.md) and [../design/kel/events.md](../design/kel/events.md). Implementor surface and test plan are tracked on the issue; the audit doc captures the decision, not the implementation brief.


