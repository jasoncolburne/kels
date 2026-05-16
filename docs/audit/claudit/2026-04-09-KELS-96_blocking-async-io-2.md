# Branch Audit: KELS-96_blocking-async-io (Round 2) — 2026-04-09

Wraps blocking `std::fs` I/O in `spawn_blocking` across 6 core files (~646 diff lines, 16 files changed). All 4 findings from round 1 are resolved.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 3        |
| Low      | 0    | 1        |

All findings from round 1 have been resolved. No new findings.

---

## Medium Priority

### ~~1. TOCTOU race in `FileSadStore::delete`~~ — RESOLVED (Round 1)

**File:** `lib/kels/src/store/sad.rs:158-164`

**Resolution:** Replaced `path.exists()` guard with match on `ErrorKind::NotFound`.

### ~~2. `FileKelStore` constructors still block~~ — RESOLVED (Round 1)

**File:** `lib/kels/src/store/file.rs:18-47`

**Resolution:** Converted `FileKelStore::new()`, `FileKelStore::with_owner()`, and `FileSadStore::new()` to `async fn` with `spawn_blocking`. All callers updated.

### ~~3. `FileKelStore::load` double-counts when skipping offset~~ — RESOLVED (Round 1)

**File:** `lib/kels/src/store/file.rs:80-88`

**Resolution:** Renamed `count` to `lines_seen` to clarify intent.

---

## Low Priority

### ~~4. Import style: `tokio::task::spawn_blocking` vs `tokio::task`~~ — RESOLVED (Round 1)

**File:** `lib/kels/src/crypto/keys.rs:4`

**Resolution:** Added `use tokio::task::spawn_blocking;` to imports and replaced all fully-qualified calls.

---

## Positive Observations

- **Complete coverage of async store paths.** Every `std::fs` call in `FileKelStore`, `FileSadStore`, `FileKeyStateStore`, and `SoftwareKeyProvider::save_to_dir` is now wrapped in `spawn_blocking`. The constructors (`new`, `with_owner`) were also converted, closing the gap noted in round 1.

- **`load_from_dir` correctly remains sync.** `SoftwareKeyProvider::load_from_dir` is synchronous, but its only caller (`SoftwareProviderConfig::load_provider`) wraps the entire call in `spawn_blocking`. This is the right pattern — the inner function doesn't need to be async since it runs on a blocking thread.

- **FFI callers handled correctly.** `lib/ffi/src/lib.rs:404` uses `runtime.block_on(FileKelStore::new(...))` and `lib/ffi/src/registry.rs:139` uses `.await` inside `runtime.block_on(async { ... })`. Both patterns are correct for FFI boundary code that creates its own runtime.

- **Consistent JoinError mapping.** All `spawn_blocking` calls use the identical `.await.map_err(|e| KelsError::StorageError(e.to_string()))?` pattern. A `JoinError` here would only occur if the blocking task panicked, and mapping it to `StorageError` is appropriate.

- **Data extracted before closures.** Serialization (`serde_json::to_string`), qb64 extraction, and `data.to_vec()` all happen before entering `spawn_blocking` closures, correctly separating CPU work from I/O work and avoiding `Send` lifetime issues.

- **Test infrastructure updated.** All `#[test]` functions that call `FileKelStore::new` or `FileSadStore::new` were converted to `#[tokio::test] async fn`, with no tests skipped or stubbed.
