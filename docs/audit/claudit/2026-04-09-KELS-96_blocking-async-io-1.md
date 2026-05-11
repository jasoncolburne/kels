# Branch Audit: KELS-96_blocking-async-io (Round 1) — 2026-04-09

Wraps blocking `std::fs` I/O in `spawn_blocking` across 4 files (~551 diff lines). Makes `KeyStateStore` trait async.

## Summary

| Priority | Open | Resolved |
|----------|------|----------|
| High     | 0    | 0        |
| Medium   | 0    | 3        |
| Low      | 0    | 1        |

---

## Medium Priority

### ~~1. TOCTOU race in `FileSadStore::delete`~~ — RESOLVED

**File:** `lib/kels/src/store/sad.rs:158-161`

~~The `path.exists()` check before `remove_file()` is a time-of-check-time-of-use race. If the file is deleted between the check and the remove, the `remove_file` will return `NotFound`. This was pre-existing but worth noting since the surrounding code was touched. The `FileKeyStateStore::delete` handles this correctly by matching on `ErrorKind::NotFound` without a prior exists check.~~

**Resolution:** Replaced `path.exists()` guard with match on `ErrorKind::NotFound`, consistent with `FileKeyStateStore::delete`.

### ~~2. `FileKelStore` constructors still block~~ — RESOLVED

**File:** `lib/kels/src/store/file.rs:18-38`

~~`FileKelStore::new()` and `FileKelStore::with_owner()` call `std::fs::create_dir_all` synchronously. These are sync constructors so they can't easily use `spawn_blocking`, but callers in async contexts will still block. The issue description lists these files but the constructors weren't wrapped. This is a minor gap — constructor I/O is typically a one-time cost, but noted for completeness since `FileSadStore::new()` has the same pattern.~~

**Resolution:** Converted `FileKelStore::new()`, `FileKelStore::with_owner()`, and `FileSadStore::new()` to `async fn` with `spawn_blocking`. Updated all callers across the codebase (CLI commands, FFI, policy tests, credential tests, gossip tests).

### ~~3. `FileKelStore::load` double-counts when skipping offset~~ — RESOLVED

**File:** `lib/kels/src/store/file.rs:80-88`

~~Pre-existing issue but visible in the diff: the `count` variable is only incremented in the `count < start` branch but not for collected events. After passing the offset, `count` continues incrementing but is never checked again, so this works by accident. However, the variable name is misleading — it tracks "lines seen" not "total count." Not a bug, but confusing.~~

**Resolution:** Renamed `count` to `lines_seen` to clarify intent.

---

## Low Priority

### ~~4. Import style: `tokio::task::spawn_blocking` vs `tokio::task`~~ — RESOLVED

**File:** `lib/kels/src/crypto/keys.rs:196,221,235`

~~In `keys.rs`, `spawn_blocking` is called as `tokio::task::spawn_blocking(...)` (fully qualified) rather than importing it at the top like `file.rs` and `sad.rs` do. This is inconsistent across the changed files.~~

**Resolution:** Added `use tokio::task::spawn_blocking;` to `keys.rs` imports and replaced all fully-qualified calls with the short form.

---

## Positive Observations

- **Serialization outside `spawn_blocking`.** In `append` and `overwrite`, JSON serialization happens before entering the blocking closure. This keeps CPU-bound serde work on the async thread (where it's fast and non-blocking) and only offloads actual I/O, which is the correct split.

- **Clean `save_to_dir` refactor.** The new version extracts qb64 strings before entering `spawn_blocking`, eliminating the interleaved error-checking-and-writing pattern. This is both more readable and correctly avoids sending `&self` into the closure.

- **`KeyStateStore` trait made async.** Rather than leaving a sync trait with blocking implementations called from async code, the trait was properly elevated to async. This makes the contract honest — callers know they're awaiting I/O, not accidentally blocking.

- **Consistent error mapping pattern.** All `spawn_blocking` calls use the same `.await.map_err(|e| KelsError::StorageError(e.to_string()))?` pattern for JoinError handling, making the code predictable and grep-friendly.

- **Minimal blast radius.** Only 4 files changed, all callers of `KeyStateStore` were updated, and all existing tests pass without modification. The changes are purely mechanical wrapping with no behavioral changes.

- **`data.to_vec()` in `FileKeyStateStore::save`.** The `&[u8]` data is correctly cloned to owned before moving into the `spawn_blocking` closure, avoiding lifetime issues without over-engineering.
