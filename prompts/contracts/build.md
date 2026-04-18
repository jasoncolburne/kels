# Build

- **`make`** verifies changes (fmt, deny, clippy, test, build). Never use naked cargo commands.
- Only run when `.rs`, `Cargo.toml`, or `deny.toml` changed.
- Dependency crates live at `../verifiable-storage-rs`, `../cacheable`, `../cesr-rs`.
- When adding a local `lib/` crate as a dependency, update the Garden config and Dockerfile too.
