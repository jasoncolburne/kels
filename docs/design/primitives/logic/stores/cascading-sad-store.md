# CascadingSadStore

**Canonical name:** `CascadingSadStore`

A [`SadStore`](sad-store.md) implementation that composes a chained read+write tier (typically local → remote): reads fall through the chain until a hit; writes fan out per policy. Lands as part of #153 → #195. Provides the surface that lets callers transparently substitute identity-service-backed remotes for local stores.

**Consumers:** any SAD-using surface that wants tiered storage.

**Dependencies:** [`sad-store.md`](sad-store.md); typically composes [`postgres-sad-store.md`](postgres-sad-store.md) and [`remote-sad-store.md`](remote-sad-store.md).

Stub. Detailed content lands iteratively.
