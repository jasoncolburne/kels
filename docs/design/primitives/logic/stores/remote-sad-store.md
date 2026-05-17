# RemoteSadStore

**Canonical name:** `RemoteSadStore`

An adapter that implements [`SadStore`](sad-store.md) over `SadStoreClient` — turning the network surface of a remote SADStore service into the local trait shape consumers expect. Lands as part of #153 → #195.

**Consumers:** clients (CLI, mobile) composing tiered storage via [`CascadingSadStore`](cascading-sad-store.md).

**Dependencies:** [`sad-store.md`](sad-store.md), the sadstore service ([`../../../infrastructure/sadstore.md`](../../../infrastructure/sadstore.md)).

Stub. Detailed content lands iteratively.
