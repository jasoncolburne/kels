# PostgresSadStore

**Canonical name:** `PostgresSadStore`

A PostgreSQL-backed [`SadStore`](sad-store.md) implementation, identity-service-backed per #195. The default durable local tier composed under [`CascadingSadStore`](cascading-sad-store.md).

**Consumers:** identity service; sadstore service (for SEL chain storage; see [`../../../infrastructure/sadstore.md`](../../../infrastructure/sadstore.md)).

**Dependencies:** [`sad-store.md`](sad-store.md); verifiable-storage Postgres backend.

Stub. Detailed content lands iteratively.
