# SadStore

**Canonical name:** `SadStore`

The unified store trait for SAD-bearing data. Defines the read+write surface that every concrete store implementation honors. The chain of implementations ([`CascadingSadStore`](cascading-sad-store.md), [`RemoteSadStore`](remote-sad-store.md), [`PostgresSadStore`](postgres-sad-store.md), [`FileSadStore`](file-sad-store.md), [`InMemorySadStore`](in-memory-sad-store.md)) lets callers compose local + remote tiers without leaking transport / persistence concerns into consumers.

**Consumers:** every SAD-using surface — credential issuance, exchange envelopes, SEL content, custody-tagged objects.

**Dependencies:** verifiable-storage SAD types (see [`../../../infrastructure/sadstore.md`](../../../infrastructure/sadstore.md)).

Stub. Detailed content lands iteratively.
