# Mail Service: General-Purpose ESSR Messaging

A general-purpose encrypted messaging layer for KELS identities. Stores and delivers ESSR-encrypted envelopes without inspecting payloads. Deployed as `services/mail` alongside other KELS node services.

## Architecture

The mail service is payload-agnostic — it handles opaque ESSR envelopes. The exchange protocol (apply/offer/grant/etc.) is one application built on top; other applications can use any topic string.

### Storage

Two layers, split between routing metadata and bulk encrypted data:

- **Envelope blobs** (MinIO) — ESSR envelopes stored as opaque binary objects at the **origin node only**. Key: `messages/{blob_digest}` where digest is qb64 Blake3. Content-addressable and integrity-verified on fetch.
- **Message metadata** (PostgreSQL) — Routing information stored at **every node** via gossip. Tells recipients where their mail lives without replicating the encrypted payloads.

### MailMessage

```rust
pub struct MailMessage {
    pub said: String,
    pub source_node_prefix: String,   // node where blob lives
    pub recipient_kel_prefix: String, // recipient's KEL prefix
    pub blob_digest: String,          // qb64 Blake3 digest (MinIO key)
    pub blob_size: i64,               // envelope size in bytes
    pub created_at: StorageDatetime,
    pub expires_at: StorageDatetime,
}
```

### Gossip Distribution

Metadata propagates network-wide on topic `kels/mail/v1`:

```rust
pub enum MailAnnouncement {
    Message(MailMessage),        // new mail available
    Removal { said: String },    // mail deleted
}
```

Announcements published to Redis, picked up by the gossip service, and broadcast to all peers.

## Message Lifecycle

1. **Send** — Sender submits ESSR envelope to their local mail node. Node stores blob in MinIO + metadata in PostgreSQL, gossips `Message` announcement.
2. **Discover** — Recipient queries any node's inbox endpoint. Gets `MailMessage` entries with `source_node_prefix` identifying where blobs live.
3. **Fetch** — Recipient resolves source node URL (via registry or base domain), authenticates to source node's mail service, retrieves blob. Client verifies `blob_digest` and `blob_size` match.
4. **Open** — Recipient deserializes blob as `SignedEssrEnvelope`, verifies sender's KEL, ESSR-opens with local decapsulation key.
5. **Acknowledge** — Recipient sends ack to local node. Source node deletes blob from MinIO, gossips `Removal` announcement. All nodes delete metadata.

## HTTP API

| Endpoint | Auth | Purpose |
|----------|------|---------|
| `GET /health` | None | Health check |
| `POST /api/v1/mail/send` | Sender signs | Submit ESSR envelope |
| `POST /api/v1/mail/inbox` | Recipient signs | List inbox metadata (paginated) |
| `POST /api/v1/mail/fetch` | Recipient signs | Retrieve envelope blob (origin node only) |
| `POST /api/v1/mail/ack` | Recipient signs | Acknowledge messages (triggers deletion + gossip removal) |

All authenticated endpoints use `SignedRequest<T>` — the caller signs the request payload, the server verifies against the caller's KEL via the co-located KELS instance.

The `fetch` endpoint is authenticated even though envelopes are ESSR-encrypted. Unauthenticated access would allow offline attacks against the ciphertext.

## Rate Limiting & Spam Prevention

Three independent layers:

| Limit | Default | Scope |
|-------|---------|-------|
| Per-sender daily cap | 100 messages/day | `MAIL_MAX_MESSAGES_PER_SENDER_PER_DAY` |
| Per-recipient inbox cap | 10,000 messages | `MAIL_MAX_INBOX_SIZE` |
| Per-recipient local storage cap | 100 MB | `MAIL_MAX_STORAGE_PER_RECIPIENT_MB` (cumulative blob size at this node) |
| Per-IP token bucket | 500 burst, 100/sec refill | Hardcoded |
| Message TTL | 30 days | `MAIL_MESSAGE_TTL_DAYS` |
| Nonce deduplication window | 60 seconds | `KELS_NONCE_WINDOW_SECS` |

The storage cap is enforced per-node: `SUM(blob_size) WHERE source_node_prefix = self AND recipient_kel_prefix = $1`. This caps what the local node stores, not network-wide metadata.

A background reaper runs every 5 minutes to:
- Expire rate limit entries older than 1 day
- Expire nonce cache entries older than the nonce window
- Delete expired messages (blob + metadata), gossip removals

## Dependencies

- **kels-core** — `SignedRequest`, `KelsClient`, `IdentityClient`, crypto utilities
- **kels-exchange** — `MailMessage`, `MailAnnouncement`, `SendRequest`, `InboxRequest`, `FetchRequest`, `AckRequest`, `compute_blob_digest`
- **verifiable-storage** / **verifiable-storage-postgres** — `SelfAddressed`, `Stored` derives, query builder
- **aws-sdk-s3** — MinIO blob storage (same pattern as SADStore)
- **redis** — pub/sub for gossip announcements
- **dashmap** — in-memory rate limiting (same pattern as SADStore)
- **axum** — HTTP framework

## Configuration

The mail service fetches its node prefix from the co-located identity service at startup. Environment variables:

| Variable | Default | Purpose |
|----------|---------|---------|
| `PORT` | 80 | HTTP listen port |
| `DATABASE_URL` | `postgres://postgres:postgres@database:5432/mail` | PostgreSQL connection |
| `REDIS_URL` | (none) | Redis for gossip pub/sub (optional, standalone mode without) |
| `KELS_URL` | `http://kels:80` | Co-located KELS instance for KEL verification |
| `IDENTITY_URL` | `http://identity:80` | Identity service for node prefix |
| `MINIO_ENDPOINT` | `http://minio:9000` | MinIO endpoint |
| `MINIO_REGION` | `us-east-1` | MinIO region |
| `MINIO_ACCESS_KEY` | (required) | MinIO credentials |
| `MINIO_SECRET_KEY` | (required) | MinIO credentials |
| `KELS_MAIL_BUCKET` | `kels-mail` | MinIO bucket name |

## Future: Access Control

The mail service can be extended with an access credential requirement. When configured with a schema SAID and policy SAID, `POST /api/v1/mail/send` would require the caller to present a valid, non-expired access credential (granted through some sign up process) to prevent abuse. The existing credential system provides authentication, authorization, expiration, and revocation (via poisoning).

## Future: Push Notifications

WebSocket endpoint for real-time delivery. Not required for initial implementation — polling via `inbox` is sufficient.
