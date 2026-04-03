//! Mail service types — message metadata and gossip announcements.

use serde::{Deserialize, Serialize};
use verifiable_storage::{SelfAddressed, StorageDatetime};

/// Mail message metadata. Stored in PostgreSQL at every node (gossiped network-wide).
/// The actual ESSR envelope blob is stored in MinIO at the origin node only.
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[storable(table = "mail_messages")]
#[serde(rename_all = "camelCase")]
pub struct MailMessage {
    #[said]
    pub said: String,
    /// Node prefix where the envelope blob lives.
    pub source_node_prefix: String,
    /// Recipient's KEL prefix.
    pub recipient_kel_prefix: String,
    /// qb64 Blake3 digest of the ESSR envelope blob (content-addressable MinIO key).
    pub blob_digest: String,
    #[created_at]
    pub created_at: StorageDatetime,
    /// When this message expires and should be garbage collected.
    pub expires_at: StorageDatetime,
}

/// Mail gossip announcement, broadcast on topic `kels/mail/v1`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum MailAnnouncement {
    /// New mail message available.
    Message(MailMessage),
    /// Mail message removed (blob deleted at source).
    Removal {
        /// SAID of the removed mail message.
        said: String,
    },
}

/// Gossip topic for mail announcements.
pub const MAIL_GOSSIP_TOPIC: &str = "kels/mail/v1";

/// Compute the Blake3 digest of a blob, returned as a qb64 CESR-encoded string.
pub fn compute_blob_digest(blob: &[u8]) -> String {
    use cesr::{Digest, Matter};
    Digest::blake3_256(blob).qb64()
}

// ==================== Mail API Request/Response Types ====================

/// Request payload for sending mail.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendRequest {
    pub timestamp: i64,
    pub nonce: String,
    pub recipient_kel_prefix: String,
    /// Base64-encoded ESSR envelope blob.
    pub blob: String,
}

/// Request payload for checking inbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InboxRequest {
    pub timestamp: i64,
    pub nonce: String,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// Response for inbox listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InboxResponse {
    pub messages: Vec<MailMessage>,
}

/// Request payload for fetching a mail blob.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FetchRequest {
    pub timestamp: i64,
    pub nonce: String,
    pub mail_said: String,
}

/// Request payload for acknowledging (deleting) messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AckRequest {
    pub timestamp: i64,
    pub nonce: String,
    pub saids: Vec<String>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use verifiable_storage::SelfAddressed;

    use super::*;

    #[test]
    fn mail_message_said_derivation() {
        let mut msg = MailMessage {
            said: String::new(),
            source_node_prefix: "node-prefix".to_string(),
            recipient_kel_prefix: "recipient-prefix".to_string(),
            blob_digest: "blob-digest-abc".to_string(),
            created_at: StorageDatetime::now(),
            expires_at: StorageDatetime::now(),
        };
        msg.derive_said().unwrap();
        assert!(!msg.said.is_empty());
    }

    #[test]
    fn mail_announcement_serialization() {
        let msg = MailMessage {
            said: "test-said".to_string(),
            source_node_prefix: "node".to_string(),
            recipient_kel_prefix: "recipient".to_string(),
            blob_digest: "digest".to_string(),
            created_at: StorageDatetime::now(),
            expires_at: StorageDatetime::now(),
        };

        let announcement = MailAnnouncement::Message(msg);
        let json = serde_json::to_string(&announcement).unwrap();
        let deserialized: MailAnnouncement = serde_json::from_str(&json).unwrap();
        match deserialized {
            MailAnnouncement::Message(m) => assert_eq!(m.said, "test-said"),
            _ => unreachable!(),
        }

        let removal = MailAnnouncement::Removal {
            said: "remove-said".to_string(),
        };
        let json = serde_json::to_string(&removal).unwrap();
        let deserialized: MailAnnouncement = serde_json::from_str(&json).unwrap();
        match deserialized {
            MailAnnouncement::Removal { said } => assert_eq!(said, "remove-said"),
            _ => unreachable!(),
        }
    }

    #[test]
    fn blob_digest_is_deterministic() {
        let data = b"test blob data";
        let d1 = compute_blob_digest(data);
        let d2 = compute_blob_digest(data);
        assert_eq!(d1, d2);
        assert!(!d1.is_empty());
    }

    #[test]
    fn different_blobs_produce_different_digests() {
        let d1 = compute_blob_digest(b"blob a");
        let d2 = compute_blob_digest(b"blob b");
        assert_ne!(d1, d2);
    }
}
