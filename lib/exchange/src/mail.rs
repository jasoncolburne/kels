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
    pub said: cesr::Digest,
    /// Sender's KEL prefix (from authenticated request).
    pub sender_kel_prefix: cesr::Digest,
    /// Node prefix where the envelope blob lives.
    pub source_node_prefix: cesr::Digest,
    /// Recipient's KEL prefix.
    pub recipient_kel_prefix: cesr::Digest,
    /// Blake3 digest of the ESSR envelope blob (content-addressable MinIO key).
    pub blob_digest: cesr::Digest,
    /// Size of the ESSR envelope blob in bytes.
    pub blob_size: i64,
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
    Message(Box<MailMessage>),
    /// Mail message removed (blob deleted at source).
    Removal {
        /// SAID of the removed mail message.
        said: cesr::Digest,
    },
}

/// Gossip topic for mail announcements.
pub const MAIL_GOSSIP_TOPIC: &str = "kels/mail/v1";

/// Compute the Blake3 digest of a blob, returned as a CESR Digest.
pub fn compute_blob_digest(blob: &[u8]) -> cesr::Digest {
    cesr::Digest::blake3_256(blob)
}

// ==================== Mail API Request/Response Types ====================

/// Request payload for sending mail.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendRequest {
    pub timestamp: i64,
    pub nonce: String,
    pub recipient_kel_prefix: cesr::Digest,
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
    pub mail_said: cesr::Digest,
}

/// Request payload for acknowledging (deleting) messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AckRequest {
    pub timestamp: i64,
    pub nonce: String,
    pub saids: Vec<cesr::Digest>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use verifiable_storage::SelfAddressed;

    use super::*;

    fn test_digest(label: &str) -> cesr::Digest {
        cesr::Digest::blake3_256(label.as_bytes())
    }

    #[test]
    fn mail_message_said_derivation() {
        let mut msg = MailMessage {
            said: cesr::Digest::default(),
            sender_kel_prefix: test_digest("sender-prefix"),
            source_node_prefix: test_digest("node-prefix"),
            recipient_kel_prefix: test_digest("recipient-prefix"),
            blob_digest: test_digest("blob-digest-abc"),
            blob_size: 1024,
            created_at: StorageDatetime::now(),
            expires_at: StorageDatetime::now(),
        };
        msg.derive_said().unwrap();
        assert_ne!(msg.said, cesr::Digest::default());
    }

    #[test]
    fn mail_announcement_serialization() {
        let test_said = test_digest("test-said");
        let msg = MailMessage {
            said: test_said.clone(),
            sender_kel_prefix: test_digest("sender"),
            source_node_prefix: test_digest("node"),
            recipient_kel_prefix: test_digest("recipient"),
            blob_digest: test_digest("digest"),
            blob_size: 512,
            created_at: StorageDatetime::now(),
            expires_at: StorageDatetime::now(),
        };

        let announcement = MailAnnouncement::Message(Box::new(msg));
        let json = serde_json::to_string(&announcement).unwrap();
        let deserialized: MailAnnouncement = serde_json::from_str(&json).unwrap();
        match deserialized {
            MailAnnouncement::Message(m) => assert_eq!(m.said, test_said),
            _ => unreachable!(),
        }

        let remove_said = test_digest("remove-said");
        let removal = MailAnnouncement::Removal {
            said: remove_said.clone(),
        };
        let json = serde_json::to_string(&removal).unwrap();
        let deserialized: MailAnnouncement = serde_json::from_str(&json).unwrap();
        match deserialized {
            MailAnnouncement::Removal { said } => assert_eq!(said, remove_said),
            _ => unreachable!(),
        }
    }

    #[test]
    fn blob_digest_is_deterministic() {
        let data = b"test blob data";
        let d1 = compute_blob_digest(data);
        let d2 = compute_blob_digest(data);
        assert_eq!(d1, d2);
        assert_ne!(d1, cesr::Digest::default());
    }

    #[test]
    fn different_blobs_produce_different_digests() {
        let d1 = compute_blob_digest(b"blob a");
        let d2 = compute_blob_digest(b"blob b");
        assert_ne!(d1, d2);
    }
}
