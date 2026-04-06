//! Exchange message types — IPEX-style credential exchange protocol.

use serde::{Deserialize, Serialize};
use verifiable_storage::{SelfAddressed, StorageDatetime};

/// Exchange message kinds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ExchangeKind {
    /// "I want credential of type X"
    Apply,
    /// "I can give you credential X under these terms"
    Offer,
    /// "I accept your offer"
    Agree,
    /// "Here is the credential" (the core payload)
    Grant,
    /// "Received and verified"
    Admit,
    /// "Rejected"
    Reject,
}

/// A chained exchange message. The first message in a thread (apply, offer, or direct grant)
/// is the v0 inception — its prefix becomes the thread identifier.
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[serde(rename_all = "camelCase")]
pub struct ExchangeMessage {
    #[said]
    pub said: cesr::Digest,
    /// Thread identifier (deterministic from v0 inception).
    #[prefix]
    pub prefix: cesr::Digest,
    /// SAID of prior message in thread (None for thread inception).
    #[previous]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous: Option<cesr::Digest>,
    /// Message sequence within thread.
    #[version]
    pub message_number: u64,
    /// Message kind.
    pub kind: ExchangeKind,
    /// Sender's KEL prefix.
    pub sender: cesr::Digest,
    /// Recipient's KEL prefix.
    pub recipient: cesr::Digest,
    #[created_at]
    pub created_at: StorageDatetime,
    /// Anti-replay nonce (Blake3 hash of random bytes).
    pub nonce: cesr::Digest,
    /// Kind-specific payload.
    pub payload: ExchangePayload,
}

/// Kind-specific payload for exchange messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum ExchangePayload {
    /// Apply: request a credential.
    Apply {
        /// Schema SAID being requested.
        schema: String,
        /// Optional policy SAID constraint.
        #[serde(skip_serializing_if = "Option::is_none")]
        policy: Option<String>,
        /// Optional disclosure expression.
        #[serde(skip_serializing_if = "Option::is_none")]
        disclosure: Option<String>,
    },
    /// Offer: propose issuing a credential.
    Offer {
        /// Schema SAID.
        schema: String,
        /// Policy SAID.
        policy: String,
        /// Optional credential preview (partial claims).
        #[serde(skip_serializing_if = "Option::is_none")]
        credential_preview: Option<serde_json::Value>,
        /// Optional rules.
        #[serde(skip_serializing_if = "Option::is_none")]
        rules: Option<serde_json::Value>,
    },
    /// Agree: accept an offer.
    Agree {
        /// SAID of the accepted offer message.
        offer: String,
    },
    /// Grant: deliver a credential.
    Grant {
        /// Full credential JSON.
        credential: serde_json::Value,
        /// Schema JSON.
        schema: serde_json::Value,
        /// Policy JSON.
        policy: serde_json::Value,
        /// Edge schemas (keyed by edge label).
        #[serde(skip_serializing_if = "Option::is_none")]
        edge_schemas: Option<serde_json::Map<String, serde_json::Value>>,
        /// Edge policies (keyed by edge label).
        #[serde(skip_serializing_if = "Option::is_none")]
        edge_policies: Option<serde_json::Map<String, serde_json::Value>>,
    },
    /// Admit: acknowledge receipt and verification of a grant.
    Admit {
        /// SAID of the acknowledged grant message.
        grant: String,
    },
    /// Reject: reject a message in the thread.
    Reject {
        /// Optional rejection reason.
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
}

/// ESSR topic for exchange protocol messages.
pub const EXCHANGE_TOPIC: &str = "kels/v1/exchange";

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use verifiable_storage::Chained;

    use super::*;

    fn test_digest(label: &str) -> cesr::Digest {
        cesr::Digest::blake3_256(label.as_bytes())
    }

    #[test]
    fn exchange_message_create() {
        let msg = ExchangeMessage::create(
            ExchangeKind::Apply,
            test_digest("sender-prefix"),
            test_digest("recipient-prefix"),
            test_digest("test-nonce"),
            ExchangePayload::Apply {
                schema: "schema-said".to_string(),
                policy: None,
                disclosure: None,
            },
        )
        .unwrap();

        assert_ne!(msg.said, cesr::Digest::default());
        assert_ne!(msg.prefix, cesr::Digest::default());
        assert!(msg.previous.is_none());
        assert_eq!(msg.message_number, 0);
    }

    #[test]
    fn chained_messages_share_thread_prefix() {
        let sender = test_digest("sender");
        let recipient = test_digest("recipient");

        let mut thread = ExchangeMessage::create(
            ExchangeKind::Apply,
            sender.clone(),
            recipient.clone(),
            test_digest("nonce-0"),
            ExchangePayload::Apply {
                schema: "schema".to_string(),
                policy: None,
                disclosure: None,
            },
        )
        .unwrap();

        let thread_prefix = thread.prefix.clone();

        // Update fields for the reply, then increment
        thread.kind = ExchangeKind::Offer;
        thread.sender = recipient;
        thread.recipient = sender;
        thread.nonce = test_digest("nonce-1");
        thread.payload = ExchangePayload::Offer {
            schema: "schema".to_string(),
            policy: "policy".to_string(),
            credential_preview: None,
            rules: None,
        };
        thread.increment().unwrap();

        assert_eq!(thread.prefix, thread_prefix);
        assert_eq!(thread.message_number, 1);
        assert!(thread.previous.is_some());
    }

    #[test]
    fn payload_serialization_roundtrip() {
        let payload = ExchangePayload::Grant {
            credential: serde_json::json!({"said": "abc"}),
            schema: serde_json::json!({"said": "def"}),
            policy: serde_json::json!({"said": "ghi"}),
            edge_schemas: None,
            edge_policies: None,
        };

        let json = serde_json::to_string(&payload).unwrap();
        let deserialized: ExchangePayload = serde_json::from_str(&json).unwrap();

        match deserialized {
            ExchangePayload::Grant { credential, .. } => {
                assert_eq!(credential["said"], "abc");
            }
            _ => unreachable!(),
        }
    }
}
