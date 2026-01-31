//! Protocol message types for KELS gossip.
//!
//! Defines the request-response protocol messages for fetching KELs from peers.

use kels::SignedKeyEvent;
use serde::{Deserialize, Serialize};

/// Protocol name for libp2p request-response
pub const PROTOCOL_NAME: &str = "/kels/sync/1.0.0";

/// Request to fetch a KEL from a peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KelRequest {
    /// The KEL prefix to fetch
    pub prefix: String,
}

/// Response containing KEL events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KelResponse {
    /// The KEL prefix
    pub prefix: String,
    /// The events in the KEL
    pub events: Vec<SignedKeyEvent>,
}

/// Gossipsub announcement message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KelAnnouncement {
    /// The KEL prefix that was updated
    pub prefix: String,
    /// The SAID of the latest event
    pub said: String,
}

impl KelAnnouncement {
    /// Parse from Redis pub/sub message format "{prefix}:{said}"
    pub fn from_pubsub_message(message: &str) -> Option<Self> {
        let mut parts = message.splitn(2, ':');
        let prefix = parts.next()?.to_string();
        let said = parts.next()?.to_string();

        // Empty SAID means deletion - skip
        if said.is_empty() {
            return None;
        }

        Some(Self { prefix, said })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_announcement_from_pubsub() {
        let msg = "Eprefix123:EsaidABC";
        let ann = KelAnnouncement::from_pubsub_message(msg);
        assert!(ann.is_some());
        let ann = ann.unwrap();
        assert_eq!(ann.prefix, "Eprefix123");
        assert_eq!(ann.said, "EsaidABC");
    }

    #[test]
    fn test_announcement_from_pubsub_empty_said() {
        let msg = "Eprefix123:";
        let ann = KelAnnouncement::from_pubsub_message(msg);
        assert!(ann.is_none());
    }

    #[test]
    fn test_announcement_serialization() {
        let ann = KelAnnouncement {
            prefix: "Eprefix".to_string(),
            said: "Esaid".to_string(),
        };
        let json = serde_json::to_string(&ann).unwrap();
        let parsed: KelAnnouncement = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.prefix, ann.prefix);
        assert_eq!(parsed.said, ann.said);
    }
}
