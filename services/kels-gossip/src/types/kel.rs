//! Protocol message types for KELS gossip.
//!
//! Defines the gossipsub announcement messages for KEL updates.

use serde::{Deserialize, Serialize};

/// Gossipsub announcement message.
///
/// PlumTree handles deduplication and epidemic broadcast to all mesh nodes.
/// The `origin` field identifies the peer that stored the event, so receivers
/// know where to fetch the event data from (looked up via allowlist).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KelAnnouncement {
    /// The KEL prefix that was updated
    pub prefix: String,
    /// The SAID of the latest event
    pub said: String,
    /// The peer prefix of the node that stored this event
    pub origin: String,
}

impl KelAnnouncement {
    /// Parse from Redis pub/sub message format "{prefix}:{said}"
    pub fn from_pubsub_message(message: &str, origin: &str) -> Option<Self> {
        let mut parts = message.splitn(2, ':');
        let prefix = parts.next()?.to_string();
        let said = parts.next()?.to_string();

        // Empty SAID means deletion - skip
        if said.is_empty() {
            return None;
        }

        Some(Self {
            prefix,
            said,
            origin: origin.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_announcement_from_pubsub() {
        let msg = "Eprefix123:EsaidABC";
        let ann = KelAnnouncement::from_pubsub_message(msg, "Eorigin");
        assert!(ann.is_some());
        let ann = ann.unwrap();
        assert_eq!(ann.prefix, "Eprefix123");
        assert_eq!(ann.said, "EsaidABC");
        assert_eq!(ann.origin, "Eorigin");
    }

    #[test]
    fn test_announcement_from_pubsub_empty_said() {
        let msg = "Eprefix123:";
        let ann = KelAnnouncement::from_pubsub_message(msg, "Eorigin");
        assert!(ann.is_none());
    }

    #[test]
    fn test_announcement_serialization() {
        let ann = KelAnnouncement {
            prefix: "Eprefix".to_string(),
            said: "Esaid".to_string(),
            origin: "Eorigin".to_string(),
        };
        let json = serde_json::to_string(&ann).unwrap();
        let parsed: KelAnnouncement = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.prefix, ann.prefix);
        assert_eq!(parsed.said, ann.said);
        assert_eq!(parsed.origin, ann.origin);
    }

    #[test]
    fn test_announcement_from_pubsub_no_colon() {
        let msg = "prefixonly";
        let ann = KelAnnouncement::from_pubsub_message(msg, "Eorigin");
        assert!(ann.is_none());
    }

    #[test]
    fn test_announcement_from_pubsub_multiple_colons() {
        // splitn(2, ':') means only split on first colon
        let msg = "Eprefix:Esaid:extra:stuff";
        let ann = KelAnnouncement::from_pubsub_message(msg, "Eorigin");
        assert!(ann.is_some());
        let ann = ann.unwrap();
        assert_eq!(ann.prefix, "Eprefix");
        assert_eq!(ann.said, "Esaid:extra:stuff");
    }

    #[test]
    fn test_kel_announcement_clone() {
        let ann = KelAnnouncement {
            prefix: "ECLONE".to_string(),
            said: "ESAID".to_string(),
            origin: "EORIGIN".to_string(),
        };
        let cloned = ann.clone();
        assert_eq!(ann.prefix, cloned.prefix);
        assert_eq!(ann.said, cloned.said);
        assert_eq!(ann.origin, cloned.origin);
    }

    #[test]
    fn test_kel_announcement_debug() {
        let ann = KelAnnouncement {
            prefix: "EDEBUG".to_string(),
            said: "ESAID".to_string(),
            origin: "EORIGIN".to_string(),
        };
        let debug_str = format!("{:?}", ann);
        assert!(debug_str.contains("EDEBUG"));
        assert!(debug_str.contains("ESAID"));
        assert!(debug_str.contains("EORIGIN"));
    }
}
