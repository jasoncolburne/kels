//! Protocol message types for KELS gossip.
//!
//! Defines the gossipsub announcement messages for KEL updates.

use cesr::Matter;
use serde::{Deserialize, Serialize};

/// Gossipsub announcement message.
///
/// PlumTree handles deduplication and epidemic broadcast to all mesh nodes.
/// The `origin` field identifies the peer that stored the event, so receivers
/// know where to fetch the event data from (looked up via allowlist).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct KelAnnouncement {
    /// The KEL prefix that was updated
    pub prefix: cesr::Digest256,
    /// The SAID of the latest event
    pub said: cesr::Digest256,
    /// The peer prefix of the node that stored this event
    pub origin: cesr::Digest256,
}

impl KelAnnouncement {
    /// Parse from Redis pub/sub message format "{prefix}:{said}"
    pub fn from_pubsub_message(message: &str, origin: &cesr::Digest256) -> Option<Self> {
        let (prefix_str, said_str) = message.split_once(':')?;

        // Empty SAID means deletion - skip
        if said_str.is_empty() {
            return None;
        }

        let prefix = cesr::Digest256::from_qb64(prefix_str).ok()?;
        let said = cesr::Digest256::from_qb64(said_str).ok()?;

        Some(Self {
            prefix,
            said,
            origin: *origin,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cesr::test_digest;

    fn make_qb64_msg() -> (String, String, String) {
        let prefix = test_digest("prefix1");
        let said = test_digest("said1");
        let origin = test_digest("origin1");
        (prefix.to_string(), said.to_string(), origin.to_string())
    }

    #[test]
    fn test_announcement_from_pubsub() {
        let (prefix_str, said_str, _) = make_qb64_msg();
        let origin_digest = test_digest("origin1");
        let msg = format!("{}:{}", prefix_str, said_str);
        let ann = KelAnnouncement::from_pubsub_message(&msg, &origin_digest);
        assert!(ann.is_some());
        let ann = ann.unwrap();
        assert_eq!(ann.prefix, test_digest("prefix1"));
        assert_eq!(ann.said, test_digest("said1"));
        assert_eq!(ann.origin, test_digest("origin1"));
    }

    #[test]
    fn test_announcement_from_pubsub_empty_said() {
        let (prefix_str, _, _) = make_qb64_msg();
        let origin_digest = test_digest("origin1");
        let msg = format!("{}:", prefix_str);
        let ann = KelAnnouncement::from_pubsub_message(&msg, &origin_digest);
        assert!(ann.is_none());
    }

    #[test]
    fn test_announcement_serialization() {
        let ann = KelAnnouncement {
            prefix: test_digest("prefix"),
            said: test_digest("said"),
            origin: test_digest("origin"),
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
        let origin = test_digest("origin");
        let ann = KelAnnouncement::from_pubsub_message(msg, &origin);
        assert!(ann.is_none());
    }

    #[test]
    fn test_announcement_from_pubsub_invalid_cesr() {
        // Invalid CESR strings should return None
        let msg = "notcesr:alsonotcesr";
        let origin = test_digest("origin");
        let ann = KelAnnouncement::from_pubsub_message(msg, &origin);
        assert!(ann.is_none());
    }

    #[test]
    fn test_kel_announcement_clone() {
        let ann = KelAnnouncement {
            prefix: test_digest("CLONE"),
            said: test_digest("SAID"),
            origin: test_digest("ORIGIN"),
        };
        let cloned = ann.clone();
        assert_eq!(ann.prefix, cloned.prefix);
        assert_eq!(ann.said, cloned.said);
        assert_eq!(ann.origin, cloned.origin);
    }

    #[test]
    fn test_kel_announcement_debug() {
        let ann = KelAnnouncement {
            prefix: test_digest("DEBUG"),
            said: test_digest("SAID"),
            origin: test_digest("ORIGIN"),
        };
        let debug_str = format!("{:?}", ann);
        assert!(debug_str.contains("Digest"));
    }
}
