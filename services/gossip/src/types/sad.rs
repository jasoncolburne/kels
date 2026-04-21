//! SAD announcement types for gossip replication.

use serde::{Deserialize, Serialize};

/// Gossip message types for SAD replication.
///
/// Broadcast on topic `kels/sad/v1`. Tagged enum allows routing both
/// raw SAD object announcements and chain update announcements on a single topic.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub(crate) enum SadAnnouncement {
    /// A new SAD object was stored (content-addressed blob in MinIO).
    Object {
        /// The SAID of the stored object.
        said: cesr::Digest256,
        /// The peer prefix that stored it.
        origin: cesr::Digest256,
    },
    /// A SAD Event Log was updated.
    Event {
        /// The chain prefix that was updated.
        chain_prefix: cesr::Digest256,
        /// The SAID of the latest chain event.
        said: cesr::Digest256,
        /// The peer prefix that stored it.
        origin: cesr::Digest256,
        /// Whether this update is a repair of a previously divergent chain.
        /// When true, the receiving node should fetch the full chain (not a delta)
        /// since repair replaces from the divergence point.
        #[serde(default)]
        repair: bool,
    },
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use cesr::test_digest;

    use super::*;

    #[test]
    fn test_sad_gossip_message_serialization() {
        let object_msg = SadAnnouncement::Object {
            said: test_digest("said123"),
            origin: test_digest("origin"),
        };
        let json = serde_json::to_string(&object_msg).unwrap();
        let parsed: SadAnnouncement = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, SadAnnouncement::Object { .. }));

        let chain_msg = SadAnnouncement::Event {
            chain_prefix: test_digest("prefix"),
            said: test_digest("said456"),
            origin: test_digest("origin"),
            repair: false,
        };
        let json = serde_json::to_string(&chain_msg).unwrap();
        let parsed: SadAnnouncement = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            parsed,
            SadAnnouncement::Event { repair: false, .. }
        ));

        // Repair messages round-trip correctly
        let repair_msg = SadAnnouncement::Event {
            chain_prefix: test_digest("prefix"),
            said: test_digest("said789"),
            origin: test_digest("origin"),
            repair: true,
        };
        let json = serde_json::to_string(&repair_msg).unwrap();
        let parsed: SadAnnouncement = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            parsed,
            SadAnnouncement::Event { repair: true, .. }
        ));

        // Backwards compatibility: messages without repair field default to false
        let without_repair = serde_json::to_string(&SadAnnouncement::Event {
            chain_prefix: test_digest("p"),
            said: test_digest("s"),
            origin: test_digest("o"),
            repair: false,
        })
        .unwrap();
        let legacy_json = without_repair.replace(",\"repair\":false", "");
        let parsed: SadAnnouncement = serde_json::from_str(&legacy_json).unwrap();
        assert!(matches!(
            parsed,
            SadAnnouncement::Event { repair: false, .. }
        ));
    }
}
