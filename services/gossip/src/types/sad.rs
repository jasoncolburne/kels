//! SAD announcement types for gossip replication.

use serde::{Deserialize, Serialize};

/// Gossip message types for SAD replication.
///
/// Broadcast on topic `kels/sad/v1`. Tagged enum allows routing both
/// raw SAD object announcements and SEL update announcements on a single topic.
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
        /// The SEL prefix that was updated.
        prefix: cesr::Digest256,
        /// The SAID of the latest SAD event.
        said: cesr::Digest256,
        /// The peer prefix that stored it.
        origin: cesr::Digest256,
    },
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use cesr::test_digest;

    use super::*;

    #[test]
    fn test_sad_announcement_serialization() {
        let object_msg = SadAnnouncement::Object {
            said: test_digest("said123"),
            origin: test_digest("origin"),
        };
        let json = serde_json::to_string(&object_msg).unwrap();
        let parsed: SadAnnouncement = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, SadAnnouncement::Object { .. }));

        let event_announcement = SadAnnouncement::Event {
            prefix: test_digest("prefix"),
            said: test_digest("said456"),
            origin: test_digest("origin"),
        };
        let json = serde_json::to_string(&event_announcement).unwrap();
        let parsed: SadAnnouncement = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, SadAnnouncement::Event { .. }));
    }
}
