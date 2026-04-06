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
        said: cesr::Digest,
        /// The peer prefix that stored it.
        origin: cesr::Digest,
    },
    /// A SAD pointer chain was updated.
    Pointer {
        /// The chain prefix that was updated.
        chain_prefix: cesr::Digest,
        /// The SAID of the latest chain pointer.
        said: cesr::Digest,
        /// The peer prefix that stored it.
        origin: cesr::Digest,
        /// Whether this update is a repair of a previously divergent chain.
        /// When true, the receiving node should use `?repair=true` to replace
        /// its local divergent chain.
        #[serde(default)]
        repair: bool,
    },
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_sad_gossip_message_serialization() {
        let object_msg = SadAnnouncement::Object {
            said: cesr::Digest::blake3_256(b"said123"),
            origin: cesr::Digest::blake3_256(b"origin"),
        };
        let json = serde_json::to_string(&object_msg).unwrap();
        let parsed: SadAnnouncement = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, SadAnnouncement::Object { .. }));

        let chain_msg = SadAnnouncement::Pointer {
            chain_prefix: cesr::Digest::blake3_256(b"prefix"),
            said: cesr::Digest::blake3_256(b"said456"),
            origin: cesr::Digest::blake3_256(b"origin"),
            repair: false,
        };
        let json = serde_json::to_string(&chain_msg).unwrap();
        let parsed: SadAnnouncement = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            parsed,
            SadAnnouncement::Pointer { repair: false, .. }
        ));

        // Repair messages round-trip correctly
        let repair_msg = SadAnnouncement::Pointer {
            chain_prefix: cesr::Digest::blake3_256(b"prefix"),
            said: cesr::Digest::blake3_256(b"said789"),
            origin: cesr::Digest::blake3_256(b"origin"),
            repair: true,
        };
        let json = serde_json::to_string(&repair_msg).unwrap();
        let parsed: SadAnnouncement = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            parsed,
            SadAnnouncement::Pointer { repair: true, .. }
        ));

        // Backwards compatibility: messages without repair field default to false
        let without_repair = serde_json::to_string(&SadAnnouncement::Pointer {
            chain_prefix: cesr::Digest::blake3_256(b"p"),
            said: cesr::Digest::blake3_256(b"s"),
            origin: cesr::Digest::blake3_256(b"o"),
            repair: false,
        })
        .unwrap();
        let legacy_json = without_repair.replace(",\"repair\":false", "");
        let parsed: SadAnnouncement = serde_json::from_str(&legacy_json).unwrap();
        assert!(matches!(
            parsed,
            SadAnnouncement::Pointer { repair: false, .. }
        ));
    }
}
