//! IEL announcement type for gossip replication.

use serde::{Deserialize, Serialize};

/// Gossip message for an Identity Event Log update.
///
/// Broadcast on topic `kels/gossip/v1/topics/iel`. IEL has no separate
/// object store (every IEL "object" is just an event), so unlike SE there
/// is only one variant — chain-tip announcement.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IelAnnouncement {
    /// The IEL prefix that was updated.
    pub prefix: cesr::Digest256,
    /// The effective SAID of the chain (tip event SAID, or synthetic
    /// `divergent:`/`contested:` hash, or Dec event SAID — see
    /// `IdentityEventRepository::effective_said`).
    pub said: cesr::Digest256,
    /// The peer prefix that originated the announcement.
    pub origin: cesr::Digest256,
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use cesr::test_digest;

    use super::*;

    #[test]
    fn test_iel_announcement_serialization() {
        let ann = IelAnnouncement {
            prefix: test_digest("prefix"),
            said: test_digest("said"),
            origin: test_digest("origin"),
        };
        let json = serde_json::to_string(&ann).unwrap();
        let parsed: IelAnnouncement = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.prefix, ann.prefix);
        assert_eq!(parsed.said, ann.said);
        assert_eq!(parsed.origin, ann.origin);
    }
}
