//! Protocol message types for KELS gossip.
//!
//! Defines the gossipsub announcement messages for KEL updates.

use serde::{Deserialize, Serialize};

/// Scope indicator for announcement routing.
/// Used for federation bridging between core and regional nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AnnouncementScope {
    /// Core nodes (cross-registry)
    Core,
    /// Regional nodes (same registry only)
    Regional,
}

impl std::fmt::Display for AnnouncementScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnnouncementScope::Core => write!(f, "core"),
            AnnouncementScope::Regional => write!(f, "regional"),
        }
    }
}

/// Gossipsub announcement message
///
/// Bridging rules based on origin→destination:
/// - regional→core: core receives, rebroadcasts as core→core
/// - core→core: core receives, rebroadcasts as core→regional
/// - core→regional: regional receives, no rebroadcast (final)
/// - regional→regional: no rebroadcast (shouldn't happen)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KelAnnouncement {
    /// The KEL prefix that was updated
    pub prefix: String,
    /// The SAID of the latest event
    pub said: String,
    /// Scope of the node that originated this announcement
    pub origin: AnnouncementScope,
    /// Target scope for this announcement
    pub destination: AnnouncementScope,
    /// PeerId of the node sending this announcement (for deduplication)
    pub sender: String,
}

impl KelAnnouncement {
    /// Parse from Redis pub/sub message format "{prefix}:{said}"
    /// Sets origin and destination based on the local node's scope.
    pub fn from_pubsub_message(
        message: &str,
        origin: AnnouncementScope,
        destination: AnnouncementScope,
        sender: String,
    ) -> Option<Self> {
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
            origin,
            destination,
            sender,
        })
    }

    /// Create a new announcement for re-broadcasting with updated origin, destination, and sender.
    pub fn rebroadcast(
        &self,
        origin: AnnouncementScope,
        destination: AnnouncementScope,
        sender: String,
    ) -> Self {
        Self {
            prefix: self.prefix.clone(),
            said: self.said.clone(),
            origin,
            destination,
            sender,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_announcement_from_pubsub() {
        let msg = "Eprefix123:EsaidABC";
        let ann = KelAnnouncement::from_pubsub_message(
            msg,
            AnnouncementScope::Regional,
            AnnouncementScope::Core,
            "sender1".to_string(),
        );
        assert!(ann.is_some());
        let ann = ann.unwrap();
        assert_eq!(ann.prefix, "Eprefix123");
        assert_eq!(ann.said, "EsaidABC");
        assert_eq!(ann.origin, AnnouncementScope::Regional);
        assert_eq!(ann.destination, AnnouncementScope::Core);
        assert_eq!(ann.sender, "sender1");
    }

    #[test]
    fn test_announcement_from_pubsub_empty_said() {
        let msg = "Eprefix123:";
        let ann = KelAnnouncement::from_pubsub_message(
            msg,
            AnnouncementScope::Core,
            AnnouncementScope::Regional,
            "sender1".to_string(),
        );
        assert!(ann.is_none());
    }

    #[test]
    fn test_announcement_serialization() {
        let ann = KelAnnouncement {
            prefix: "Eprefix".to_string(),
            said: "Esaid".to_string(),
            origin: AnnouncementScope::Regional,
            destination: AnnouncementScope::Core,
            sender: "sender1".to_string(),
        };
        let json = serde_json::to_string(&ann).unwrap();
        let parsed: KelAnnouncement = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.prefix, ann.prefix);
        assert_eq!(parsed.said, ann.said);
        assert_eq!(parsed.origin, ann.origin);
        assert_eq!(parsed.destination, ann.destination);
        assert_eq!(parsed.sender, ann.sender);
    }

    #[test]
    fn test_announcement_from_pubsub_no_colon() {
        let msg = "prefixonly";
        let ann = KelAnnouncement::from_pubsub_message(
            msg,
            AnnouncementScope::Core,
            AnnouncementScope::Core,
            "sender1".to_string(),
        );
        assert!(ann.is_none());
    }

    #[test]
    fn test_announcement_from_pubsub_multiple_colons() {
        // splitn(2, ':') means only split on first colon
        let msg = "Eprefix:Esaid:extra:stuff";
        let ann = KelAnnouncement::from_pubsub_message(
            msg,
            AnnouncementScope::Core,
            AnnouncementScope::Regional,
            "sender1".to_string(),
        );
        assert!(ann.is_some());
        let ann = ann.unwrap();
        assert_eq!(ann.prefix, "Eprefix");
        assert_eq!(ann.said, "Esaid:extra:stuff");
        assert_eq!(ann.origin, AnnouncementScope::Core);
        assert_eq!(ann.destination, AnnouncementScope::Regional);
        assert_eq!(ann.sender, "sender1");
    }

    #[test]
    fn test_announcement_rebroadcast() {
        let ann = KelAnnouncement {
            prefix: "Eprefix".to_string(),
            said: "Esaid".to_string(),
            origin: AnnouncementScope::Regional,
            destination: AnnouncementScope::Core,
            sender: "original-sender".to_string(),
        };
        // regional→core received by core, rebroadcast as core→core
        let rebroadcast = ann.rebroadcast(
            AnnouncementScope::Core,
            AnnouncementScope::Core,
            "new-sender".to_string(),
        );
        assert_eq!(rebroadcast.prefix, ann.prefix);
        assert_eq!(rebroadcast.said, ann.said);
        assert_eq!(rebroadcast.origin, AnnouncementScope::Core);
        assert_eq!(rebroadcast.destination, AnnouncementScope::Core);
        assert_eq!(rebroadcast.sender, "new-sender");
    }

    #[test]
    fn test_announcement_scope_display() {
        assert_eq!(format!("{}", AnnouncementScope::Core), "core");
        assert_eq!(format!("{}", AnnouncementScope::Regional), "regional");
    }

    #[test]
    fn test_kel_announcement_clone() {
        let ann = KelAnnouncement {
            prefix: "ECLONE".to_string(),
            said: "ESAID".to_string(),
            origin: AnnouncementScope::Regional,
            destination: AnnouncementScope::Core,
            sender: "sender1".to_string(),
        };
        let cloned = ann.clone();
        assert_eq!(ann.prefix, cloned.prefix);
        assert_eq!(ann.said, cloned.said);
        assert_eq!(ann.origin, cloned.origin);
        assert_eq!(ann.destination, cloned.destination);
        assert_eq!(ann.sender, cloned.sender);
    }

    #[test]
    fn test_kel_announcement_debug() {
        let ann = KelAnnouncement {
            prefix: "EDEBUG".to_string(),
            said: "ESAID".to_string(),
            origin: AnnouncementScope::Core,
            destination: AnnouncementScope::Regional,
            sender: "sender1".to_string(),
        };
        let debug_str = format!("{:?}", ann);
        assert!(debug_str.contains("EDEBUG"));
        assert!(debug_str.contains("ESAID"));
        // Note: Debug shows variant name, serde serializes as lowercase
    }
}
