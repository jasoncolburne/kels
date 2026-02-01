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

    #[test]
    fn test_announcement_from_pubsub_no_colon() {
        let msg = "prefixonly";
        let ann = KelAnnouncement::from_pubsub_message(msg);
        assert!(ann.is_none());
    }

    #[test]
    fn test_announcement_from_pubsub_multiple_colons() {
        // splitn(2, ':') means only split on first colon
        let msg = "Eprefix:Esaid:extra:stuff";
        let ann = KelAnnouncement::from_pubsub_message(msg);
        assert!(ann.is_some());
        let ann = ann.unwrap();
        assert_eq!(ann.prefix, "Eprefix");
        assert_eq!(ann.said, "Esaid:extra:stuff");
    }

    #[test]
    fn test_protocol_name_constant() {
        assert_eq!(PROTOCOL_NAME, "/kels/sync/1.0.0");
    }

    // ==================== KelRequest Tests ====================

    #[test]
    fn test_kel_request_serialization() {
        let req = KelRequest {
            prefix: "EPREFIX123".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("EPREFIX123"));
    }

    #[test]
    fn test_kel_request_deserialization() {
        let json = r#"{"prefix": "ETEST"}"#;
        let req: KelRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.prefix, "ETEST");
    }

    #[test]
    fn test_kel_request_roundtrip() {
        let original = KelRequest {
            prefix: "EROUNDTRIP".to_string(),
        };
        let json = serde_json::to_string(&original).unwrap();
        let parsed: KelRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(original.prefix, parsed.prefix);
    }

    // ==================== KelResponse Tests ====================

    #[test]
    fn test_kel_response_empty_events() {
        let resp = KelResponse {
            prefix: "EPREFIX".to_string(),
            events: vec![],
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("EPREFIX"));
        assert!(json.contains("[]"));
    }

    #[test]
    fn test_kel_response_serialization_roundtrip() {
        let resp = KelResponse {
            prefix: "ETEST".to_string(),
            events: vec![],
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: KelResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(resp.prefix, parsed.prefix);
        assert_eq!(resp.events.len(), parsed.events.len());
    }

    // ==================== KelAnnouncement Clone and Debug ====================

    #[test]
    fn test_kel_announcement_clone() {
        let ann = KelAnnouncement {
            prefix: "ECLONE".to_string(),
            said: "ESAID".to_string(),
        };
        let cloned = ann.clone();
        assert_eq!(ann.prefix, cloned.prefix);
        assert_eq!(ann.said, cloned.said);
    }

    #[test]
    fn test_kel_announcement_debug() {
        let ann = KelAnnouncement {
            prefix: "EDEBUG".to_string(),
            said: "ESAID".to_string(),
        };
        let debug_str = format!("{:?}", ann);
        assert!(debug_str.contains("EDEBUG"));
        assert!(debug_str.contains("ESAID"));
    }

    #[test]
    fn test_kel_request_debug() {
        let req = KelRequest {
            prefix: "EDEBUG".to_string(),
        };
        let debug_str = format!("{:?}", req);
        assert!(debug_str.contains("EDEBUG"));
    }

    #[test]
    fn test_kel_response_debug() {
        let resp = KelResponse {
            prefix: "EDEBUG".to_string(),
            events: vec![],
        };
        let debug_str = format!("{:?}", resp);
        assert!(debug_str.contains("EDEBUG"));
    }
}
