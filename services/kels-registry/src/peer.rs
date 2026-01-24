//! Peer model for the authorized peer allowlist
//!
//! Re-exports from the kels library for use in kels-registry.

pub use kels::{Peer, PeerHistory};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_creation() {
        let peer = Peer::create("12D3KooWExample".to_string(), "node-a".to_string(), true).unwrap();

        assert!(peer.active);
        assert_eq!(peer.version, 0);
        assert!(peer.previous.is_none());
        assert!(!peer.said.is_empty());
        // Prefix is derived from content hash, not manually set
        assert!(!peer.prefix.is_empty());
        assert_eq!(peer.prefix, peer.said);
    }

    #[test]
    fn test_peer_deactivation() {
        let peer = Peer::create("12D3KooWExample".to_string(), "node-a".to_string(), true).unwrap();

        let deactivated = peer.deactivate().unwrap();

        assert!(!deactivated.active);
        assert_eq!(deactivated.version, 1);
        assert_eq!(deactivated.previous, Some(peer.said.clone()));
        assert_eq!(deactivated.prefix, peer.prefix);
    }

    #[test]
    fn test_peer_reactivation() {
        let peer = Peer::create("12D3KooWExample".to_string(), "node-a".to_string(), true).unwrap();

        let deactivated = peer.deactivate().unwrap();
        let reactivated = deactivated.reactivate().unwrap();

        assert!(reactivated.active);
        assert_eq!(reactivated.version, 2);
        assert_eq!(reactivated.previous, Some(deactivated.said.clone()));
    }
}
