//! KELS types for API requests and responses

mod error;
mod events;
mod kel;
mod node;
mod peer;
mod raft;
mod sync;

pub use error::*;
pub use events::*;
pub use kel::*;
pub use node::*;
pub use peer::*;
pub use raft::*;
pub use sync::*;

#[cfg(test)]
mod tests {
    use verifiable_storage::Chained;

    use super::*;

    #[test]
    fn test_event_kind_serialization() {
        assert_eq!(EventKind::Icp.as_str(), "icp");
        assert_eq!(EventKind::Dip.as_str(), "dip");
        assert_eq!(EventKind::Rot.as_str(), "rot");
        assert_eq!(EventKind::Ixn.as_str(), "ixn");
        assert_eq!(EventKind::Rec.as_str(), "rec");
        assert_eq!(EventKind::Ror.as_str(), "ror");
        assert_eq!(EventKind::Dec.as_str(), "dec");
        assert_eq!(EventKind::Cnt.as_str(), "cnt");
    }

    #[test]
    fn test_event_kind_parsing() {
        use std::str::FromStr;
        assert_eq!(EventKind::from_str("icp").unwrap(), EventKind::Icp);
        assert_eq!(EventKind::from_str("ICP").unwrap(), EventKind::Icp);
        assert_eq!(EventKind::from_str("cnt").unwrap(), EventKind::Cnt);
        assert!(EventKind::from_str("invalid").is_err());
    }

    #[test]
    fn test_event_kind_properties() {
        assert!(EventKind::Icp.is_inception());
        assert!(EventKind::Dip.is_inception());
        assert!(!EventKind::Rot.is_inception());
        assert!(EventKind::Icp.is_establishment());
        assert!(!EventKind::Ixn.is_establishment());
        assert!(EventKind::Rec.reveals_recovery_key());
        assert!(EventKind::Ror.reveals_recovery_key());
        assert!(EventKind::Dec.reveals_recovery_key());
        assert!(EventKind::Cnt.reveals_recovery_key());
        assert!(!EventKind::Rot.reveals_recovery_key());
        assert!(EventKind::Dec.decommissions());
        assert!(EventKind::Cnt.decommissions());
        assert!(!EventKind::Rec.decommissions());
    }

    #[test]
    fn test_event_kind_json() {
        let json = serde_json::to_string(&EventKind::Icp).unwrap();
        assert_eq!(json, "\"icp\"");
        let parsed: EventKind = serde_json::from_str("\"rec\"").unwrap();
        assert_eq!(parsed, EventKind::Rec);
    }

    #[test]
    fn test_peer_creation() {
        let peer = Peer::create(
            "12D3KooWExample".to_string(),
            "node-a".to_string(),
            "EAuthorizingKel_____________________________".to_string(),
            true,
            PeerScope::Regional,
            "http://node-a:8080".to_string(),
            "/ip4/127.0.0.1/tcp/4001".to_string(),
        )
        .unwrap();

        assert!(peer.active);
        assert_eq!(peer.version, 0);
        assert!(peer.previous.is_none());
        assert!(!peer.said.is_empty());
        // Prefix is derived from content hash, not manually set
        assert!(!peer.prefix.is_empty());
        assert_eq!(peer.scope, PeerScope::Regional);
        assert_eq!(peer.kels_url, "http://node-a:8080");
        assert_eq!(peer.gossip_multiaddr, "/ip4/127.0.0.1/tcp/4001");
    }

    #[test]
    fn test_peer_creation_with_core_scope() {
        let peer = Peer::create(
            "12D3KooWExample".to_string(),
            "node-b".to_string(),
            "EAuthorizingKel_____________________________".to_string(),
            true,
            PeerScope::Core,
            "http://node-b:8080".to_string(),
            "/ip4/127.0.0.1/tcp/4002".to_string(),
        )
        .unwrap();

        assert_eq!(peer.scope, PeerScope::Core);
    }

    #[test]
    fn test_peer_deactivation() {
        let peer = Peer::create(
            "12D3KooWExample".to_string(),
            "node-a".to_string(),
            "EAuthorizingKel_____________________________".to_string(),
            true,
            PeerScope::Regional,
            "http://node-a:8080".to_string(),
            "/ip4/127.0.0.1/tcp/4001".to_string(),
        )
        .unwrap();

        let deactivated = peer.deactivate().unwrap();

        assert!(!deactivated.active);
        assert_eq!(deactivated.version, 1);
        assert_eq!(deactivated.previous, Some(peer.said.clone()));
        assert_eq!(deactivated.prefix, peer.prefix);
    }

    // ==================== Test Helpers ====================

    fn make_blake3_digest(data: &str) -> String {
        use cesr::{Digest, Matter};
        Digest::blake3_256(data.as_bytes()).qb64()
    }

    fn make_secp256r1_key() -> String {
        use cesr::{KeyCode, Matter, PublicKey};
        // Valid compressed secp256r1 public key (33 bytes)
        let key_bytes = [
            0x02, // compressed prefix
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        PublicKey::from_raw(KeyCode::Secp256r1, key_bytes.to_vec())
            .unwrap()
            .qb64()
    }

    fn make_valid_icp() -> KeyEvent {
        KeyEvent {
            kind: EventKind::Icp,
            said: make_blake3_digest("said"),
            prefix: make_blake3_digest("prefix"),
            previous: None,
            public_key: Some(make_secp256r1_key()),
            rotation_hash: Some(make_blake3_digest("rotation")),
            recovery_hash: Some(make_blake3_digest("recovery")),
            recovery_key: None,
            anchor: None,
            delegating_prefix: None,
        }
    }

    // ==================== validate_structure tests ====================

    #[test]
    fn test_validate_structure_valid_icp() {
        let event = make_valid_icp();
        assert!(event.validate_structure().is_ok());
    }

    #[test]
    fn test_validate_structure_icp_missing_public_key() {
        let mut event = make_valid_icp();
        event.public_key = None;
        let err = event.validate_structure().unwrap_err();
        assert!(err.contains("requires publicKey"));
    }

    #[test]
    fn test_validate_structure_icp_missing_rotation_hash() {
        let mut event = make_valid_icp();
        event.rotation_hash = None;
        let err = event.validate_structure().unwrap_err();
        assert!(err.contains("requires rotationHash"));
    }

    #[test]
    fn test_validate_structure_icp_missing_recovery_hash() {
        let mut event = make_valid_icp();
        event.recovery_hash = None;
        let err = event.validate_structure().unwrap_err();
        assert!(err.contains("requires recoveryHash"));
    }

    #[test]
    fn test_validate_structure_icp_forbids_previous() {
        let mut event = make_valid_icp();
        event.previous = Some(make_blake3_digest("prev"));
        let err = event.validate_structure().unwrap_err();
        assert!(err.contains("must not have previous"));
    }

    #[test]
    fn test_validate_structure_icp_forbids_recovery_key() {
        let mut event = make_valid_icp();
        event.recovery_key = Some(make_secp256r1_key());
        let err = event.validate_structure().unwrap_err();
        assert!(err.contains("must not have recoveryKey"));
    }

    #[test]
    fn test_validate_structure_icp_forbids_anchor() {
        let mut event = make_valid_icp();
        event.anchor = Some(make_blake3_digest("anchor"));
        let err = event.validate_structure().unwrap_err();
        assert!(err.contains("must not have anchor"));
    }

    #[test]
    fn test_validate_structure_valid_dip() {
        let mut event = make_valid_icp();
        event.kind = EventKind::Dip;
        event.delegating_prefix = Some(make_blake3_digest("delegator"));
        assert!(event.validate_structure().is_ok());
    }

    #[test]
    fn test_validate_structure_dip_requires_delegating_prefix() {
        let mut event = make_valid_icp();
        event.kind = EventKind::Dip;
        // Missing delegating_prefix
        let err = event.validate_structure().unwrap_err();
        assert!(err.contains("requires delegatingPrefix"));
    }

    #[test]
    fn test_validate_structure_valid_rot() {
        let event = KeyEvent {
            kind: EventKind::Rot,
            said: make_blake3_digest("said"),
            prefix: make_blake3_digest("prefix"),
            previous: Some(make_blake3_digest("prev")),
            public_key: Some(make_secp256r1_key()),
            rotation_hash: Some(make_blake3_digest("rotation")),
            recovery_hash: None,
            recovery_key: None,
            anchor: None,
            delegating_prefix: None,
        };
        assert!(event.validate_structure().is_ok());
    }

    #[test]
    fn test_validate_structure_rot_missing_previous() {
        let event = KeyEvent {
            kind: EventKind::Rot,
            said: make_blake3_digest("said"),
            prefix: make_blake3_digest("prefix"),
            previous: None,
            public_key: Some(make_secp256r1_key()),
            rotation_hash: Some(make_blake3_digest("rotation")),
            recovery_hash: None,
            recovery_key: None,
            anchor: None,
            delegating_prefix: None,
        };
        let err = event.validate_structure().unwrap_err();
        assert!(err.contains("requires previous"));
    }

    #[test]
    fn test_validate_structure_valid_ixn() {
        let event = KeyEvent {
            kind: EventKind::Ixn,
            said: make_blake3_digest("said"),
            prefix: make_blake3_digest("prefix"),
            previous: Some(make_blake3_digest("prev")),
            public_key: None,
            rotation_hash: None,
            recovery_hash: None,
            recovery_key: None,
            anchor: Some(make_blake3_digest("anchor")),
            delegating_prefix: None,
        };
        assert!(event.validate_structure().is_ok());
    }

    #[test]
    fn test_validate_structure_ixn_forbids_public_key() {
        let event = KeyEvent {
            kind: EventKind::Ixn,
            said: make_blake3_digest("said"),
            prefix: make_blake3_digest("prefix"),
            previous: Some(make_blake3_digest("prev")),
            public_key: Some(make_secp256r1_key()),
            rotation_hash: None,
            recovery_hash: None,
            recovery_key: None,
            anchor: Some(make_blake3_digest("anchor")),
            delegating_prefix: None,
        };
        let err = event.validate_structure().unwrap_err();
        assert!(err.contains("must not have publicKey"));
    }

    #[test]
    fn test_validate_structure_valid_rec() {
        let event = KeyEvent {
            kind: EventKind::Rec,
            said: make_blake3_digest("said"),
            prefix: make_blake3_digest("prefix"),
            previous: Some(make_blake3_digest("prev")),
            public_key: Some(make_secp256r1_key()),
            rotation_hash: Some(make_blake3_digest("rotation")),
            recovery_hash: Some(make_blake3_digest("recovery")),
            recovery_key: Some(make_secp256r1_key()),
            anchor: None,
            delegating_prefix: None,
        };
        assert!(event.validate_structure().is_ok());
    }

    #[test]
    fn test_validate_structure_rec_missing_recovery_key() {
        let event = KeyEvent {
            kind: EventKind::Rec,
            said: make_blake3_digest("said"),
            prefix: make_blake3_digest("prefix"),
            previous: Some(make_blake3_digest("prev")),
            public_key: Some(make_secp256r1_key()),
            rotation_hash: Some(make_blake3_digest("rotation")),
            recovery_hash: Some(make_blake3_digest("recovery")),
            recovery_key: None,
            anchor: None,
            delegating_prefix: None,
        };
        let err = event.validate_structure().unwrap_err();
        assert!(err.contains("requires recoveryKey"));
    }

    #[test]
    fn test_validate_structure_valid_dec() {
        let event = KeyEvent {
            kind: EventKind::Dec,
            said: make_blake3_digest("said"),
            prefix: make_blake3_digest("prefix"),
            previous: Some(make_blake3_digest("prev")),
            public_key: Some(make_secp256r1_key()),
            rotation_hash: None,
            recovery_hash: None,
            recovery_key: Some(make_secp256r1_key()),
            anchor: None,
            delegating_prefix: None,
        };
        assert!(event.validate_structure().is_ok());
    }

    #[test]
    fn test_validate_structure_dec_forbids_rotation_hash() {
        let event = KeyEvent {
            kind: EventKind::Dec,
            said: make_blake3_digest("said"),
            prefix: make_blake3_digest("prefix"),
            previous: Some(make_blake3_digest("prev")),
            public_key: Some(make_secp256r1_key()),
            rotation_hash: Some(make_blake3_digest("rotation")),
            recovery_hash: None,
            recovery_key: Some(make_secp256r1_key()),
            anchor: None,
            delegating_prefix: None,
        };
        let err = event.validate_structure().unwrap_err();
        assert!(err.contains("must not have rotationHash"));
    }

    #[test]
    fn test_validate_structure_self_referencing_previous() {
        let said = make_blake3_digest("said");
        let event = KeyEvent {
            kind: EventKind::Rot,
            said: said.clone(),
            prefix: make_blake3_digest("prefix"),
            previous: Some(said), // Same as said - circular!
            public_key: Some(make_secp256r1_key()),
            rotation_hash: Some(make_blake3_digest("rotation")),
            recovery_hash: None,
            recovery_key: None,
            anchor: None,
            delegating_prefix: None,
        };
        let err = event.validate_structure().unwrap_err();
        assert!(err.contains("self-referencing"));
    }

    #[test]
    fn test_validate_structure_invalid_said_format() {
        let mut event = make_valid_icp();
        event.said = "not_a_valid_cesr_digest".to_string();
        let err = event.validate_structure().unwrap_err();
        assert!(err.contains("not a valid CESR digest"));
    }

    #[test]
    fn test_validate_structure_invalid_public_key_format() {
        let mut event = make_valid_icp();
        event.public_key = Some("not_a_valid_key".to_string());
        let err = event.validate_structure().unwrap_err();
        assert!(err.contains("not a valid CESR public key"));
    }

    // ==================== SignedKeyEvent tests ====================

    #[test]
    fn test_signed_key_event_equality_same_said() {
        let event = make_valid_icp();
        let sig1 = KeyEventSignature {
            public_key: "key1".to_string(),
            signature: "sig1".to_string(),
        };
        let sig2 = KeyEventSignature {
            public_key: "key2".to_string(),
            signature: "sig2".to_string(),
        };

        let signed1 = SignedKeyEvent {
            event: event.clone(),
            signatures: vec![sig1.clone(), sig2.clone()],
        };
        let signed2 = SignedKeyEvent {
            event: event.clone(),
            signatures: vec![sig2, sig1], // Different order
        };

        // Same SAID = equal (signature order doesn't matter)
        assert_eq!(signed1, signed2);
    }

    #[test]
    fn test_signed_key_event_equality_different_said() {
        let event1 = make_valid_icp();
        let mut event2 = make_valid_icp();
        event2.said = make_blake3_digest("different");

        let sig = KeyEventSignature {
            public_key: "key".to_string(),
            signature: "sig".to_string(),
        };

        let signed1 = SignedKeyEvent {
            event: event1,
            signatures: vec![sig.clone()],
        };
        let signed2 = SignedKeyEvent {
            event: event2,
            signatures: vec![sig],
        };

        assert_ne!(signed1, signed2);
    }

    #[test]
    fn test_signed_key_event_signature_lookup() {
        let event = make_valid_icp();
        let sig1 = KeyEventSignature {
            public_key: "key1".to_string(),
            signature: "sig1".to_string(),
        };
        let sig2 = KeyEventSignature {
            public_key: "key2".to_string(),
            signature: "sig2".to_string(),
        };

        let signed = SignedKeyEvent {
            event,
            signatures: vec![sig1.clone(), sig2.clone()],
        };

        assert_eq!(
            signed.signature("key1").map(|s| &s.signature),
            Some(&"sig1".to_string())
        );
        assert_eq!(
            signed.signature("key2").map(|s| &s.signature),
            Some(&"sig2".to_string())
        );
        assert!(signed.signature("key3").is_none());
    }

    // ==================== KeyEvent predicate tests ====================

    #[test]
    fn test_key_event_requires_dual_signature() {
        assert!(
            KeyEvent {
                kind: EventKind::Rec,
                ..make_valid_icp()
            }
            .requires_dual_signature()
        );
        assert!(
            KeyEvent {
                kind: EventKind::Ror,
                ..make_valid_icp()
            }
            .requires_dual_signature()
        );
        assert!(
            KeyEvent {
                kind: EventKind::Dec,
                ..make_valid_icp()
            }
            .requires_dual_signature()
        );
        assert!(
            KeyEvent {
                kind: EventKind::Cnt,
                ..make_valid_icp()
            }
            .requires_dual_signature()
        );
        assert!(!make_valid_icp().requires_dual_signature());
        assert!(
            !KeyEvent {
                kind: EventKind::Rot,
                ..make_valid_icp()
            }
            .requires_dual_signature()
        );
    }

    #[test]
    fn test_key_event_is_inception() {
        assert!(make_valid_icp().is_inception());
        assert!(
            !KeyEvent {
                kind: EventKind::Rot,
                ..make_valid_icp()
            }
            .is_inception()
        );
    }

    #[test]
    fn test_key_event_is_delegated_inception() {
        assert!(
            KeyEvent {
                kind: EventKind::Dip,
                ..make_valid_icp()
            }
            .is_delegated_inception()
        );
        assert!(!make_valid_icp().is_delegated_inception());
    }

    #[test]
    fn test_key_event_is_establishment() {
        assert!(make_valid_icp().is_establishment());
        assert!(
            KeyEvent {
                kind: EventKind::Rot,
                ..make_valid_icp()
            }
            .is_establishment()
        );
        assert!(
            !KeyEvent {
                kind: EventKind::Ixn,
                ..make_valid_icp()
            }
            .is_establishment()
        );
    }

    // ==================== EventKind tests ====================

    #[test]
    fn test_event_kind_as_str() {
        assert_eq!(EventKind::Icp.as_str(), "icp");
        assert_eq!(EventKind::Dip.as_str(), "dip");
        assert_eq!(EventKind::Rot.as_str(), "rot");
        assert_eq!(EventKind::Ixn.as_str(), "ixn");
        assert_eq!(EventKind::Rec.as_str(), "rec");
        assert_eq!(EventKind::Ror.as_str(), "ror");
        assert_eq!(EventKind::Dec.as_str(), "dec");
        assert_eq!(EventKind::Cnt.as_str(), "cnt");
    }

    #[test]
    fn test_event_kind_display() {
        assert_eq!(format!("{}", EventKind::Icp), "icp");
        assert_eq!(format!("{}", EventKind::Cnt), "cnt");
    }

    #[test]
    fn test_event_kind_from_str() {
        assert_eq!("icp".parse::<EventKind>().unwrap(), EventKind::Icp);
        assert_eq!("ICP".parse::<EventKind>().unwrap(), EventKind::Icp);
        assert_eq!("dip".parse::<EventKind>().unwrap(), EventKind::Dip);
        assert_eq!("rot".parse::<EventKind>().unwrap(), EventKind::Rot);
        assert_eq!("ixn".parse::<EventKind>().unwrap(), EventKind::Ixn);
        assert_eq!("rec".parse::<EventKind>().unwrap(), EventKind::Rec);
        assert_eq!("ror".parse::<EventKind>().unwrap(), EventKind::Ror);
        assert_eq!("dec".parse::<EventKind>().unwrap(), EventKind::Dec);
        assert_eq!("cnt".parse::<EventKind>().unwrap(), EventKind::Cnt);
    }

    #[test]
    fn test_event_kind_from_str_invalid() {
        let result = "invalid".parse::<EventKind>();
        assert!(result.is_err());
    }

    #[test]
    fn test_event_kind_is_inception() {
        assert!(EventKind::Icp.is_inception());
        assert!(EventKind::Dip.is_inception());
        assert!(!EventKind::Rot.is_inception());
        assert!(!EventKind::Ixn.is_inception());
    }

    #[test]
    fn test_event_kind_decommissions() {
        assert!(EventKind::Dec.decommissions());
        assert!(EventKind::Cnt.decommissions());
        assert!(!EventKind::Icp.decommissions());
        assert!(!EventKind::Rec.decommissions());
    }

    #[test]
    fn test_event_kind_reveals_rotation_key() {
        assert!(EventKind::Rot.reveals_rotation_key());
        assert!(EventKind::Rec.reveals_rotation_key());
        assert!(EventKind::Ror.reveals_rotation_key());
        assert!(!EventKind::Icp.reveals_rotation_key());
        assert!(!EventKind::Ixn.reveals_rotation_key());
    }

    #[test]
    fn test_event_kind_reveals_recovery_key() {
        assert!(EventKind::Rec.reveals_recovery_key());
        assert!(EventKind::Ror.reveals_recovery_key());
        assert!(EventKind::Dec.reveals_recovery_key());
        assert!(EventKind::Cnt.reveals_recovery_key());
        assert!(!EventKind::Icp.reveals_recovery_key());
        assert!(!EventKind::Rot.reveals_recovery_key());
    }

    // ==================== More KeyEvent predicate tests ====================

    #[test]
    fn test_key_event_is_rotation() {
        assert!(
            KeyEvent {
                kind: EventKind::Rot,
                ..make_valid_icp()
            }
            .is_rotation()
        );
        assert!(!make_valid_icp().is_rotation());
    }

    #[test]
    fn test_key_event_is_recover() {
        assert!(
            KeyEvent {
                kind: EventKind::Rec,
                ..make_valid_icp()
            }
            .is_recover()
        );
        assert!(!make_valid_icp().is_recover());
    }

    #[test]
    fn test_key_event_is_recovery_rotation() {
        assert!(
            KeyEvent {
                kind: EventKind::Ror,
                ..make_valid_icp()
            }
            .is_recovery_rotation()
        );
        assert!(!make_valid_icp().is_recovery_rotation());
    }

    #[test]
    fn test_key_event_is_decommission() {
        assert!(
            KeyEvent {
                kind: EventKind::Dec,
                ..make_valid_icp()
            }
            .is_decommission()
        );
        assert!(!make_valid_icp().is_decommission());
    }

    #[test]
    fn test_key_event_is_contest() {
        assert!(
            KeyEvent {
                kind: EventKind::Cnt,
                ..make_valid_icp()
            }
            .is_contest()
        );
        assert!(!make_valid_icp().is_contest());
    }

    #[test]
    fn test_key_event_is_interaction() {
        assert!(
            KeyEvent {
                kind: EventKind::Ixn,
                ..make_valid_icp()
            }
            .is_interaction()
        );
        assert!(!make_valid_icp().is_interaction());
    }

    #[test]
    fn test_key_event_reveals_rotation_key() {
        assert!(
            KeyEvent {
                kind: EventKind::Rot,
                ..make_valid_icp()
            }
            .reveals_rotation_key()
        );
        assert!(!make_valid_icp().reveals_rotation_key());
    }

    #[test]
    fn test_key_event_reveals_recovery_key() {
        assert!(
            KeyEvent {
                kind: EventKind::Rec,
                ..make_valid_icp()
            }
            .reveals_recovery_key()
        );
        assert!(!make_valid_icp().reveals_recovery_key());
    }

    #[test]
    fn test_key_event_has_recovery_hash() {
        assert!(make_valid_icp().has_recovery_hash());
        let mut event = make_valid_icp();
        event.recovery_hash = None;
        assert!(!event.has_recovery_hash());
    }

    #[test]
    fn test_key_event_decommissions() {
        assert!(
            KeyEvent {
                kind: EventKind::Dec,
                ..make_valid_icp()
            }
            .decommissions()
        );
        assert!(
            KeyEvent {
                kind: EventKind::Cnt,
                ..make_valid_icp()
            }
            .decommissions()
        );
        assert!(!make_valid_icp().decommissions());
    }

    // ==================== SignedKeyEvent additional tests ====================

    #[test]
    fn test_signed_key_event_new() {
        let event = make_valid_icp();
        let signed = SignedKeyEvent::new(event.clone(), "pubkey".to_string(), "sig".to_string());
        assert_eq!(signed.event.said, event.said);
        assert_eq!(signed.signatures.len(), 1);
        assert_eq!(signed.signatures[0].public_key, "pubkey");
        assert_eq!(signed.signatures[0].signature, "sig");
    }

    #[test]
    fn test_signed_key_event_new_recovery() {
        let event = make_valid_icp();
        let signed = SignedKeyEvent::new_recovery(
            event.clone(),
            "primary_key".to_string(),
            "primary_sig".to_string(),
            "recovery_key".to_string(),
            "recovery_sig".to_string(),
        );
        assert_eq!(signed.signatures.len(), 2);
        assert_eq!(signed.signatures[0].public_key, "primary_key");
        assert_eq!(signed.signatures[1].public_key, "recovery_key");
    }

    #[test]
    fn test_signed_key_event_from_signatures() {
        let event = make_valid_icp();
        let sigs = vec![
            ("key1".to_string(), "sig1".to_string()),
            ("key2".to_string(), "sig2".to_string()),
        ];
        let signed = SignedKeyEvent::from_signatures(event, sigs);
        assert_eq!(signed.signatures.len(), 2);
        assert_eq!(signed.signatures[0].public_key, "key1");
        assert_eq!(signed.signatures[1].signature, "sig2");
    }

    #[test]
    fn test_signed_key_event_hash() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let event = make_valid_icp();
        let signed = SignedKeyEvent::new(event, "key".to_string(), "sig".to_string());

        let mut hasher = DefaultHasher::new();
        signed.hash(&mut hasher);
        let hash1 = hasher.finish();

        // Same event should produce same hash
        let signed2 = signed.clone();
        let mut hasher2 = DefaultHasher::new();
        signed2.hash(&mut hasher2);
        let hash2 = hasher2.finish();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_signed_key_event_equality_different_signature_count() {
        let event = make_valid_icp();
        let sig = KeyEventSignature {
            public_key: "key".to_string(),
            signature: "sig".to_string(),
        };

        let signed1 = SignedKeyEvent {
            event: event.clone(),
            signatures: vec![sig.clone()],
        };
        let signed2 = SignedKeyEvent {
            event,
            signatures: vec![sig.clone(), sig],
        };

        assert_ne!(signed1, signed2);
    }

    #[test]
    fn test_signed_key_event_equality_different_signatures() {
        let event = make_valid_icp();

        let signed1 = SignedKeyEvent {
            event: event.clone(),
            signatures: vec![KeyEventSignature {
                public_key: "key".to_string(),
                signature: "sig1".to_string(),
            }],
        };
        let signed2 = SignedKeyEvent {
            event,
            signatures: vec![KeyEventSignature {
                public_key: "key".to_string(),
                signature: "sig2".to_string(),
            }],
        };

        assert_ne!(signed1, signed2);
    }

    // ==================== Validate structure additional tests ====================

    #[test]
    fn test_validate_structure_dip_complete() {
        let event = KeyEvent {
            kind: EventKind::Dip,
            said: make_blake3_digest("said"),
            prefix: make_blake3_digest("prefix"),
            previous: None,
            public_key: Some(make_secp256r1_key()),
            rotation_hash: Some(make_blake3_digest("rotation")),
            recovery_hash: Some(make_blake3_digest("recovery")),
            recovery_key: None,
            anchor: None,
            delegating_prefix: Some(make_blake3_digest("delegator")),
        };
        assert!(event.validate_structure().is_ok());
    }

    #[test]
    fn test_validate_structure_dip_missing_delegating_prefix() {
        let event = KeyEvent {
            kind: EventKind::Dip,
            said: make_blake3_digest("said"),
            prefix: make_blake3_digest("prefix"),
            previous: None,
            public_key: Some(make_secp256r1_key()),
            rotation_hash: Some(make_blake3_digest("rotation")),
            recovery_hash: Some(make_blake3_digest("recovery")),
            recovery_key: None,
            anchor: None,
            delegating_prefix: None,
        };
        let err = event.validate_structure().unwrap_err();
        assert!(err.contains("requires delegatingPrefix"));
    }

    #[test]
    fn test_validate_structure_valid_ror() {
        let event = KeyEvent {
            kind: EventKind::Ror,
            said: make_blake3_digest("said"),
            prefix: make_blake3_digest("prefix"),
            previous: Some(make_blake3_digest("prev")),
            public_key: Some(make_secp256r1_key()),
            rotation_hash: Some(make_blake3_digest("rotation")),
            recovery_hash: Some(make_blake3_digest("recovery")),
            recovery_key: Some(make_secp256r1_key()),
            anchor: None,
            delegating_prefix: None,
        };
        assert!(event.validate_structure().is_ok());
    }

    #[test]
    fn test_validate_structure_valid_cnt() {
        let event = KeyEvent {
            kind: EventKind::Cnt,
            said: make_blake3_digest("said"),
            prefix: make_blake3_digest("prefix"),
            previous: Some(make_blake3_digest("prev")),
            public_key: Some(make_secp256r1_key()),
            rotation_hash: None,
            recovery_hash: None,
            recovery_key: Some(make_secp256r1_key()),
            anchor: None,
            delegating_prefix: None,
        };
        assert!(event.validate_structure().is_ok());
    }

    // ==================== NodeInfo tests ====================

    #[test]
    fn test_node_info_from_registration() {
        let reg = NodeRegistration {
            node_id: "node1".to_string(),
            node_type: NodeType::Kels,
            kels_url: "http://localhost:8080".to_string(),
            gossip_multiaddr: "/ip4/127.0.0.1/tcp/9000".to_string(),
            registered_at: chrono::Utc::now(),
            last_heartbeat: chrono::Utc::now(),
            status: NodeStatus::Ready,
        };

        let info: NodeInfo = reg.into();
        assert_eq!(info.node_id, "node1");
        assert_eq!(info.kels_url, "http://localhost:8080");
        assert_eq!(info.status, NodeStatus::Ready);
        assert!(info.latency_ms.is_none());
    }

    // ==================== BatchSubmitResponse tests ====================

    #[test]
    fn test_batch_submit_response_accepted() {
        let response = BatchSubmitResponse {
            accepted: true,
            diverged_at: None,
        };
        assert!(response.accepted);
        assert!(response.diverged_at.is_none());
    }

    #[test]
    fn test_batch_submit_response_diverged() {
        let response = BatchSubmitResponse {
            accepted: false,
            diverged_at: Some(5),
        };
        assert!(!response.accepted);
        assert_eq!(response.diverged_at, Some(5));
    }

    // ==================== Raft types tests ====================

    #[test]
    fn test_raft_vote_create() {
        let vote = RaftVote::create(1, 5, Some(2), false).unwrap();
        assert!(!vote.said.is_empty());
        assert!(!vote.prefix.is_empty());
        assert!(vote.previous.is_none());
        assert_eq!(vote.version, 0);
        assert_eq!(vote.node_id, 1);
        assert_eq!(vote.term, 5);
        assert_eq!(vote.voted_for, Some(2));
        assert!(!vote.committed);
    }

    #[test]
    fn test_raft_vote_create_no_vote() {
        let vote = RaftVote::create(1, 3, None, true).unwrap();
        assert_eq!(vote.voted_for, None);
        assert!(vote.committed);
    }

    #[test]
    fn test_raft_vote_increment() {
        let mut vote = RaftVote::create(1, 5, Some(2), false).unwrap();
        let original_said = vote.said.clone();
        let original_prefix = vote.prefix.clone();
        let original_version = vote.version;

        vote.term = 6;
        vote.voted_for = Some(3);
        vote.increment().unwrap();

        assert_ne!(vote.said, original_said);
        assert_eq!(vote.prefix, original_prefix);
        assert_eq!(vote.previous, Some(original_said));
        assert_eq!(vote.version, original_version + 1);
    }

    #[test]
    fn test_raft_vote_json_roundtrip() {
        let vote = RaftVote::create(42, 100, Some(5), true).unwrap();
        let json = serde_json::to_string(&vote).unwrap();
        let parsed: RaftVote = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.said, vote.said);
        assert_eq!(parsed.prefix, vote.prefix);
        assert_eq!(parsed.node_id, vote.node_id);
        assert_eq!(parsed.term, vote.term);
        assert_eq!(parsed.voted_for, vote.voted_for);
        assert_eq!(parsed.committed, vote.committed);
    }

    #[test]
    fn test_raft_log_entry_create() {
        let entry = RaftLogEntry::create(
            1,
            10,
            5,
            2,
            "normal".to_string(),
            Some("payload".to_string()),
        )
        .unwrap();

        assert!(!entry.said.is_empty());
        assert!(!entry.prefix.is_empty());
        assert!(entry.previous.is_none());
        assert_eq!(entry.version, 0);
        assert_eq!(entry.node_id, 1);
        assert_eq!(entry.log_index, 10);
        assert_eq!(entry.term, 5);
        assert_eq!(entry.leader_node_id, 2);
        assert_eq!(entry.payload_type, "normal");
        assert_eq!(entry.payload_data, Some("payload".to_string()));
    }

    #[test]
    fn test_raft_log_entry_create_blank() {
        let entry = RaftLogEntry::create(1, 0, 1, 0, "blank".to_string(), None).unwrap();

        assert_eq!(entry.payload_type, "blank");
        assert_eq!(entry.payload_data, None);
    }

    #[test]
    fn test_raft_log_entry_increment() {
        let mut entry =
            RaftLogEntry::create(1, 10, 5, 2, "normal".to_string(), Some("data".to_string()))
                .unwrap();
        let original_said = entry.said.clone();

        entry.log_index = 11;
        entry.term = 6;
        entry.increment().unwrap();

        assert_ne!(entry.said, original_said);
        assert_eq!(entry.previous, Some(original_said));
        assert_eq!(entry.version, 1);
    }

    #[test]
    fn test_raft_log_entry_json_roundtrip() {
        let entry =
            RaftLogEntry::create(2, 5, 3, 1, "membership".to_string(), Some("{}".to_string()))
                .unwrap();
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: RaftLogEntry = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.said, entry.said);
        assert_eq!(parsed.node_id, entry.node_id);
        assert_eq!(parsed.log_index, entry.log_index);
        assert_eq!(parsed.term, entry.term);
        assert_eq!(parsed.leader_node_id, entry.leader_node_id);
        assert_eq!(parsed.payload_type, entry.payload_type);
        assert_eq!(parsed.payload_data, entry.payload_data);
    }

    #[test]
    fn test_raft_state_create() {
        let state =
            RaftState::create(1, Some(5), Some(3), Some(2), Some(10), Some(4), Some(1)).unwrap();

        assert!(!state.said.is_empty());
        assert!(!state.prefix.is_empty());
        assert_eq!(state.node_id, 1);
        assert_eq!(state.last_purged_index, Some(5));
        assert_eq!(state.last_purged_term, Some(3));
        assert_eq!(state.last_purged_node_id, Some(2));
        assert_eq!(state.committed_index, Some(10));
        assert_eq!(state.committed_term, Some(4));
        assert_eq!(state.committed_node_id, Some(1));
    }

    #[test]
    fn test_raft_state_create_empty() {
        let state = RaftState::create(1, None, None, None, None, None, None).unwrap();

        assert_eq!(state.last_purged_index, None);
        assert_eq!(state.last_purged_term, None);
        assert_eq!(state.last_purged_node_id, None);
        assert_eq!(state.committed_index, None);
        assert_eq!(state.committed_term, None);
        assert_eq!(state.committed_node_id, None);
    }

    #[test]
    fn test_raft_state_increment() {
        let mut state = RaftState::create(1, None, None, None, None, None, None).unwrap();
        let original_said = state.said.clone();

        state.last_purged_index = Some(3);
        state.last_purged_term = Some(2);
        state.increment().unwrap();

        assert_ne!(state.said, original_said);
        assert_eq!(state.previous, Some(original_said));
        assert_eq!(state.version, 1);
    }

    #[test]
    fn test_raft_state_json_roundtrip() {
        let state = RaftState::create(
            5,
            Some(100),
            Some(50),
            Some(3),
            Some(150),
            Some(55),
            Some(4),
        )
        .unwrap();
        let json = serde_json::to_string(&state).unwrap();
        let parsed: RaftState = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.said, state.said);
        assert_eq!(parsed.node_id, state.node_id);
        assert_eq!(parsed.last_purged_index, state.last_purged_index);
        assert_eq!(parsed.last_purged_term, state.last_purged_term);
        assert_eq!(parsed.last_purged_node_id, state.last_purged_node_id);
        assert_eq!(parsed.committed_index, state.committed_index);
        assert_eq!(parsed.committed_term, state.committed_term);
        assert_eq!(parsed.committed_node_id, state.committed_node_id);
    }

    #[test]
    fn test_raft_log_audit_record_for_truncate() {
        let entry1 =
            RaftLogEntry::create(1, 10, 5, 2, "normal".to_string(), Some("a".to_string())).unwrap();
        let entry2 =
            RaftLogEntry::create(1, 11, 5, 2, "normal".to_string(), Some("b".to_string())).unwrap();
        let entries = vec![entry1.clone(), entry2.clone()];

        let audit = RaftLogAuditRecord::for_truncate(1, &entries).unwrap();

        assert!(!audit.said.is_empty());
        assert_eq!(audit.node_id, 1);
        assert_eq!(audit.operation, "truncate");

        // Verify entries can be deserialized
        let recovered = audit.entries().unwrap();
        assert_eq!(recovered.len(), 2);
        assert_eq!(recovered[0].said, entry1.said);
        assert_eq!(recovered[1].said, entry2.said);
    }

    #[test]
    fn test_raft_log_audit_record_for_purge() {
        let entry = RaftLogEntry::create(1, 5, 3, 2, "blank".to_string(), None).unwrap();
        let entries = vec![entry.clone()];

        let audit = RaftLogAuditRecord::for_purge(1, &entries).unwrap();

        assert_eq!(audit.operation, "purge");
        let recovered = audit.entries().unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].said, entry.said);
    }

    #[test]
    fn test_raft_log_audit_record_empty_entries() {
        let entries: Vec<RaftLogEntry> = vec![];
        let audit = RaftLogAuditRecord::for_truncate(1, &entries).unwrap();

        let recovered = audit.entries().unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn test_raft_log_audit_record_json_roundtrip() {
        let entry =
            RaftLogEntry::create(1, 10, 5, 2, "normal".to_string(), Some("data".to_string()))
                .unwrap();
        let audit = RaftLogAuditRecord::for_truncate(2, &[entry]).unwrap();

        let json = serde_json::to_string(&audit).unwrap();
        let parsed: RaftLogAuditRecord = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.said, audit.said);
        assert_eq!(parsed.node_id, audit.node_id);
        assert_eq!(parsed.operation, audit.operation);
        assert_eq!(parsed.entries_json, audit.entries_json);
    }

    // ==================== PeerScope Tests ====================

    #[test]
    fn test_peer_scope_as_str() {
        assert_eq!(PeerScope::Core.as_str(), "core");
        assert_eq!(PeerScope::Regional.as_str(), "regional");
    }

    #[test]
    fn test_peer_scope_display() {
        assert_eq!(format!("{}", PeerScope::Core), "core");
        assert_eq!(format!("{}", PeerScope::Regional), "regional");
    }

    #[test]
    fn test_peer_scope_from_str() {
        use std::str::FromStr;

        assert_eq!(PeerScope::from_str("core").unwrap(), PeerScope::Core);
        assert_eq!(
            PeerScope::from_str("regional").unwrap(),
            PeerScope::Regional
        );
        assert_eq!(PeerScope::from_str("CORE").unwrap(), PeerScope::Core);
        assert_eq!(
            PeerScope::from_str("Regional").unwrap(),
            PeerScope::Regional
        );
        assert_eq!(
            PeerScope::from_str("REGIONAL").unwrap(),
            PeerScope::Regional
        );
    }

    #[test]
    fn test_peer_scope_from_str_invalid() {
        use std::str::FromStr;

        let result = PeerScope::from_str("invalid");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("Unknown peer scope"));
    }

    #[test]
    fn test_peer_scope_default() {
        let scope = PeerScope::default();
        assert_eq!(scope, PeerScope::Regional);
    }

    #[test]
    fn test_peer_scope_serialization() {
        let core_json = serde_json::to_string(&PeerScope::Core).unwrap();
        assert_eq!(core_json, "\"core\"");

        let regional_json = serde_json::to_string(&PeerScope::Regional).unwrap();
        assert_eq!(regional_json, "\"regional\"");
    }

    #[test]
    fn test_peer_scope_deserialization() {
        let core: PeerScope = serde_json::from_str("\"core\"").unwrap();
        assert_eq!(core, PeerScope::Core);

        let regional: PeerScope = serde_json::from_str("\"regional\"").unwrap();
        assert_eq!(regional, PeerScope::Regional);
    }

    #[test]
    fn test_peer_scope_equality() {
        assert_eq!(PeerScope::Core, PeerScope::Core);
        assert_eq!(PeerScope::Regional, PeerScope::Regional);
        assert_ne!(PeerScope::Core, PeerScope::Regional);
    }

    #[test]
    fn test_peer_scope_hash() {
        use std::collections::HashSet;

        let mut set = HashSet::new();
        set.insert(PeerScope::Core);
        set.insert(PeerScope::Regional);
        set.insert(PeerScope::Core); // Duplicate

        assert_eq!(set.len(), 2);
        assert!(set.contains(&PeerScope::Core));
        assert!(set.contains(&PeerScope::Regional));
    }

    #[test]
    fn test_peer_scope_copy() {
        let scope = PeerScope::Core;
        let copied = scope; // Copy, not move
        assert_eq!(scope, copied);
        assert_eq!(scope, PeerScope::Core); // Original still usable
    }
}
