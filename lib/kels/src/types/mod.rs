//! KELS types for API requests and responses

mod auth;
mod error;
mod federation;
mod gossip;
mod kel;
mod sad;
mod sync;

pub use auth::*;
pub use error::*;
pub use federation::*;
pub use gossip::*;
pub use kel::*;
pub use sad::*;
pub use sync::*;

#[cfg(test)]
mod tests {
    use cesr::{test_digest, test_signature};
    use verifiable_storage::Chained;

    use super::*;

    #[test]
    fn test_event_kind_serialization() {
        assert_eq!(EventKind::Icp.as_str(), "kels/kel/v1/events/icp");
        assert_eq!(EventKind::Dip.as_str(), "kels/kel/v1/events/dip");
        assert_eq!(EventKind::Rot.as_str(), "kels/kel/v1/events/rot");
        assert_eq!(EventKind::Ixn.as_str(), "kels/kel/v1/events/ixn");
        assert_eq!(EventKind::Rec.as_str(), "kels/kel/v1/events/rec");
        assert_eq!(EventKind::Ror.as_str(), "kels/kel/v1/events/ror");
        assert_eq!(EventKind::Dec.as_str(), "kels/kel/v1/events/dec");
        assert_eq!(EventKind::Cnt.as_str(), "kels/kel/v1/events/cnt");
    }

    #[test]
    fn test_event_kind_parsing() {
        use std::str::FromStr;
        assert_eq!(
            EventKind::from_str("kels/kel/v1/events/icp").unwrap(),
            EventKind::Icp
        );
        assert_eq!(
            EventKind::from_str("kels/kel/v1/events/cnt").unwrap(),
            EventKind::Cnt
        );
        // Rejects uppercase
        assert!(EventKind::from_str("KELS/V1/ICP").is_err());
        // Rejects short names
        assert!(EventKind::from_str("icp").is_err());
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
        assert_eq!(json, "\"kels/kel/v1/events/icp\"");
        let parsed: EventKind = serde_json::from_str("\"kels/kel/v1/events/rec\"").unwrap();
        assert_eq!(parsed, EventKind::Rec);
        // Short form rejected
        assert!(serde_json::from_str::<EventKind>("\"icp\"").is_err());
    }

    #[test]
    fn test_peer_creation() {
        let peer = Peer::create(
            test_digest("12D3KooWExample"),
            "node-a".to_string(),
            test_digest("KAuthorizingKel"),
            true,
            "node-a.kels".to_string(),
            "127.0.0.1:4001".to_string(),
        )
        .unwrap();

        assert!(peer.active);
        assert_eq!(peer.version, 0);
        assert!(peer.previous.is_none());
        assert_eq!(peer.said.to_string().len(), 44);
        // Prefix is derived from content hash, not manually set
        assert_eq!(peer.prefix.to_string().len(), 44);
        assert_eq!(peer.base_domain, "node-a.kels");
        assert_eq!(peer.gossip_addr, "127.0.0.1:4001");
    }

    #[test]
    fn test_peer_deactivation() {
        let peer = Peer::create(
            test_digest("12D3KooWExample"),
            "node-a".to_string(),
            test_digest("KAuthorizingKel"),
            true,
            "node-a.kels".to_string(),
            "127.0.0.1:4001".to_string(),
        )
        .unwrap();

        let deactivated = peer.deactivate().unwrap();

        assert!(!deactivated.active);
        assert_eq!(deactivated.version, 1);
        assert_eq!(deactivated.previous, Some(peer.said));
        assert_eq!(deactivated.prefix, peer.prefix);
    }

    // ==================== Test Helpers ====================

    fn make_blake3_digest(data: &str) -> cesr::Digest256 {
        cesr::Digest256::blake3_256(data.as_bytes())
    }

    fn make_secp256r1_key() -> cesr::VerificationKey {
        use cesr::VerificationKeyCode;
        // Valid compressed secp256r1 public key (33 bytes)
        let key_bytes = [
            0x02, // compressed prefix
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        cesr::VerificationKey::from_raw(VerificationKeyCode::Secp256r1, key_bytes.to_vec()).unwrap()
    }

    fn make_valid_icp() -> KeyEvent {
        KeyEvent {
            kind: EventKind::Icp,
            said: make_blake3_digest("said"),
            prefix: make_blake3_digest("prefix"),
            previous: None,
            serial: 0,
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
            serial: 0,
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
            serial: 0,
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
            serial: 0,
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
            serial: 0,
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
            serial: 0,
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
            serial: 0,
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
            serial: 0,
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
            serial: 0,
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
            said,
            prefix: make_blake3_digest("prefix"),
            previous: Some(said), // Same as said - circular!
            serial: 0,
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

    // Note: invalid_said_format and invalid_public_key_format tests removed
    // because these fields are now typed (cesr::Digest256, cesr::VerificationKey)
    // and invalid CESR is caught at deserialization time.

    // ==================== SignedKeyEvent tests ====================

    #[test]
    fn test_signed_key_event_equality_same_said() {
        let event = make_valid_icp();
        let sig1 = KeyEventSignature {
            label: "key1".to_string(),
            signature: test_signature("sig1"),
        };
        let sig2 = KeyEventSignature {
            label: "key2".to_string(),
            signature: test_signature("sig2"),
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
            label: "key".to_string(),
            signature: test_signature("sig"),
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
        let test_sig1 = test_signature("sig1");
        let test_sig2 = test_signature("sig2");
        let sig1 = KeyEventSignature {
            label: "key1".to_string(),
            signature: test_sig1.clone(),
        };
        let sig2 = KeyEventSignature {
            label: "key2".to_string(),
            signature: test_sig2.clone(),
        };

        let signed = SignedKeyEvent {
            event,
            signatures: vec![sig1.clone(), sig2.clone()],
        };

        assert_eq!(
            signed.signature("key1").map(|s| &s.signature),
            Some(&test_sig1)
        );
        assert_eq!(
            signed.signature("key2").map(|s| &s.signature),
            Some(&test_sig2)
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
        assert_eq!(EventKind::Icp.as_str(), "kels/kel/v1/events/icp");
        assert_eq!(EventKind::Dip.as_str(), "kels/kel/v1/events/dip");
        assert_eq!(EventKind::Rot.as_str(), "kels/kel/v1/events/rot");
        assert_eq!(EventKind::Ixn.as_str(), "kels/kel/v1/events/ixn");
        assert_eq!(EventKind::Rec.as_str(), "kels/kel/v1/events/rec");
        assert_eq!(EventKind::Ror.as_str(), "kels/kel/v1/events/ror");
        assert_eq!(EventKind::Dec.as_str(), "kels/kel/v1/events/dec");
        assert_eq!(EventKind::Cnt.as_str(), "kels/kel/v1/events/cnt");
    }

    #[test]
    fn test_event_kind_display() {
        assert_eq!(format!("{}", EventKind::Icp), "kels/kel/v1/events/icp");
        assert_eq!(format!("{}", EventKind::Cnt), "kels/kel/v1/events/cnt");
    }

    #[test]
    fn test_event_kind_from_str() {
        assert_eq!(
            "kels/kel/v1/events/icp".parse::<EventKind>().unwrap(),
            EventKind::Icp
        );
        assert_eq!(
            "kels/kel/v1/events/dip".parse::<EventKind>().unwrap(),
            EventKind::Dip
        );
        assert_eq!(
            "kels/kel/v1/events/rot".parse::<EventKind>().unwrap(),
            EventKind::Rot
        );
        assert_eq!(
            "kels/kel/v1/events/ixn".parse::<EventKind>().unwrap(),
            EventKind::Ixn
        );
        assert_eq!(
            "kels/kel/v1/events/rec".parse::<EventKind>().unwrap(),
            EventKind::Rec
        );
        assert_eq!(
            "kels/kel/v1/events/ror".parse::<EventKind>().unwrap(),
            EventKind::Ror
        );
        assert_eq!(
            "kels/kel/v1/events/dec".parse::<EventKind>().unwrap(),
            EventKind::Dec
        );
        assert_eq!(
            "kels/kel/v1/events/cnt".parse::<EventKind>().unwrap(),
            EventKind::Cnt
        );
    }

    #[test]
    fn test_event_kind_from_str_rejects_short_names() {
        assert!("icp".parse::<EventKind>().is_err());
        assert!("rot".parse::<EventKind>().is_err());
        assert!("ixn".parse::<EventKind>().is_err());
        assert!("rec".parse::<EventKind>().is_err());
    }

    #[test]
    fn test_event_kind_from_str_rejects_uppercase() {
        assert!("KELS/V1/ICP".parse::<EventKind>().is_err());
        assert!("Kels/V1/Icp".parse::<EventKind>().is_err());
    }

    #[test]
    fn test_event_kind_from_str_invalid() {
        let result = "invalid".parse::<EventKind>();
        assert!(result.is_err());
    }

    #[test]
    fn test_event_kind_from_short_name() {
        assert_eq!(EventKind::from_short_name("icp").unwrap(), EventKind::Icp);
        assert_eq!(EventKind::from_short_name("dip").unwrap(), EventKind::Dip);
        assert_eq!(EventKind::from_short_name("rot").unwrap(), EventKind::Rot);
        assert_eq!(EventKind::from_short_name("ixn").unwrap(), EventKind::Ixn);
        assert_eq!(EventKind::from_short_name("rec").unwrap(), EventKind::Rec);
        assert_eq!(EventKind::from_short_name("ror").unwrap(), EventKind::Ror);
        assert_eq!(EventKind::from_short_name("dec").unwrap(), EventKind::Dec);
        assert_eq!(EventKind::from_short_name("cnt").unwrap(), EventKind::Cnt);
    }

    #[test]
    fn test_event_kind_from_short_name_rejects_uppercase() {
        assert!(EventKind::from_short_name("ICP").is_err());
        assert!(EventKind::from_short_name("ROT").is_err());
    }

    #[test]
    fn test_event_kind_from_short_name_rejects_versioned() {
        assert!(EventKind::from_short_name("kels/kel/v1/events/icp").is_err());
    }

    #[test]
    fn test_event_kind_from_short_name_rejects_invalid() {
        assert!(EventKind::from_short_name("invalid").is_err());
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
        let sig = test_signature("sig");
        let signed = SignedKeyEvent::new(event.clone(), "signing".to_string(), sig.clone());
        assert_eq!(signed.event.said, event.said);
        assert_eq!(signed.signatures.len(), 1);
        assert_eq!(signed.signatures[0].label, "signing");
        assert_eq!(signed.signatures[0].signature, sig);
    }

    #[test]
    fn test_signed_key_event_new_recovery() {
        let event = make_valid_icp();
        let signed = SignedKeyEvent::new_recovery(
            event.clone(),
            test_signature("primary_sig"),
            test_signature("recovery_sig"),
        );
        assert_eq!(signed.signatures.len(), 2);
        assert_eq!(signed.signatures[0].label, "signing");
        assert_eq!(signed.signatures[1].label, "recovery");
    }

    #[test]
    fn test_signed_key_event_from_signatures() {
        let event = make_valid_icp();
        let sig2 = test_signature("sig2");
        let sigs = vec![
            ("key1".to_string(), test_signature("sig1")),
            ("key2".to_string(), sig2.clone()),
        ];
        let signed = SignedKeyEvent::from_signatures(event, sigs);
        assert_eq!(signed.signatures.len(), 2);
        assert_eq!(signed.signatures[0].label, "key1");
        assert_eq!(signed.signatures[1].signature, sig2);
    }

    #[test]
    fn test_signed_key_event_hash() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let event = make_valid_icp();
        let signed = SignedKeyEvent::new(event, "key".to_string(), test_signature("sig"));

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
            label: "key".to_string(),
            signature: test_signature("sig"),
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
                label: "key".to_string(),
                signature: test_signature("sig1"),
            }],
        };
        let signed2 = SignedKeyEvent {
            event,
            signatures: vec![KeyEventSignature {
                label: "key".to_string(),
                signature: test_signature("sig2"),
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
            serial: 0,
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
            serial: 0,
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
            serial: 0,
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
            serial: 0,
            public_key: Some(make_secp256r1_key()),
            rotation_hash: None,
            recovery_hash: None,
            recovery_key: Some(make_secp256r1_key()),
            anchor: None,
            delegating_prefix: None,
        };
        assert!(event.validate_structure().is_ok());
    }

    // ==================== BatchSubmitResponse tests ====================

    #[test]
    fn test_batch_submit_response_applied() {
        let response = SubmitEventsResponse {
            applied: true,
            diverged_at: None,
        };
        assert!(response.applied);
        assert!(response.diverged_at.is_none());
    }

    #[test]
    fn test_batch_submit_response_diverged() {
        let response = SubmitEventsResponse {
            applied: false,
            diverged_at: Some(5),
        };
        assert!(!response.applied);
        assert_eq!(response.diverged_at, Some(5));
    }

    // ==================== Raft types tests ====================

    #[test]
    fn test_raft_vote_create() {
        let vote = RaftVote::create(1, 5, Some(2), false).unwrap();
        assert_eq!(vote.said.to_string().len(), 44);
        assert_eq!(vote.prefix.to_string().len(), 44);
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
        let original_said = vote.said;
        let original_prefix = vote.prefix;
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

        assert_eq!(entry.said.to_string().len(), 44);
        assert_eq!(entry.prefix.to_string().len(), 44);
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
        let original_said = entry.said;

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

        assert_eq!(state.said.to_string().len(), 44);
        assert_eq!(state.prefix.to_string().len(), 44);
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
        let original_said = state.said;

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

        assert_eq!(audit.said.to_string().len(), 44);
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

    // ==================== SadPointerKind tests ====================

    #[test]
    fn test_sad_pointer_kind_as_str() {
        assert_eq!(SadPointerKind::Icp.as_str(), "kels/sad/v1/pointer/icp");
        assert_eq!(SadPointerKind::Upd.as_str(), "kels/sad/v1/pointer/upd");
        assert_eq!(SadPointerKind::Est.as_str(), "kels/sad/v1/pointer/est");
        assert_eq!(SadPointerKind::Evl.as_str(), "kels/sad/v1/pointer/evl");
        assert_eq!(SadPointerKind::Rpr.as_str(), "kels/sad/v1/pointer/rpr");
    }

    #[test]
    fn test_sad_pointer_kind_display() {
        assert_eq!(
            format!("{}", SadPointerKind::Icp),
            "kels/sad/v1/pointer/icp"
        );
        assert_eq!(
            format!("{}", SadPointerKind::Rpr),
            "kels/sad/v1/pointer/rpr"
        );
    }

    #[test]
    fn test_sad_pointer_kind_from_str() {
        assert_eq!(
            "kels/sad/v1/pointer/icp".parse::<SadPointerKind>().unwrap(),
            SadPointerKind::Icp
        );
        assert_eq!(
            "kels/sad/v1/pointer/upd".parse::<SadPointerKind>().unwrap(),
            SadPointerKind::Upd
        );
        assert_eq!(
            "kels/sad/v1/pointer/est".parse::<SadPointerKind>().unwrap(),
            SadPointerKind::Est
        );
        assert_eq!(
            "kels/sad/v1/pointer/evl".parse::<SadPointerKind>().unwrap(),
            SadPointerKind::Evl
        );
        assert_eq!(
            "kels/sad/v1/pointer/rpr".parse::<SadPointerKind>().unwrap(),
            SadPointerKind::Rpr
        );
    }

    #[test]
    fn test_sad_pointer_kind_from_str_rejects_invalid() {
        assert!("invalid".parse::<SadPointerKind>().is_err());
        assert!("icp".parse::<SadPointerKind>().is_err());
    }

    #[test]
    fn test_sad_pointer_kind_from_short_name() {
        assert_eq!(
            SadPointerKind::from_short_name("icp").unwrap(),
            SadPointerKind::Icp
        );
        assert_eq!(
            SadPointerKind::from_short_name("upd").unwrap(),
            SadPointerKind::Upd
        );
        assert_eq!(
            SadPointerKind::from_short_name("est").unwrap(),
            SadPointerKind::Est
        );
        assert_eq!(
            SadPointerKind::from_short_name("evl").unwrap(),
            SadPointerKind::Evl
        );
        assert_eq!(
            SadPointerKind::from_short_name("rpr").unwrap(),
            SadPointerKind::Rpr
        );
    }

    #[test]
    fn test_sad_pointer_kind_from_short_name_rejects_invalid() {
        assert!(SadPointerKind::from_short_name("invalid").is_err());
        assert!(SadPointerKind::from_short_name("kels/sad/v1/pointer/icp").is_err());
    }

    #[test]
    fn test_sad_pointer_kind_serde_roundtrip() {
        let json = serde_json::to_string(&SadPointerKind::Icp).unwrap();
        assert_eq!(json, "\"kels/sad/v1/pointer/icp\"");
        let parsed: SadPointerKind = serde_json::from_str("\"kels/sad/v1/pointer/evl\"").unwrap();
        assert_eq!(parsed, SadPointerKind::Evl);
        // Short form rejected
        assert!(serde_json::from_str::<SadPointerKind>("\"icp\"").is_err());
    }

    #[test]
    fn test_sad_pointer_kind_predicates() {
        assert!(SadPointerKind::Icp.is_inception());
        assert!(!SadPointerKind::Upd.is_inception());

        assert!(SadPointerKind::Rpr.is_repair());
        assert!(!SadPointerKind::Evl.is_repair());

        assert!(SadPointerKind::Evl.evaluates_checkpoint());
        assert!(SadPointerKind::Rpr.evaluates_checkpoint());
        assert!(!SadPointerKind::Upd.evaluates_checkpoint());
        assert!(!SadPointerKind::Est.evaluates_checkpoint());
        assert!(!SadPointerKind::Icp.evaluates_checkpoint());
    }

    // ==================== SadPointer::validate_structure tests ====================

    fn make_valid_icp_pointer() -> SadPointer {
        let wp = cesr::Digest256::blake3_256(b"wp");
        SadPointer::create(
            "test/topic".to_string(),
            SadPointerKind::Icp,
            None,
            None,
            Some(wp),
            None,
        )
        .unwrap()
    }

    #[test]
    fn test_validate_structure_icp_valid() {
        let pointer = make_valid_icp_pointer();
        assert!(pointer.validate_structure().is_ok());
    }

    #[test]
    fn test_validate_structure_icp_with_checkpoint_policy_valid() {
        let wp = cesr::Digest256::blake3_256(b"wp");
        let cp = cesr::Digest256::blake3_256(b"cp");
        let pointer = SadPointer::create(
            "test/topic".to_string(),
            SadPointerKind::Icp,
            None,
            None,
            Some(wp),
            Some(cp),
        )
        .unwrap();
        assert!(pointer.validate_structure().is_ok());
    }

    #[test]
    fn test_validate_structure_icp_missing_write_policy_rejected() {
        let mut pointer = make_valid_icp_pointer();
        pointer.write_policy = None;
        let err = pointer.validate_structure().unwrap_err();
        assert!(
            err.contains("requires writePolicy"),
            "expected writePolicy required error, got: {err}"
        );
    }

    #[test]
    fn test_validate_structure_icp_wrong_version() {
        let mut pointer = make_valid_icp_pointer();
        pointer.version = 1;
        let err = pointer.validate_structure().unwrap_err();
        assert!(err.contains("version 0"));
    }

    #[test]
    fn test_validate_structure_sad_icp_forbids_content() {
        let mut pointer = make_valid_icp_pointer();
        pointer.content = Some(cesr::Digest256::blake3_256(b"content"));
        let err = pointer.validate_structure().unwrap_err();
        assert!(err.contains("must not have content"));
    }

    #[test]
    fn test_validate_structure_sad_icp_forbids_previous() {
        let mut pointer = make_valid_icp_pointer();
        pointer.previous = Some(cesr::Digest256::blake3_256(b"prev"));
        let err = pointer.validate_structure().unwrap_err();
        assert!(err.contains("must not have previous"));
    }

    #[test]
    fn test_validate_structure_est_valid() {
        let mut pointer = make_valid_icp_pointer();
        pointer.kind = SadPointerKind::Est;
        pointer.version = 1;
        pointer.previous = Some(cesr::Digest256::blake3_256(b"prev"));
        pointer.checkpoint_policy = Some(cesr::Digest256::blake3_256(b"cp"));
        pointer.write_policy = None;
        assert!(pointer.validate_structure().is_ok());
    }

    #[test]
    fn test_validate_structure_est_wrong_version() {
        let mut pointer = make_valid_icp_pointer();
        pointer.kind = SadPointerKind::Est;
        pointer.version = 2;
        pointer.previous = Some(cesr::Digest256::blake3_256(b"prev"));
        pointer.checkpoint_policy = Some(cesr::Digest256::blake3_256(b"cp"));
        pointer.write_policy = None;
        let err = pointer.validate_structure().unwrap_err();
        assert!(err.contains("version 1"));
    }

    #[test]
    fn test_validate_structure_est_missing_checkpoint_policy() {
        let mut pointer = make_valid_icp_pointer();
        pointer.kind = SadPointerKind::Est;
        pointer.version = 1;
        pointer.previous = Some(cesr::Digest256::blake3_256(b"prev"));
        pointer.write_policy = None;
        let err = pointer.validate_structure().unwrap_err();
        assert!(err.contains("requires checkpointPolicy"));
    }

    #[test]
    fn test_validate_structure_est_forbids_write_policy() {
        let mut pointer = make_valid_icp_pointer();
        pointer.kind = SadPointerKind::Est;
        pointer.version = 1;
        pointer.previous = Some(cesr::Digest256::blake3_256(b"prev"));
        pointer.checkpoint_policy = Some(cesr::Digest256::blake3_256(b"cp"));
        // write_policy inherited from Icp helper — Est forbids it
        let err = pointer.validate_structure().unwrap_err();
        assert!(err.contains("must not have writePolicy"));
    }

    #[test]
    fn test_validate_structure_upd_valid() {
        let mut pointer = make_valid_icp_pointer();
        pointer.kind = SadPointerKind::Upd;
        pointer.version = 1;
        pointer.previous = Some(cesr::Digest256::blake3_256(b"prev"));
        pointer.content = Some(cesr::Digest256::blake3_256(b"content"));
        pointer.write_policy = None;
        assert!(pointer.validate_structure().is_ok());
    }

    #[test]
    fn test_validate_structure_upd_forbids_checkpoint_policy() {
        let mut pointer = make_valid_icp_pointer();
        pointer.kind = SadPointerKind::Upd;
        pointer.version = 1;
        pointer.previous = Some(cesr::Digest256::blake3_256(b"prev"));
        pointer.checkpoint_policy = Some(cesr::Digest256::blake3_256(b"cp"));
        pointer.write_policy = None;
        let err = pointer.validate_structure().unwrap_err();
        assert!(err.contains("must not have checkpointPolicy"));
    }

    #[test]
    fn test_validate_structure_upd_forbids_write_policy() {
        let mut pointer = make_valid_icp_pointer();
        pointer.kind = SadPointerKind::Upd;
        pointer.version = 1;
        pointer.previous = Some(cesr::Digest256::blake3_256(b"prev"));
        // write_policy inherited from Icp helper — Upd forbids it
        let err = pointer.validate_structure().unwrap_err();
        assert!(err.contains("must not have writePolicy"));
    }

    #[test]
    fn test_validate_structure_evl_with_write_policy_valid() {
        let mut pointer = make_valid_icp_pointer();
        pointer.kind = SadPointerKind::Evl;
        pointer.version = 2;
        pointer.previous = Some(cesr::Digest256::blake3_256(b"prev"));
        // write_policy Some — policy evolution
        assert!(pointer.validate_structure().is_ok());
    }

    #[test]
    fn test_validate_structure_evl_without_write_policy_valid() {
        let mut pointer = make_valid_icp_pointer();
        pointer.kind = SadPointerKind::Evl;
        pointer.version = 2;
        pointer.previous = Some(cesr::Digest256::blake3_256(b"prev"));
        pointer.write_policy = None;
        // write_policy None — pure checkpoint
        assert!(pointer.validate_structure().is_ok());
    }

    #[test]
    fn test_validate_structure_evl_with_checkpoint_policy_valid() {
        let mut pointer = make_valid_icp_pointer();
        pointer.kind = SadPointerKind::Evl;
        pointer.version = 2;
        pointer.previous = Some(cesr::Digest256::blake3_256(b"prev"));
        pointer.checkpoint_policy = Some(cesr::Digest256::blake3_256(b"new-cp"));
        assert!(pointer.validate_structure().is_ok());
    }

    #[test]
    fn test_validate_structure_rpr_valid() {
        let mut pointer = make_valid_icp_pointer();
        pointer.kind = SadPointerKind::Rpr;
        pointer.version = 1;
        pointer.previous = Some(cesr::Digest256::blake3_256(b"prev"));
        pointer.write_policy = None;
        assert!(pointer.validate_structure().is_ok());
    }

    #[test]
    fn test_validate_structure_rpr_forbids_checkpoint_policy() {
        let mut pointer = make_valid_icp_pointer();
        pointer.kind = SadPointerKind::Rpr;
        pointer.version = 1;
        pointer.previous = Some(cesr::Digest256::blake3_256(b"prev"));
        pointer.checkpoint_policy = Some(cesr::Digest256::blake3_256(b"cp"));
        pointer.write_policy = None;
        let err = pointer.validate_structure().unwrap_err();
        assert!(err.contains("must not have checkpointPolicy"));
    }

    #[test]
    fn test_validate_structure_rpr_forbids_write_policy() {
        let mut pointer = make_valid_icp_pointer();
        pointer.kind = SadPointerKind::Rpr;
        pointer.version = 1;
        pointer.previous = Some(cesr::Digest256::blake3_256(b"prev"));
        // write_policy inherited from Icp helper — Rpr forbids it
        let err = pointer.validate_structure().unwrap_err();
        assert!(err.contains("must not have writePolicy"));
    }
}
