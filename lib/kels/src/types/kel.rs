//! Key event chain utilities — rotation hash computation.
//!
//! All KEL verification and state queries go through `KelVerifier` +
//! `MergeContext` (proof-of-verification). See `verifier.rs` and
//! `merge_context.rs`.

use cesr::{Digest, Matter};

pub fn compute_rotation_hash(public_key: &str) -> String {
    let digest = Digest::blake3_256(public_key.as_bytes());
    digest.qb64()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::KeyEventBuilder;
    use crate::crypto::SoftwareKeyProvider;
    use crate::types::SignedKeyEvent;
    use crate::types::verifier::KelVerifier;
    use cesr::PrivateKey;

    /// Helper to clone all keys from a builder's key provider
    fn clone_keys(
        builder: &KeyEventBuilder<SoftwareKeyProvider>,
    ) -> (PrivateKey, PrivateKey, PrivateKey) {
        let software = builder.key_provider();
        (
            software.current_private_key().unwrap().clone(),
            software.next_private_key().unwrap().clone(),
            software.recovery_private_key().unwrap().clone(),
        )
    }

    /// Create a valid CESR anchor digest from a test label
    fn anchor(label: &str) -> String {
        Digest::blake3_256(label.as_bytes()).qb64()
    }

    /// Sort events the way the DB would: serial ASC, said ASC
    fn sort_events(events: &mut [SignedKeyEvent]) {
        events.sort_by(|a, b| {
            a.event
                .serial
                .cmp(&b.event.serial)
                .then(a.event.said.cmp(&b.event.said))
        });
    }

    /// Verify events with KelVerifier and return MergeContext
    fn verify(events: &[SignedKeyEvent]) -> crate::Verification {
        let prefix = events[0].event.prefix.clone();
        let mut verifier = KelVerifier::new(&prefix);
        verifier.verify_page(events).unwrap();
        verifier.into_verification()
    }

    /// Verify events with anchor checking and return MergeContext
    fn verify_with_anchors(
        events: &[SignedKeyEvent],
        anchors: impl IntoIterator<Item = String>,
    ) -> crate::Verification {
        let prefix = events[0].event.prefix.clone();
        let mut verifier = KelVerifier::new(&prefix);
        verifier.check_anchors(anchors);
        verifier.verify_page(events).unwrap();
        verifier.into_verification()
    }

    // ==================== compute_rotation_hash ====================

    #[test]
    fn test_compute_rotation_hash() {
        let public_key = "1AAACk1SoB-PO_xcbaR6LgKHVgojABYjAhd4kEk7-qeS";
        let hash = compute_rotation_hash(public_key);
        // Should produce a Blake3-256 digest (starts with 'E')
        assert!(hash.starts_with('E'));
        assert_eq!(hash.len(), 44);

        // Same input should produce same output
        let hash2 = compute_rotation_hash(public_key);
        assert_eq!(hash, hash2);
    }

    // ==================== Builder / Event Creation ====================

    #[tokio::test]
    async fn test_incept() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);

        let icp = builder.incept().await.unwrap();

        assert!(icp.event.is_inception());
        assert!(!icp.event.said.is_empty());
        assert!(icp.event.previous.is_none());
        assert!(icp.event.public_key.is_some());
        assert!(icp.event.rotation_hash.is_some());

        let public_key = builder.current_public_key().await.unwrap();
        let signature = cesr::Signature::from_qb64(&icp.signatures[0].signature).unwrap();
        assert!(
            public_key
                .verify(icp.event.said.as_bytes(), &signature)
                .is_ok()
        );

        assert_eq!(builder.prefix(), Some(icp.event.prefix.as_str()));
    }

    #[tokio::test]
    async fn test_interact() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);

        let icp = builder.incept().await.unwrap();

        let a = anchor("credential");
        let ixn = builder.interact(&a).await.unwrap();

        assert!(ixn.event.is_interaction());
        assert_ne!(ixn.event.said, icp.event.said);
        assert_eq!(ixn.event.prefix, icp.event.prefix);
        assert_eq!(ixn.event.previous, Some(icp.event.said.clone()));
        assert_eq!(ixn.event.anchor, Some(a));
        assert!(ixn.event.public_key.is_none());
        assert!(ixn.event.rotation_hash.is_none());
    }

    #[tokio::test]
    async fn test_rotate() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);

        let icp = builder.incept().await.unwrap();
        let original_public_key = builder.current_public_key().await.unwrap();

        let rot = builder.rotate().await.unwrap();

        assert!(rot.event.is_rotation());
        assert_ne!(rot.event.said, icp.event.said);
        assert_eq!(rot.event.prefix, icp.event.prefix);
        assert_eq!(rot.event.previous, Some(icp.event.said.clone()));
        assert!(rot.event.public_key.is_some());
        assert!(rot.event.rotation_hash.is_some());

        let new_public_key = builder.current_public_key().await.unwrap();
        assert_ne!(original_public_key.qb64(), new_public_key.qb64());

        let rotation_hash = icp.event.rotation_hash.unwrap();
        let expected_hash = compute_rotation_hash(&new_public_key.qb64());
        assert_eq!(rotation_hash, expected_hash);
    }

    #[tokio::test]
    async fn test_interact_before_incept_fails() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let result = builder.interact("some_anchor").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_rotate_before_incept_fails() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let result = builder.rotate().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_said_verification() {
        use verifiable_storage::{Chained, SelfAddressed};

        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);

        let icp = builder.incept().await.unwrap();
        assert!(icp.event.verify_prefix().is_ok());

        let ixn = builder.interact(&anchor("test")).await.unwrap();
        assert!(ixn.event.verify_said().is_ok());
    }

    #[tokio::test]
    async fn test_with_events() {
        let mut builder1 = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let icp = builder1.incept().await.unwrap();

        let (current_key, next_key, recovery_key) = clone_keys(&builder1);

        let mut builder2 = KeyEventBuilder::with_events(
            SoftwareKeyProvider::with_all_keys(current_key, next_key, recovery_key),
            None,
            None,
            vec![icp.clone()],
        );

        let ixn = builder2.interact(&anchor("test")).await.unwrap();
        assert_eq!(ixn.event.prefix, icp.event.prefix);
        assert_eq!(ixn.event.previous, Some(icp.event.said.clone()));
    }

    #[tokio::test]
    async fn test_rotation_after_interactions() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let icp = builder.incept().await.unwrap();
        builder.interact(&anchor("a1")).await.unwrap();
        let ixn2 = builder.interact(&anchor("a2")).await.unwrap();

        let (current_key, next_key, recovery_key) = clone_keys(&builder);
        let mut builder2 = KeyEventBuilder::with_events(
            SoftwareKeyProvider::with_all_keys(current_key, next_key, recovery_key),
            None,
            None,
            builder.events().to_vec(),
        );

        assert_eq!(builder2.last_event().unwrap().said, ixn2.event.said);
        assert_eq!(
            builder2.last_establishment_event().unwrap().said,
            icp.event.said
        );

        let rot = builder2.rotate().await.unwrap();
        assert_eq!(rot.event.previous, Some(ixn2.event.said.clone()));
    }

    #[tokio::test]
    async fn test_json_roundtrip() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let icp = builder.incept().await.unwrap();

        let json = serde_json::to_string(&icp).unwrap();
        let deserialized: SignedKeyEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.event.said, icp.event.said);
        assert_eq!(deserialized.event.prefix, icp.event.prefix);

        // Verify deserialized event passes KelVerifier
        let ctx = verify(&[deserialized]);
        assert!(!ctx.is_empty());
    }

    // ==================== KelVerifier — basic verification ====================

    #[tokio::test]
    async fn test_verify_basic_kel() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        builder.incept().await.unwrap();
        let ixn = builder.interact(&anchor("test")).await.unwrap();

        let ctx = verify(builder.events());
        assert!(!ctx.is_empty());
        assert!(!ctx.is_divergent());
        assert!(!ctx.is_contested());
        assert!(!ctx.is_decommissioned());
        assert!(ctx.current_public_key().is_some());
        assert_eq!(ctx.branch_tips()[0].tip.event.said, ixn.event.said);
    }

    #[tokio::test]
    async fn test_verify_with_rotation() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let icp = builder.incept().await.unwrap();
        builder.interact(&anchor("a1")).await.unwrap();
        let rot = builder.rotate().await.unwrap();
        let ixn2 = builder.interact(&anchor("a2")).await.unwrap();

        let ctx = verify(builder.events());

        // Last event is ixn2, last establishment is rot
        assert_eq!(ctx.branch_tips()[0].tip.event.said, ixn2.event.said);
        assert_eq!(
            ctx.last_establishment_event().unwrap().event.said,
            rot.event.said
        );

        // Public key should be from the rotation, not inception
        let rot_key = rot.event.public_key.as_ref().unwrap();
        let icp_key = icp.event.public_key.as_ref().unwrap();
        assert_ne!(ctx.current_public_key().unwrap(), icp_key);
        assert_eq!(ctx.current_public_key().unwrap(), rot_key);
    }

    // ==================== KelVerifier — divergence detection ====================

    #[tokio::test]
    async fn test_divergence_two_way() {
        let mut builder1 = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let icp = builder1.incept().await.unwrap();
        let mut builder2 = builder1.clone();

        let ixn1 = builder1.interact(&anchor("a1")).await.unwrap();
        let ixn2 = builder2.interact(&anchor("a2")).await.unwrap();

        assert_ne!(ixn1.event.said, ixn2.event.said);

        let mut events = vec![icp, ixn1, ixn2];
        sort_events(&mut events);

        let ctx = verify(&events);
        assert!(ctx.is_divergent());
        assert_eq!(ctx.diverged_at_serial(), Some(1));
        assert_eq!(ctx.branch_tips().len(), 2);
    }

    #[tokio::test]
    async fn test_divergence_three_way() {
        let mut builder1 = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let icp = builder1.incept().await.unwrap();
        let mut builder2 = builder1.clone();
        let mut builder3 = builder1.clone();

        let ixn1 = builder1.interact(&anchor("a1")).await.unwrap();
        let ixn2 = builder2.interact(&anchor("a2")).await.unwrap();
        let ixn3 = builder3.interact(&anchor("a3")).await.unwrap();

        let mut events = vec![icp, ixn1, ixn2, ixn3];
        sort_events(&mut events);

        let ctx = verify(&events);
        assert!(ctx.is_divergent());
        assert_eq!(ctx.diverged_at_serial(), Some(1));
        assert_eq!(ctx.branch_tips().len(), 3);
    }

    #[tokio::test]
    async fn test_divergent_kel_has_no_single_public_key() {
        let mut builder1 = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let icp = builder1.incept().await.unwrap();
        let mut builder2 = builder1.clone();

        let ixn1 = builder1.interact(&anchor("a1")).await.unwrap();
        let ixn2 = builder2.interact(&anchor("a2")).await.unwrap();

        let mut events = vec![icp, ixn1, ixn2];
        sort_events(&mut events);

        let ctx = verify(&events);
        assert!(ctx.current_public_key().is_none());
        assert!(ctx.last_establishment_event().is_none());
    }

    #[tokio::test]
    async fn test_adversary_rotation_detection() {
        let mut owner = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let icp = owner.incept().await.unwrap();
        let owner_ixn = owner.interact(&anchor("owner")).await.unwrap();

        let (current_key, next_key, recovery_key) = clone_keys(&owner);

        let mut adversary = KeyEventBuilder::with_events(
            SoftwareKeyProvider::with_all_keys(current_key, next_key, recovery_key),
            None,
            None,
            vec![icp.clone()],
        );
        let adversary_rot = adversary.rotate().await.unwrap();

        let mut events = vec![icp, owner_ixn.clone(), adversary_rot.clone()];
        sort_events(&mut events);

        let ctx = verify(&events);
        assert!(ctx.is_divergent());
        assert_eq!(ctx.diverged_at_serial(), Some(1));

        let tips = ctx.branch_tips();
        assert_eq!(tips.len(), 2);
        let tip_saids: std::collections::HashSet<_> =
            tips.iter().map(|t| t.tip.event.said.as_str()).collect();
        assert!(tip_saids.contains(owner_ixn.event.said.as_str()));
        assert!(tip_saids.contains(adversary_rot.event.said.as_str()));
    }

    // ==================== KelVerifier — decommission / contest ====================

    #[tokio::test]
    async fn test_decommissioned_kel() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        builder.incept().await.unwrap();
        builder.decommission().await.unwrap();

        let ctx = verify(builder.events());
        assert!(ctx.is_decommissioned());
        assert!(!ctx.is_contested());
    }

    #[tokio::test]
    async fn test_contested_kel() {
        let mut owner = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let icp = owner.incept().await.unwrap();

        let mut adversary = owner.clone();

        let ror = adversary.rotate_recovery().await.unwrap();
        let cnt = owner.contest().await.unwrap();

        let mut events = vec![icp, ror, cnt];
        sort_events(&mut events);

        let ctx = verify(&events);
        assert!(ctx.is_contested());
        assert!(ctx.is_decommissioned());
    }

    #[tokio::test]
    async fn test_non_contested_kel_with_ror() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let icp = builder.incept().await.unwrap();

        let mut adversary = builder.clone();
        let ror = adversary.rotate_recovery().await.unwrap();

        let mut events = vec![icp, ror];
        sort_events(&mut events);

        let ctx = verify(&events);
        assert!(!ctx.is_contested());
        assert!(!ctx.is_decommissioned());
    }

    // ==================== KelVerifier — anchor checking ====================

    #[tokio::test]
    async fn test_anchor_found() {
        let a = anchor("my-anchor");
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        builder.incept().await.unwrap();
        builder.interact(&a).await.unwrap();

        let ctx = verify_with_anchors(builder.events(), [a.clone()]);
        assert!(ctx.is_said_anchored(&a));
        assert!(ctx.anchors_all_saids());
    }

    #[tokio::test]
    async fn test_anchor_not_found() {
        let a = anchor("my-anchor");
        let missing = anchor("missing");
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        builder.incept().await.unwrap();
        builder.interact(&a).await.unwrap();

        let ctx = verify_with_anchors(builder.events(), [missing.clone()]);
        assert!(!ctx.is_said_anchored(&missing));
        assert!(!ctx.anchors_all_saids());
    }

    #[tokio::test]
    async fn test_anchor_no_interactions() {
        let missing = anchor("anything");
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        builder.incept().await.unwrap();

        let ctx = verify_with_anchors(builder.events(), [missing.clone()]);
        assert!(!ctx.is_said_anchored(&missing));
    }

    #[tokio::test]
    async fn test_anchor_before_divergence() {
        let a_pre = anchor("pre-divergence");
        let mut owner = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        owner.incept().await.unwrap();
        owner.interact(&a_pre).await.unwrap();

        let mut adversary = owner.clone();

        owner.interact(&anchor("owner-gen2")).await.unwrap();
        let adversary_ixn2 = adversary.interact(&anchor("adv-gen2")).await.unwrap();

        let mut events = owner.events().to_vec();
        events.push(adversary_ixn2);
        sort_events(&mut events);

        let ctx = verify_with_anchors(&events, [a_pre.clone()]);
        assert!(ctx.is_divergent());
        assert_eq!(ctx.diverged_at_serial(), Some(2));
        assert!(ctx.is_said_anchored(&a_pre));
    }

    #[tokio::test]
    async fn test_anchors_on_divergent_branches() {
        let a_owner = anchor("owner");
        let a_adv = anchor("adversary");
        let mut owner = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        owner.incept().await.unwrap();
        let mut adversary = owner.clone();

        owner.interact(&a_owner).await.unwrap();
        let adversary_ixn = adversary.interact(&a_adv).await.unwrap();

        let mut events = owner.events().to_vec();
        events.push(adversary_ixn);
        sort_events(&mut events);

        let ctx = verify_with_anchors(&events, [a_owner.clone(), a_adv.clone()]);
        assert!(ctx.is_divergent());
        assert!(ctx.is_said_anchored(&a_owner));
        assert!(ctx.is_said_anchored(&a_adv));
    }

    // ==================== KelVerifier — effective SAID ====================

    #[tokio::test]
    async fn test_effective_tail_said_non_divergent() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        builder.incept().await.unwrap();
        let ixn = builder.interact(&anchor("test")).await.unwrap();

        let ctx = verify(builder.events());
        assert_eq!(ctx.effective_tail_said(), Some(ixn.event.said.clone()));
    }

    #[tokio::test]
    async fn test_effective_tail_said_divergent() {
        let mut builder1 = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let icp = builder1.incept().await.unwrap();
        let mut builder2 = builder1.clone();

        let ixn1 = builder1.interact(&anchor("a1")).await.unwrap();
        let ixn2 = builder2.interact(&anchor("a2")).await.unwrap();

        let mut events = vec![icp, ixn1.clone(), ixn2.clone()];
        sort_events(&mut events);

        let ctx = verify(&events);
        let effective = ctx.effective_tail_said().unwrap();

        assert_ne!(effective, ixn1.event.said);
        assert_ne!(effective, ixn2.event.said);

        let ctx2 = verify(&events);
        assert_eq!(ctx.effective_tail_said(), ctx2.effective_tail_said());
    }

    // ==================== KelVerifier — recovery events ====================

    #[tokio::test]
    async fn test_verify_recovery_event() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        builder.incept().await.unwrap();
        builder.recover(false).await.unwrap();

        let ctx = verify(builder.events());
        assert!(!ctx.is_empty());
        assert!(!ctx.is_divergent());
        assert!(ctx.last_establishment_event().unwrap().event.is_recover());
    }

    #[tokio::test]
    async fn test_verify_rotate_recovery() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        builder.incept().await.unwrap();
        builder.rotate_recovery().await.unwrap();

        let ctx = verify(builder.events());
        assert!(!ctx.is_empty());
        assert!(!ctx.is_divergent());
        assert!(
            ctx.last_establishment_event()
                .unwrap()
                .event
                .reveals_recovery_key()
        );
    }

    // ==================== KelVerifier — resume from MergeContext ====================

    #[tokio::test]
    async fn test_resume_extends_verification() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        builder.incept().await.unwrap();
        let ixn1 = builder.interact(&anchor("a1")).await.unwrap();

        let ctx = verify(&builder.events()[..2]);
        assert_eq!(ctx.branch_tips()[0].tip.event.said, ixn1.event.said);

        let ixn2 = builder.interact(&anchor("a2")).await.unwrap();

        let prefix = ctx.prefix().to_string();
        let mut verifier = KelVerifier::resume(&prefix, &ctx);
        verifier.verify_page(std::slice::from_ref(&ixn2)).unwrap();
        let ctx2 = verifier.into_verification();

        assert_eq!(ctx2.branch_tips()[0].tip.event.said, ixn2.event.said);
    }

    // ==================== KelVerifier — from_branch_tip ====================

    #[tokio::test]
    async fn test_from_branch_tip_verifies_extension() {
        use crate::BranchTip;

        let mut owner = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let icp = owner.incept().await.unwrap();
        let mut adversary = owner.clone();

        let owner_ixn = owner.interact(&anchor("owner")).await.unwrap();
        let _adv_ixn = adversary.interact(&anchor("adv")).await.unwrap();

        let tip = BranchTip {
            tip: owner_ixn.clone(),
            establishment_tip: icp.clone(),
        };

        let owner_ixn2 = owner.interact(&anchor("owner2")).await.unwrap();

        let mut verifier = KelVerifier::from_branch_tip(&icp.event.prefix, &tip);
        verifier
            .verify_page(std::slice::from_ref(&owner_ixn2))
            .unwrap();
        let ctx = verifier.into_verification();

        assert_eq!(ctx.branch_tips()[0].tip.event.said, owner_ixn2.event.said);
    }

    // ==================== Builder — divergent state ====================

    #[tokio::test]
    async fn test_builder_with_divergent_events() {
        let mut builder1 = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let icp = builder1.incept().await.unwrap();
        builder1.interact(&anchor("a1")).await.unwrap();

        let (current_key, next_key, recovery_key) = clone_keys(&builder1);

        let mut builder2 = KeyEventBuilder::with_events(
            SoftwareKeyProvider::with_all_keys(
                current_key.clone(),
                next_key.clone(),
                recovery_key.clone(),
            ),
            None,
            None,
            vec![icp.clone()],
        );
        builder2.interact(&anchor("a2")).await.unwrap();

        let mut events = builder1.events().to_vec();
        events.extend(builder2.events()[1..].iter().cloned());
        sort_events(&mut events);

        let ctx = verify(&events);
        assert!(ctx.is_divergent());

        let builder3 = KeyEventBuilder::with_events(
            SoftwareKeyProvider::with_all_keys(current_key, next_key, recovery_key),
            None,
            None,
            events,
        );
        assert_eq!(builder3.confirmed_count(), 3);
        assert_eq!(builder3.pending_events().len(), 0);
    }
}
