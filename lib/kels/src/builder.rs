//! Key Event Builder

use std::collections::HashSet;

use cesr::{Matter, PublicKey};

use crate::{
    client::KelsClient,
    crypto::KeyProvider,
    error::KelsError,
    store::KelStore,
    types::{Kel, KeyEvent, SignedKeyEvent},
};

pub struct KeyEventBuilder<K: KeyProvider + Clone> {
    key_provider: K,
    #[allow(dead_code)]
    kels_client: Option<KelsClient>,
    kel_store: Option<std::sync::Arc<dyn KelStore>>,
    kel: Kel,
    confirmed_cursor: usize,
}

impl<K: KeyProvider + Clone> Clone for KeyEventBuilder<K> {
    fn clone(&self) -> Self {
        Self {
            key_provider: self.key_provider.clone(),
            kels_client: self.kels_client.clone(),
            kel_store: self.kel_store.clone(),
            kel: self.kel.clone(),
            confirmed_cursor: self.confirmed_cursor,
        }
    }
}

impl<K: KeyProvider + Clone> KeyEventBuilder<K> {
    // ==================== Constructors ====================

    pub fn new(key_provider: K, kels_client: Option<KelsClient>) -> Self {
        Self {
            key_provider,
            kels_client,
            kel_store: None,
            kel: Kel::default(),
            confirmed_cursor: 0,
        }
    }

    pub async fn with_dependencies(
        key_provider: K,
        kels_client: Option<KelsClient>,
        kel_store: Option<std::sync::Arc<dyn KelStore>>,
        prefix: Option<&str>,
    ) -> Result<Self, KelsError> {
        let kel = match (&kel_store, prefix) {
            (Some(store), Some(p)) => store.load(p).await?.unwrap_or_default(),
            _ => Kel::default(),
        };
        let confirmed_cursor = kel.confirmed_length();

        Ok(Self {
            key_provider,
            kels_client,
            kel_store,
            kel,
            confirmed_cursor,
        })
    }

    pub fn with_kel(
        key_provider: K,
        kels_client: Option<KelsClient>,
        kel_store: Option<std::sync::Arc<dyn KelStore>>,
        kel: Kel,
    ) -> Result<Self, KelsError> {
        let confirmed_cursor = kel.confirmed_length();
        Ok(Self {
            key_provider,
            kels_client,
            kel_store,
            kel,
            confirmed_cursor,
        })
    }

    // ==================== Accessors ====================

    pub fn confirmed_count(&self) -> usize {
        self.confirmed_cursor
    }

    pub async fn current_public_key(&self) -> Result<PublicKey, KelsError> {
        self.key_provider.current_public_key().await
    }

    pub fn events(&self) -> &[SignedKeyEvent] {
        self.kel.events()
    }

    pub fn is_decommissioned(&self) -> bool {
        self.kel.is_decommissioned()
    }

    pub fn kel(&self) -> &Kel {
        &self.kel
    }

    pub fn key_provider(&self) -> &K {
        &self.key_provider
    }

    pub fn key_provider_mut(&mut self) -> &mut K {
        &mut self.key_provider
    }

    pub fn last_establishment_event(&self) -> Option<&KeyEvent> {
        self.kel.last_establishment_event().map(|e| &e.event)
    }

    pub fn last_event(&self) -> Option<&KeyEvent> {
        self.kel.last_event().map(|e| &e.event)
    }

    pub fn last_said(&self) -> Option<&str> {
        self.kel.last_said()
    }

    pub fn pending_events(&self) -> &[SignedKeyEvent] {
        &self.kel.events()[self.confirmed_cursor..]
    }

    pub fn prefix(&self) -> Option<&str> {
        self.kel.prefix()
    }

    /// Reload the KEL from the store, if one is configured.
    /// This is useful when the KEL may have been modified externally (e.g., by a CLI tool).
    pub async fn reload(&mut self) -> Result<(), KelsError> {
        let Some(ref store) = self.kel_store else {
            return Ok(());
        };
        let Some(prefix) = self.prefix().map(|s| s.to_string()) else {
            return Ok(());
        };
        if let Some(kel) = store.load(&prefix).await? {
            self.confirmed_cursor = kel.confirmed_length();
            self.kel = kel;
        }
        Ok(())
    }

    pub async fn should_add_rot_with_recover(&self) -> Result<bool, KelsError> {
        if let Some(client) = &self.kels_client
            && let Some(prefix) = self.prefix()
        {
            let mut kels_kel = client.get_kel(prefix).await?;
            let local_events = self.events();
            let local_set: HashSet<_> = local_events.iter().collect();
            let local_vec: Vec<_> = local_events.to_vec();

            let _ = kels_kel.merge(local_vec)?;
            if let Some(divergence) = kels_kel.find_divergence() {
                let owner_has_rot = local_events.iter().any(|e| {
                    divergence.divergent_saids.contains(&e.event.said)
                        && e.event.reveals_rotation_key()
                });

                if owner_has_rot {
                    // owner rotated
                    Ok(false)
                } else {
                    let adversarial_events: Vec<_> = kels_kel
                        .events()
                        .iter()
                        .filter(|e| !local_set.contains(e))
                        .collect();
                    Ok(adversarial_events
                        .iter()
                        .any(|e| e.event.reveals_rotation_key()))
                }
            } else {
                // not divergent
                Ok(false)
            }
        } else {
            // fail secure
            Ok(true)
        }
    }

    // ==================== Event Operations ====================

    pub async fn incept(&mut self) -> Result<SignedKeyEvent, KelsError> {
        let signed_event = self.create_signed_inception_event().await?;
        self.add_and_flush(std::slice::from_ref(&signed_event))
            .await?;
        Ok(signed_event)
    }

    pub async fn incept_delegated(
        &mut self,
        delegating_prefix: &str,
    ) -> Result<SignedKeyEvent, KelsError> {
        let signed_event = self
            .create_signed_delegated_inception_event(delegating_prefix)
            .await?;
        self.add_and_flush(std::slice::from_ref(&signed_event))
            .await?;
        Ok(signed_event)
    }

    pub async fn interact(&mut self, anchor: &str) -> Result<SignedKeyEvent, KelsError> {
        if self.is_decommissioned() {
            return Err(KelsError::KelDecommissioned);
        }

        let last_event = self.get_owner_tail().await?.event.clone();
        let signed_event = self
            .create_signed_interaction_event(&last_event, anchor)
            .await?;
        self.add_and_flush(std::slice::from_ref(&signed_event))
            .await?;
        Ok(signed_event)
    }

    pub async fn rotate(&mut self) -> Result<SignedKeyEvent, KelsError> {
        if self.is_decommissioned() {
            return Err(KelsError::KelDecommissioned);
        }

        let last_event = self.get_owner_tail().await?.event.clone();
        let signed_event = match self.create_signed_rotation_event(&last_event).await {
            Ok(r) => r,
            Err(e) => {
                self.key_provider.rollback().await?;
                return Err(e);
            }
        };
        self.add_and_flush(std::slice::from_ref(&signed_event))
            .await?;
        Ok(signed_event)
    }

    pub async fn decommission(&mut self) -> Result<SignedKeyEvent, KelsError> {
        if self.is_decommissioned() {
            return Err(KelsError::KelDecommissioned);
        }

        let last_event = self.get_owner_tail().await?.event.clone();
        let signed_event = match self.create_signed_decommission_event(&last_event).await {
            Ok(r) => r,
            Err(e) => {
                self.key_provider.rollback().await?;
                return Err(e);
            }
        };
        self.add_and_flush(std::slice::from_ref(&signed_event))
            .await?;
        Ok(signed_event)
    }

    pub async fn rotate_recovery(&mut self) -> Result<SignedKeyEvent, KelsError> {
        if self.is_decommissioned() {
            return Err(KelsError::KelDecommissioned);
        }

        let last_event = self.get_owner_tail().await?.event.clone();
        let signed_event = match self
            .create_signed_recovery_rotation_event(&last_event)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                self.key_provider.rollback().await?;
                return Err(e);
            }
        };
        self.add_and_flush(std::slice::from_ref(&signed_event))
            .await?;
        Ok(signed_event)
    }

    pub async fn recover(&mut self, add_rot: bool) -> Result<SignedKeyEvent, KelsError> {
        if self.is_decommissioned() {
            return Err(KelsError::KelDecommissioned);
        }

        let last_event = self.get_owner_tail().await?.event.clone();
        let signed_rec_event = match self.create_signed_recovery_event(&last_event).await {
            Ok(signed_event) => signed_event,
            Err(e) => {
                self.key_provider.rollback().await?;
                return Err(e);
            }
        };

        let mut events = vec![signed_rec_event.clone()];
        // we can add a rot intentionally in case the attacker determined the rotation key.
        // after recovery, they'd still be able to inject ixn if we didn't.
        //
        // however, this is only necessary if they exposed the rotation key which
        // is unlikely. our logic should be:
        //  1. ensure we didn't already rotate as the last, divergent event that will
        //     become authoritative after recovery
        //  2. if we didn't rotate, fetch from the server and determine if the attacker rotated
        //  3. if they did, we must rotate
        //
        // If we didn't rotate and the adversary did, we should add a rotation.
        let result = if add_rot {
            let signed_rot_event = match self
                .create_signed_rotation_event(&signed_rec_event.event)
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    self.key_provider.rollback().await?;
                    return Err(e);
                }
            };

            events.push(signed_rot_event.clone());
            signed_rot_event
        } else {
            signed_rec_event
        };

        self.add_and_flush(&events).await?;
        Ok(result)
    }

    pub async fn contest(&mut self) -> Result<SignedKeyEvent, KelsError> {
        if self.is_decommissioned() {
            return Err(KelsError::KelDecommissioned);
        }

        let last_event = self.get_owner_tail().await?.event.clone();
        let signed_event = match self.create_signed_contest_event(&last_event).await {
            Ok(r) => r,
            Err(e) => {
                self.key_provider.rollback().await?;
                return Err(e);
            }
        };

        match self
            .add_and_flush(std::slice::from_ref(&signed_event))
            .await
        {
            Err(e) => {
                match e {
                    // in this case, we expect and welcome divergence
                    KelsError::DivergenceDetected {
                        diverged_at: _,
                        submission_accepted,
                    } => {
                        if submission_accepted {
                            Ok(signed_event)
                        } else {
                            Err(e)
                        }
                    }
                    _ => Err(e),
                }
            }
            _ => Ok(signed_event),
        }
    }

    // ==================== Operations ====================

    async fn commit(&mut self, act: bool) -> Result<(), KelsError> {
        if act {
            self.key_provider.commit().await?;
        }

        Ok(())
    }

    async fn rollback(&mut self, act: bool) -> Result<(), KelsError> {
        if act {
            self.key_provider.rollback().await?;
        }

        Ok(())
    }

    async fn add_and_flush(&mut self, signed_events: &[SignedKeyEvent]) -> Result<(), KelsError> {
        let events = signed_events.iter().cloned();

        let has_staged = self.key_provider.has_staged().await;

        let old_length = self.kel.len();
        self.kel.extend(events);
        let flush_result = self.flush().await;
        let accepted = self.was_flush_accepted(&flush_result);

        if let Some(ref store) = self.kel_store
            && accepted
            && let Err(e) = store.save(self.kel()).await
        {
            self.kel.truncate(old_length);
            self.rollback(has_staged).await?;
            return Err(e);
        }

        if accepted {
            self.commit(has_staged).await?;
        } else {
            self.kel.truncate(old_length);
            self.rollback(has_staged).await?;
        }

        flush_result
    }

    async fn flush(&mut self) -> Result<(), KelsError> {
        let client = match &self.kels_client {
            Some(c) => c.clone(),
            None => {
                self.confirmed_cursor = self.kel.confirmed_length();
                return Ok(());
            }
        };

        let pending: Vec<_> = self.pending_events().to_vec();
        if pending.is_empty() {
            return Ok(());
        }

        let response = client.submit_events(&pending).await?;

        if response.accepted {
            self.confirmed_cursor = self.kel.confirmed_length();
        }

        if let Some(diverged_at) = response.diverged_at {
            Err(KelsError::DivergenceDetected {
                diverged_at,
                submission_accepted: response.accepted,
            })
        } else if !response.accepted {
            Err(KelsError::InvalidKel(
                "Rejected without divergence".to_string(),
            ))
        } else {
            Ok(())
        }
    }

    // ==================== Private Helpers ====================

    async fn get_owner_tail(&self) -> Result<&SignedKeyEvent, KelsError> {
        self.kel.last_event().ok_or(KelsError::NotIncepted)
    }

    pub fn was_flush_accepted(&self, flush_result: &Result<(), KelsError>) -> bool {
        matches!(
            flush_result,
            Ok(())
                | Err(KelsError::DivergenceDetected {
                    submission_accepted: true,
                    ..
                })
        )
    }

    /// Create a signed contest event from a base event.
    /// Returns (signed_event, event, primary_signature).
    async fn create_signed_contest_event(
        &mut self,
        base_event: &KeyEvent,
    ) -> Result<SignedKeyEvent, KelsError> {
        let (rotation_key, _next_hash) = self.key_provider.stage_rotation().await?;
        let (current_recovery_pub, _recovery_hash) =
            self.key_provider.stage_recovery_rotation().await?;

        let cnt_event =
            KeyEvent::create_contest(base_event, rotation_key.qb64(), current_recovery_pub.qb64())?;

        let cnt_primary_signature = self.key_provider.sign(cnt_event.said.as_bytes()).await?;
        let cnt_secondary_signature = self
            .key_provider
            .sign_with_recovery(cnt_event.said.as_bytes())
            .await?;

        Ok(SignedKeyEvent::new_recovery(
            cnt_event,
            rotation_key.qb64(),
            cnt_primary_signature.qb64(),
            current_recovery_pub.qb64(),
            cnt_secondary_signature.qb64(),
        ))
    }

    async fn create_signed_inception_event(&mut self) -> Result<SignedKeyEvent, KelsError> {
        let (current_key, rotation_hash, recovery_hash) =
            self.key_provider.generate_initial_keys().await?;

        let event = KeyEvent::create_inception(current_key.qb64(), rotation_hash, recovery_hash)?;
        let signature = self.key_provider.sign(event.said.as_bytes()).await?;

        Ok(SignedKeyEvent::new(
            event,
            current_key.qb64(),
            signature.qb64(),
        ))
    }

    async fn create_signed_delegated_inception_event(
        &mut self,
        delegating_prefix: &str,
    ) -> Result<SignedKeyEvent, KelsError> {
        let (current_key, rotation_hash, recovery_hash) =
            self.key_provider.generate_initial_keys().await?;

        let event = KeyEvent::create_delegated_inception(
            current_key.qb64(),
            rotation_hash,
            recovery_hash,
            delegating_prefix.to_string(),
        )?;
        let signature = self.key_provider.sign(event.said.as_bytes()).await?;

        Ok(SignedKeyEvent::new(
            event,
            current_key.qb64(),
            signature.qb64(),
        ))
    }

    async fn create_signed_interaction_event(
        &self,
        base_event: &KeyEvent,
        anchor: &str,
    ) -> Result<SignedKeyEvent, KelsError> {
        let current_key = self.key_provider.current_public_key().await?;

        let event = KeyEvent::create_interaction(base_event, anchor.to_string())?;
        let signature = self.key_provider.sign(event.said.as_bytes()).await?;

        Ok(SignedKeyEvent::new(
            event,
            current_key.qb64(),
            signature.qb64(),
        ))
    }

    async fn create_signed_rotation_event(
        &mut self,
        base_event: &KeyEvent,
    ) -> Result<SignedKeyEvent, KelsError> {
        let (new_current, rotation_hash) = self.key_provider.stage_rotation().await?;

        let event = KeyEvent::create_rotation(base_event, new_current.qb64(), Some(rotation_hash))?;
        let signature = self.key_provider.sign(event.said.as_bytes()).await?;

        Ok(SignedKeyEvent::new(
            event,
            new_current.qb64(),
            signature.qb64(),
        ))
    }

    async fn create_signed_decommission_event(
        &mut self,
        base_event: &KeyEvent,
    ) -> Result<SignedKeyEvent, KelsError> {
        let (new_current, _rotation_hash) = self.key_provider.stage_rotation().await?;
        let (current_recovery_pub, _recovery_hash) =
            self.key_provider.stage_recovery_rotation().await?;

        let event = KeyEvent::create_decommission(
            base_event,
            new_current.qb64(),
            current_recovery_pub.qb64(),
        )?;

        let primary_signature = self.key_provider.sign(event.said.as_bytes()).await?;
        let secondary_signature = self
            .key_provider
            .sign_with_recovery(event.said.as_bytes())
            .await?;

        Ok(SignedKeyEvent::new_recovery(
            event,
            new_current.qb64(),
            primary_signature.qb64(),
            current_recovery_pub.qb64(),
            secondary_signature.qb64(),
        ))
    }

    async fn create_signed_recovery_rotation_event(
        &mut self,
        base_event: &KeyEvent,
    ) -> Result<SignedKeyEvent, KelsError> {
        let (new_current, rotation_hash) = self.key_provider.stage_rotation().await?;

        let (current_recovery_pub, new_recovery_hash) =
            self.key_provider.stage_recovery_rotation().await?;

        let event = KeyEvent::create_recovery_rotation(
            base_event,
            new_current.qb64(),
            rotation_hash,
            current_recovery_pub.qb64(),
            new_recovery_hash,
        )?;

        let primary_signature = self.key_provider.sign(event.said.as_bytes()).await?;
        let secondary_signature = self
            .key_provider
            .sign_with_recovery(event.said.as_bytes())
            .await?;

        Ok(SignedKeyEvent::new_recovery(
            event,
            new_current.qb64(),
            primary_signature.qb64(),
            current_recovery_pub.qb64(),
            secondary_signature.qb64(),
        ))
    }

    async fn create_signed_recovery_event(
        &mut self,
        base_event: &KeyEvent,
    ) -> Result<SignedKeyEvent, KelsError> {
        let (rotation_key, new_rotation_hash) = self.key_provider.stage_rotation().await?;
        let (current_recovery_pub, new_recovery_hash) =
            self.key_provider.stage_recovery_rotation().await?;

        let rec_event = KeyEvent::create_recovery(
            base_event,
            rotation_key.qb64(),
            new_rotation_hash,
            current_recovery_pub.qb64(),
            new_recovery_hash,
        )?;

        let rec_primary_signature = self.key_provider.sign(rec_event.said.as_bytes()).await?;
        let rec_secondary_signature = self
            .key_provider
            .sign_with_recovery(rec_event.said.as_bytes())
            .await?;

        Ok(SignedKeyEvent::new_recovery(
            rec_event,
            rotation_key.qb64(),
            rec_primary_signature.qb64(),
            current_recovery_pub.qb64(),
            rec_secondary_signature.qb64(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use cesr::{Digest, Matter};

    use super::*;
    use crate::crypto::SoftwareKeyProvider;

    fn make_anchor() -> String {
        Digest::blake3_256(b"test_anchor").qb64()
    }

    #[tokio::test]
    async fn test_builder_new() {
        let builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        assert!(builder.prefix().is_none());
        assert!(builder.last_event().is_none());
        assert_eq!(builder.confirmed_count(), 0);
    }

    #[tokio::test]
    async fn test_builder_incept() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let icp = builder.incept().await.unwrap();

        assert!(icp.event.is_inception());
        assert!(builder.prefix().is_some());
        assert_eq!(builder.prefix(), Some(icp.event.prefix.as_str()));
        assert_eq!(builder.events().len(), 1);
    }

    #[tokio::test]
    async fn test_builder_incept_delegated() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let delegating_prefix = Digest::blake3_256(b"delegator").qb64();
        let dip = builder.incept_delegated(&delegating_prefix).await.unwrap();

        assert!(dip.event.is_delegated_inception());
        assert_eq!(dip.event.delegating_prefix, Some(delegating_prefix));
    }

    #[tokio::test]
    async fn test_builder_interact() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        builder.incept().await.unwrap();

        let anchor = make_anchor();
        let ixn = builder.interact(&anchor).await.unwrap();

        assert!(ixn.event.is_interaction());
        assert_eq!(ixn.event.anchor, Some(anchor));
        assert_eq!(builder.events().len(), 2);
    }

    #[tokio::test]
    async fn test_builder_rotate() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let icp = builder.incept().await.unwrap();
        let original_pub = builder.current_public_key().await.unwrap();

        let rot = builder.rotate().await.unwrap();

        assert!(rot.event.is_rotation());
        assert_eq!(rot.event.previous, Some(icp.event.said));

        let new_pub = builder.current_public_key().await.unwrap();
        assert_ne!(original_pub.qb64(), new_pub.qb64());
    }

    #[tokio::test]
    async fn test_builder_interact_before_incept_fails() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let result = builder.interact(&make_anchor()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_builder_rotate_before_incept_fails() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let result = builder.rotate().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_builder_decommission() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        builder.incept().await.unwrap();

        let dec = builder.decommission().await.unwrap();

        assert!(dec.event.is_decommission());
        assert!(builder.is_decommissioned());
    }

    #[tokio::test]
    async fn test_builder_decommission_before_incept_fails() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let result = builder.decommission().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_builder_interact_after_decommission_fails() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        builder.incept().await.unwrap();
        builder.decommission().await.unwrap();

        let result = builder.interact(&make_anchor()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_builder_rotate_after_decommission_fails() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        builder.incept().await.unwrap();
        builder.decommission().await.unwrap();

        let result = builder.rotate().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_builder_rotate_recovery() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        builder.incept().await.unwrap();

        let ror = builder.rotate_recovery().await.unwrap();

        assert!(ror.event.is_recovery_rotation());
        assert!(ror.event.recovery_key.is_some());
        assert!(ror.event.recovery_hash.is_some());
    }

    #[tokio::test]
    async fn test_builder_rotate_recovery_before_incept_fails() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let result = builder.rotate_recovery().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_builder_recover() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        builder.incept().await.unwrap();

        let rec = builder.recover(false).await.unwrap();

        assert!(rec.event.is_recover());
        assert!(rec.event.recovery_key.is_some());
    }

    #[tokio::test]
    async fn test_builder_recover_with_rotation() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        builder.incept().await.unwrap();

        let rot = builder.recover(true).await.unwrap();

        // When add_rot=true, we get a rotation event back (not the recovery event)
        assert!(rot.event.is_rotation());
        // KEL should have: icp, rec, rot
        assert_eq!(builder.events().len(), 3);
    }

    #[tokio::test]
    async fn test_builder_recover_before_incept_fails() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let result = builder.recover(false).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_builder_contest() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        builder.incept().await.unwrap();

        let cnt = builder.contest().await.unwrap();

        assert!(cnt.event.is_contest());
        assert!(cnt.event.recovery_key.is_some());
    }

    #[tokio::test]
    async fn test_builder_contest_before_incept_fails() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let result = builder.contest().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_builder_accessors() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let icp = builder.incept().await.unwrap();
        let ixn = builder.interact(&make_anchor()).await.unwrap();

        assert_eq!(builder.last_said(), Some(ixn.event.said.as_str()));
        assert_eq!(builder.last_event().unwrap().said, ixn.event.said);
        assert_eq!(
            builder.last_establishment_event().unwrap().said,
            icp.event.said
        );
        assert_eq!(builder.events().len(), 2);
        assert!(!builder.is_decommissioned());
    }

    #[tokio::test]
    async fn test_builder_pending_events_no_client() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        builder.incept().await.unwrap();
        builder.interact(&make_anchor()).await.unwrap();

        // Without a client, all events are "confirmed" locally
        assert!(builder.pending_events().is_empty());
    }

    #[tokio::test]
    async fn test_builder_key_provider_accessors() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        builder.incept().await.unwrap();

        // Test key_provider accessor
        let _provider = builder.key_provider();
        let _provider_mut = builder.key_provider_mut();
    }

    #[tokio::test]
    async fn test_builder_kel_accessor() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        builder.incept().await.unwrap();

        let kel = builder.kel();
        assert_eq!(kel.len(), 1);
    }

    #[tokio::test]
    async fn test_was_flush_accepted() {
        let builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);

        // Ok result is accepted
        assert!(builder.was_flush_accepted(&Ok(())));

        // Divergence with accepted=true is accepted
        assert!(
            builder.was_flush_accepted(&Err(KelsError::DivergenceDetected {
                diverged_at: 1,
                submission_accepted: true,
            }))
        );

        // Divergence with accepted=false is not accepted
        assert!(
            !builder.was_flush_accepted(&Err(KelsError::DivergenceDetected {
                diverged_at: 1,
                submission_accepted: false,
            }))
        );

        // Other errors are not accepted
        assert!(!builder.was_flush_accepted(&Err(KelsError::NotIncepted)));
    }

    #[tokio::test]
    async fn test_builder_with_kel() {
        let mut builder1 = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let icp = builder1.incept().await.unwrap();

        let kel = Kel::from_events(vec![icp.clone()], true).unwrap();

        let builder2 =
            KeyEventBuilder::with_kel(SoftwareKeyProvider::new(), None, None, kel).unwrap();

        assert_eq!(builder2.prefix(), Some(icp.event.prefix.as_str()));
        assert_eq!(builder2.events().len(), 1);
    }

    #[tokio::test]
    async fn test_builder_reload_no_store() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        builder.incept().await.unwrap();

        // Reload without store should succeed (no-op)
        builder.reload().await.unwrap();
    }

    #[tokio::test]
    async fn test_builder_reload_no_prefix() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);

        // No prefix yet, reload should succeed (no-op)
        builder.reload().await.unwrap();
    }

    #[tokio::test]
    async fn test_builder_with_dependencies_no_store() {
        let builder = KeyEventBuilder::with_dependencies(
            SoftwareKeyProvider::new(),
            None, // no client
            None, // no store
            None, // no prefix
        )
        .await
        .unwrap();

        assert!(builder.prefix().is_none());
        assert_eq!(builder.confirmed_count(), 0);
    }

    #[tokio::test]
    async fn test_builder_double_decommission_fails() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        builder.incept().await.unwrap();
        builder.decommission().await.unwrap();

        // Second decommission should fail
        let result = builder.decommission().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_builder_contest_after_decommission_fails() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        builder.incept().await.unwrap();
        builder.decommission().await.unwrap();

        // Contest after decommission should fail
        let result = builder.contest().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_builder_recover_after_decommission_fails() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        builder.incept().await.unwrap();
        builder.decommission().await.unwrap();

        // Recover after decommission should fail
        let result = builder.recover(false).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_builder_rotate_recovery_after_decommission_fails() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        builder.incept().await.unwrap();
        builder.decommission().await.unwrap();

        // Rotate recovery after decommission should fail
        let result = builder.rotate_recovery().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_builder_multiple_rotations() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        builder.incept().await.unwrap();

        let pub1 = builder.current_public_key().await.unwrap();
        builder.rotate().await.unwrap();
        let pub2 = builder.current_public_key().await.unwrap();
        builder.rotate().await.unwrap();
        let pub3 = builder.current_public_key().await.unwrap();

        // All public keys should be different
        assert_ne!(pub1.qb64(), pub2.qb64());
        assert_ne!(pub2.qb64(), pub3.qb64());
        assert_ne!(pub1.qb64(), pub3.qb64());
        assert_eq!(builder.events().len(), 3); // icp + 2 rotations
    }

    #[tokio::test]
    async fn test_builder_last_establishment_after_interactions() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let icp = builder.incept().await.unwrap();
        builder.interact(&make_anchor()).await.unwrap();
        builder.interact(&make_anchor()).await.unwrap();

        // Last establishment should still be icp
        assert_eq!(
            builder.last_establishment_event().unwrap().said,
            icp.event.said
        );
    }

    #[tokio::test]
    async fn test_builder_last_establishment_after_rotation() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        builder.incept().await.unwrap();
        builder.interact(&make_anchor()).await.unwrap();
        let rot = builder.rotate().await.unwrap();

        // Last establishment should now be rot
        assert_eq!(
            builder.last_establishment_event().unwrap().said,
            rot.event.said
        );
    }

    #[tokio::test]
    async fn test_builder_incept_delegated_has_prefix() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let delegating_prefix = Digest::blake3_256(b"delegator").qb64();

        // Can incept as delegated
        let dip = builder.incept_delegated(&delegating_prefix).await.unwrap();
        assert!(dip.event.is_delegated_inception());
        assert_eq!(dip.event.delegating_prefix, Some(delegating_prefix));
        assert!(builder.prefix().is_some());
    }
}
