//! Key Event Builder

use std::collections::HashSet;

use crate::client::KelsClient;
use crate::crypto::KeyProvider;
use crate::error::KelsError;
use crate::kel::Kel;
use crate::store::KelStore;
use crate::types::{KeyEvent, SignedKeyEvent};
use cesr::{Matter, PublicKey, Signature};

pub struct KeyEventBuilder<K: KeyProvider> {
    key_provider: K,
    #[allow(dead_code)]
    kels_client: Option<KelsClient>,
    kel_store: Option<std::sync::Arc<dyn KelStore>>,
    kel: Kel,
    confirmed_cursor: usize,
}

impl<K: KeyProvider> KeyEventBuilder<K> {
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
        let confirmed_cursor = kel.len();

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
        let confirmed_cursor = kel.len();
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

    pub fn is_fully_confirmed(&self) -> bool {
        self.confirmed_cursor == self.kel.events().len()
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
            self.confirmed_cursor = kel.len();
            self.kel = kel;
        }
        Ok(())
    }

    pub async fn should_add_rot_with_recover(&self) -> Result<bool, KelsError> {
        if let Some(client) = &self.kels_client
            && let Some(prefix) = self.prefix()
        {
            let mut kels_kel = client.fetch_full_kel(prefix).await?;
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

    pub async fn incept(&mut self) -> Result<(KeyEvent, Signature), KelsError> {
        let (signed_event, event, signature) = self.create_signed_inception_event().await?;
        self.add_and_flush(&[signed_event]).await?;
        Ok((event, signature))
    }

    pub async fn incept_delegated(
        &mut self,
        delegating_prefix: &str,
    ) -> Result<(KeyEvent, Signature), KelsError> {
        let (signed_event, event, signature) = self
            .create_signed_delegated_inception_event(delegating_prefix)
            .await?;
        self.add_and_flush(&[signed_event]).await?;
        Ok((event, signature))
    }

    pub async fn interact(&mut self, anchor: &str) -> Result<(KeyEvent, Signature), KelsError> {
        if self.is_decommissioned() {
            return Err(KelsError::KelDecommissioned);
        }

        let last_event = self.get_owner_tail().await?.event.clone();
        let (signed_event, event, signature) = self
            .create_signed_interaction_event(&last_event, anchor)
            .await?;
        self.add_and_flush(&[signed_event]).await?;
        Ok((event, signature))
    }

    pub async fn rotate(&mut self) -> Result<(KeyEvent, Signature), KelsError> {
        if self.is_decommissioned() {
            return Err(KelsError::KelDecommissioned);
        }

        let last_event = self.get_owner_tail().await?.event.clone();
        let (signed_event, event, signature) =
            match self.create_signed_rotation_event(&last_event).await {
                Ok(r) => r,
                Err(e) => {
                    self.key_provider.rollback().await?;
                    return Err(e);
                }
            };
        self.add_and_flush(&[signed_event]).await?;
        Ok((event, signature))
    }

    pub async fn decommission(&mut self) -> Result<(KeyEvent, Signature), KelsError> {
        if self.is_decommissioned() {
            return Err(KelsError::KelDecommissioned);
        }

        let last_event = self.get_owner_tail().await?.event.clone();
        let (signed_event, event, primary_signature) =
            match self.create_signed_decommission_event(&last_event).await {
                Ok(r) => r,
                Err(e) => {
                    self.key_provider.rollback().await?;
                    return Err(e);
                }
            };
        self.add_and_flush(&[signed_event]).await?;
        Ok((event, primary_signature))
    }

    pub async fn rotate_recovery(&mut self) -> Result<(KeyEvent, Signature), KelsError> {
        if self.is_decommissioned() {
            return Err(KelsError::KelDecommissioned);
        }

        let last_event = self.get_owner_tail().await?.event.clone();
        let (signed_event, event, primary_signature) = match self
            .create_signed_recovery_rotation_event(&last_event)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                self.key_provider.rollback().await?;
                return Err(e);
            }
        };
        self.add_and_flush(&[signed_event]).await?;
        Ok((event, primary_signature))
    }

    pub async fn recover(&mut self, add_rot: bool) -> Result<(KeyEvent, Signature), KelsError> {
        if self.is_decommissioned() {
            return Err(KelsError::KelDecommissioned);
        }

        let last_event = self.get_owner_tail().await?.event.clone();
        let (signed_rec_event, rec_event, rec_signature) =
            match self.create_signed_recovery_event(&last_event).await {
                Ok((signed_event, event, signature)) => (signed_event, event, signature),
                Err(e) => {
                    self.key_provider.rollback().await?;
                    return Err(e);
                }
            };

        let mut events = vec![signed_rec_event];
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
        let (event, signature) = if add_rot {
            let (signed_rot_event, rot_event, rot_signature) =
                match self.create_signed_rotation_event(&rec_event).await {
                    Ok(r) => r,
                    Err(e) => {
                        self.key_provider.rollback().await?;
                        return Err(e);
                    }
                };

            events.push(signed_rot_event);
            (rot_event, rot_signature)
        } else {
            (rec_event, rec_signature)
        };

        self.add_and_flush(&events).await?;
        Ok((event, signature))
    }

    pub async fn contest(&mut self) -> Result<(KeyEvent, Signature), KelsError> {
        if self.is_decommissioned() {
            return Err(KelsError::KelDecommissioned);
        }

        let last_event = self.get_owner_tail().await?.event.clone();
        let (signed_event, event, signature) =
            match self.create_signed_contest_event(&last_event).await {
                Ok(r) => r,
                Err(e) => {
                    self.key_provider.rollback().await?;
                    return Err(e);
                }
            };
        self.add_and_flush(&[signed_event]).await?;
        Ok((event, signature))
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
                self.confirmed_cursor = self.kel.len();
                return Ok(());
            }
        };

        let pending: Vec<_> = self.pending_events().to_vec();
        if pending.is_empty() {
            return Ok(());
        }

        let response = client.submit_events(&pending).await?;
        if let Some(diverged_at) = response.diverged_at {
            Err(KelsError::DivergenceDetected {
                diverged_at,
                submission_accepted: response.accepted,
            })
        } else if response.accepted {
            self.confirmed_cursor = self.kel.len();
            Ok(())
        } else {
            Err(KelsError::InvalidKel(
                "Rejected without divergence".to_string(),
            ))
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
    ) -> Result<(SignedKeyEvent, KeyEvent, Signature), KelsError> {
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

        let signed_cnt_event = SignedKeyEvent::new_recovery(
            cnt_event.clone(),
            rotation_key.qb64(),
            cnt_primary_signature.qb64(),
            current_recovery_pub.qb64(),
            cnt_secondary_signature.qb64(),
        );

        Ok((signed_cnt_event, cnt_event, cnt_primary_signature))
    }

    /// Create a signed inception event.
    /// Generates all keys. Caller should handle any cleanup on failure.
    /// Returns (signed_event, event, signature).
    async fn create_signed_inception_event(
        &mut self,
    ) -> Result<(SignedKeyEvent, KeyEvent, Signature), KelsError> {
        let (current_key, rotation_hash, recovery_hash) =
            self.key_provider.generate_initial_keys().await?;

        let event = KeyEvent::create_inception(current_key.qb64(), rotation_hash, recovery_hash)?;
        let signature = self.key_provider.sign(event.said.as_bytes()).await?;

        let signed_event = SignedKeyEvent::new(event.clone(), current_key.qb64(), signature.qb64());

        Ok((signed_event, event, signature))
    }

    /// Create a signed delegated inception event.
    /// Generates all keys. Caller should handle any cleanup on failure.
    /// Returns (signed_event, event, signature).
    async fn create_signed_delegated_inception_event(
        &mut self,
        delegating_prefix: &str,
    ) -> Result<(SignedKeyEvent, KeyEvent, Signature), KelsError> {
        let (current_key, rotation_hash, recovery_hash) =
            self.key_provider.generate_initial_keys().await?;

        let event = KeyEvent::create_delegated_inception(
            current_key.qb64(),
            rotation_hash,
            recovery_hash,
            delegating_prefix.to_string(),
        )?;
        let signature = self.key_provider.sign(event.said.as_bytes()).await?;

        let signed_event = SignedKeyEvent::new(event.clone(), current_key.qb64(), signature.qb64());

        Ok((signed_event, event, signature))
    }

    /// Create a signed interaction event from a base event.
    /// Returns (signed_event, event, signature).
    async fn create_signed_interaction_event(
        &self,
        base_event: &KeyEvent,
        anchor: &str,
    ) -> Result<(SignedKeyEvent, KeyEvent, Signature), KelsError> {
        let current_key = self.key_provider.current_public_key().await?;

        let event = KeyEvent::create_interaction(base_event, anchor.to_string())?;
        let signature = self.key_provider.sign(event.said.as_bytes()).await?;

        let signed_event = SignedKeyEvent::new(event.clone(), current_key.qb64(), signature.qb64());

        Ok((signed_event, event, signature))
    }

    /// Create a signed rotation event from a base event.
    /// Prepares key rotation. Caller must commit/rollback.
    /// Returns (signed_event, event, signature).
    async fn create_signed_rotation_event(
        &mut self,
        base_event: &KeyEvent,
    ) -> Result<(SignedKeyEvent, KeyEvent, Signature), KelsError> {
        let (new_current, rotation_hash) = self.key_provider.stage_rotation().await?;

        let event = KeyEvent::create_rotation(base_event, new_current.qb64(), Some(rotation_hash))?;
        let signature = self.key_provider.sign(event.said.as_bytes()).await?;

        let signed_event = SignedKeyEvent::new(event.clone(), new_current.qb64(), signature.qb64());

        Ok((signed_event, event, signature))
    }

    /// Create a signed decommission event from a base event.
    /// Prepares key rotation. Caller must commit/rollback.
    /// Returns (signed_event, event, primary_signature).
    async fn create_signed_decommission_event(
        &mut self,
        base_event: &KeyEvent,
    ) -> Result<(SignedKeyEvent, KeyEvent, Signature), KelsError> {
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

        let signed_event = SignedKeyEvent::new_recovery(
            event.clone(),
            new_current.qb64(),
            primary_signature.qb64(),
            current_recovery_pub.qb64(),
            secondary_signature.qb64(),
        );

        Ok((signed_event, event, primary_signature))
    }

    /// Create a signed recovery rotation event from a base event.
    /// Prepares key rotation and recovery rotation. Caller must commit/rollback.
    /// Returns (signed_event, event, primary_signature).
    async fn create_signed_recovery_rotation_event(
        &mut self,
        base_event: &KeyEvent,
    ) -> Result<(SignedKeyEvent, KeyEvent, Signature), KelsError> {
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

        let signed_event = SignedKeyEvent::new_recovery(
            event.clone(),
            new_current.qb64(),
            primary_signature.qb64(),
            current_recovery_pub.qb64(),
            secondary_signature.qb64(),
        );

        Ok((signed_event, event, primary_signature))
    }

    /// Create a signed recovery event from a base event.
    /// Prepares key rotation and recovery rotation. Caller must commit/rollback.
    /// Returns (signed_event, event, primary_signature).
    async fn create_signed_recovery_event(
        &mut self,
        base_event: &KeyEvent,
    ) -> Result<(SignedKeyEvent, KeyEvent, Signature), KelsError> {
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

        let signed_rec_event = SignedKeyEvent::new_recovery(
            rec_event.clone(),
            rotation_key.qb64(),
            rec_primary_signature.qb64(),
            current_recovery_pub.qb64(),
            rec_secondary_signature.qb64(),
        );

        Ok((signed_rec_event, rec_event, rec_primary_signature))
    }
}
