//! Key Event Builder

use std::collections::HashSet;

use cesr::{Matter, PublicKey};

use crate::{
    client::KelsClient,
    crypto::KeyProvider,
    error::KelsError,
    store::KelStore,
    types::{KeyEvent, SignedKeyEvent},
};

pub struct KeyEventBuilder<K: KeyProvider + Clone> {
    key_provider: K,
    kels_client: Option<KelsClient>,
    kel_store: Option<std::sync::Arc<dyn KelStore>>,
    events: Vec<SignedKeyEvent>,
    confirmed_cursor: usize,
}

impl<K: KeyProvider + Clone> Clone for KeyEventBuilder<K> {
    fn clone(&self) -> Self {
        Self {
            key_provider: self.key_provider.clone(),
            kels_client: self.kels_client.clone(),
            kel_store: self.kel_store.clone(),
            events: self.events.clone(),
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
            events: Vec::new(),
            confirmed_cursor: 0,
        }
    }

    pub async fn with_dependencies(
        key_provider: K,
        kels_client: Option<KelsClient>,
        kel_store: Option<std::sync::Arc<dyn KelStore>>,
        prefix: Option<&str>,
    ) -> Result<Self, KelsError> {
        let events = match (&kel_store, prefix) {
            (Some(store), Some(p)) => {
                let (events, _) = store.load(p, crate::LOAD_ALL, 0).await?;
                events
            }
            _ => Vec::new(),
        };
        let confirmed_cursor = events.len();

        Ok(Self {
            key_provider,
            kels_client,
            kel_store,
            events,
            confirmed_cursor,
        })
    }

    pub fn with_events(
        key_provider: K,
        kels_client: Option<KelsClient>,
        kel_store: Option<std::sync::Arc<dyn KelStore>>,
        events: Vec<SignedKeyEvent>,
    ) -> Self {
        let confirmed_cursor = events.len();
        Self {
            key_provider,
            kels_client,
            kel_store,
            events,
            confirmed_cursor,
        }
    }

    // ==================== Accessors ====================

    pub fn confirmed_count(&self) -> usize {
        self.confirmed_cursor
    }

    pub async fn current_public_key(&self) -> Result<PublicKey, KelsError> {
        self.key_provider.current_public_key().await
    }

    pub fn events(&self) -> &[SignedKeyEvent] {
        &self.events
    }

    pub fn is_decommissioned(&self) -> bool {
        self.events
            .last()
            .map(|e| e.event.decommissions())
            .unwrap_or(false)
    }

    pub fn key_provider(&self) -> &K {
        &self.key_provider
    }

    pub fn key_provider_mut(&mut self) -> &mut K {
        &mut self.key_provider
    }

    pub fn last_establishment_event(&self) -> Option<&KeyEvent> {
        self.events
            .iter()
            .rev()
            .find(|e| e.event.is_establishment())
            .map(|e| &e.event)
    }

    pub fn last_event(&self) -> Option<&KeyEvent> {
        self.events.last().map(|e| &e.event)
    }

    pub fn last_said(&self) -> Option<&str> {
        self.events.last().map(|e| e.event.said.as_str())
    }

    pub fn pending_events(&self) -> &[SignedKeyEvent] {
        &self.events[self.confirmed_cursor..]
    }

    pub fn prefix(&self) -> Option<&str> {
        self.events.first().map(|e| e.event.prefix.as_str())
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
        let (events, _) = store.load(&prefix, crate::LOAD_ALL, 0).await?;
        if !events.is_empty() {
            self.confirmed_cursor = events.len();
            self.events = events;
        }
        Ok(())
    }

    /// Check if recovery should include a rotation (rec+rot vs just rec).
    ///
    /// Fetches server events, compares with local to detect adversary rotation.
    /// If the adversary revealed the rotation key, we need to rotate after recovery
    /// to prevent them from injecting events with the compromised key.
    pub async fn should_add_rot_with_recover(&self) -> Result<bool, KelsError> {
        if let Some(client) = &self.kels_client
            && let Some(prefix) = self.prefix()
        {
            // Fetch server events (paginated)
            let source = crate::HttpKelSource::new(client.base_url(), "/api/kels/kel/{prefix}");
            let server_events = crate::resolve_key_events(
                prefix,
                &source,
                crate::MAX_EVENTS_PER_KEL_QUERY,
                crate::max_verification_pages(),
                None,
            )
            .await?;

            let local_saids: HashSet<&str> = self
                .events()
                .iter()
                .map(|e| e.event.said.as_str())
                .collect();

            // Events on the server that we don't have locally = adversary events
            let adversary_events: Vec<_> = server_events
                .iter()
                .filter(|e| !local_saids.contains(e.event.said.as_str()))
                .collect();

            if adversary_events.is_empty() {
                // No adversary events — not divergent
                return Ok(false);
            }

            // Check if owner already rotated (our local events include a rotation
            // at the same serial range as the adversary events)
            let adversary_serials: HashSet<u64> =
                adversary_events.iter().map(|e| e.event.serial).collect();
            let owner_has_rot = self.events().iter().any(|e| {
                adversary_serials.contains(&e.event.serial) && e.event.reveals_rotation_key()
            });

            if owner_has_rot {
                // Owner already rotated — no need for additional rotation
                Ok(false)
            } else {
                // Check if adversary revealed the rotation key
                Ok(adversary_events
                    .iter()
                    .any(|e| e.event.reveals_rotation_key()))
            }
        } else {
            // Fail secure: no client = assume rotation needed
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
        match self
            .add_and_flush(std::slice::from_ref(&signed_event))
            .await
        {
            Ok(()) => Ok(signed_event),
            // Divergence is expected if an adversary event arrived via gossip before our ror.
            // The ror was accepted — keys are committed internally.
            Err(KelsError::DivergenceDetected {
                submission_accepted: true,
                ..
            }) => Ok(signed_event),
            Err(e) => Err(e),
        }
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
        let has_staged = self.key_provider.has_staged().await;

        let old_length = self.events.len();
        self.events.extend(signed_events.iter().cloned());
        let flush_result = self.flush().await;
        let accepted = self.was_flush_accepted(&flush_result);

        if let Some(ref store) = self.kel_store
            && accepted
            && let Some(prefix) = self.prefix().map(|s| s.to_string())
            && let Err(e) = store.save(&prefix, &self.events).await
        {
            self.events.truncate(old_length);
            self.rollback(has_staged).await?;
            return Err(e);
        }

        if accepted {
            self.commit(has_staged).await?;
        } else {
            self.events.truncate(old_length);
            self.rollback(has_staged).await?;
        }

        flush_result
    }

    async fn flush(&mut self) -> Result<(), KelsError> {
        let client = match &self.kels_client {
            Some(c) => c.clone(),
            None => {
                self.confirmed_cursor = self.events.len();
                return Ok(());
            }
        };

        let pending: Vec<_> = self.pending_events().to_vec();
        if pending.is_empty() {
            return Ok(());
        }

        let response = client.submit_events(&pending).await?;

        if response.applied {
            self.confirmed_cursor = self.events.len();
        }

        if let Some(diverged_at) = response.diverged_at {
            Err(KelsError::DivergenceDetected {
                diverged_at,
                submission_accepted: response.applied,
            })
        } else if !response.applied {
            Err(KelsError::InvalidKel(
                "Rejected without divergence".to_string(),
            ))
        } else {
            Ok(())
        }
    }

    // ==================== Private Helpers ====================

    async fn get_owner_tail(&self) -> Result<&SignedKeyEvent, KelsError> {
        self.events.last().ok_or(KelsError::NotIncepted)
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
