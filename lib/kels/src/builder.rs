//! Key Event Builder

use cesr::{Matter, VerificationKey};

use crate::{
    client::KelsClient,
    crypto::KeyProvider,
    error::KelsError,
    store::KelStore,
    types::{KelVerification, KeyEvent, SignedKeyEvent},
};

/// Determine if recovery should include a rotation based on server verification state.
///
/// Two conditions must both hold for an extra rotation to be needed:
/// 1. The server has more rotations than the owner (adversary revealed a rotation key)
/// 2. The owner hasn't already rotated past the divergence point (escaping to new keys)
///
/// If the KEL diverged and the owner's last establishment event is after the fork,
/// the adversary only had pre-fork keys and the current rotation key is safe.
pub fn should_rotate_with_recovery(
    server_verification: &KelVerification,
    owner_rotation_count: usize,
    owner_last_establishment_serial: u64,
) -> bool {
    if let Some(div_serial) = server_verification.diverged_at_serial()
        && owner_last_establishment_serial > div_serial
    {
        return false;
    }
    server_verification.rotation_count() > owner_rotation_count
}

pub struct KeyEventBuilder<K: KeyProvider> {
    key_provider: K,
    kels_client: Option<KelsClient>,
    kel_store: Option<std::sync::Arc<dyn KelStore>>,
    kel_verification: Option<KelVerification>,
    pending_events: Vec<SignedKeyEvent>,
}

impl<K: KeyProvider + Clone> Clone for KeyEventBuilder<K> {
    fn clone(&self) -> Self {
        Self {
            key_provider: self.key_provider.clone(),
            kels_client: self.kels_client.clone(),
            kel_store: self.kel_store.clone(),
            kel_verification: self.kel_verification.clone(),
            pending_events: self.pending_events.clone(),
        }
    }
}

impl<K: KeyProvider> KeyEventBuilder<K> {
    // ==================== Constructors ====================

    pub fn new(key_provider: K, kels_client: Option<KelsClient>) -> Self {
        Self {
            key_provider,
            kels_client,
            kel_store: None,
            kel_verification: None,
            pending_events: Vec::new(),
        }
    }

    pub async fn with_dependencies(
        key_provider: K,
        kels_client: Option<KelsClient>,
        kel_store: Option<std::sync::Arc<dyn KelStore>>,
        prefix: Option<&cesr::Digest256>,
    ) -> Result<Self, KelsError> {
        let kel_verification = match (&kel_store, prefix) {
            (Some(store), Some(p)) => {
                let verification = crate::completed_verification(
                    &mut crate::StorePageLoader::new(store.as_ref()),
                    p,
                    crate::page_size(),
                    crate::max_pages(),
                    std::iter::empty::<cesr::Digest256>(),
                )
                .await?;
                if verification.is_empty() {
                    None
                } else {
                    Some(verification)
                }
            }
            _ => None,
        };

        Ok(Self {
            key_provider,
            kels_client,
            kel_store,
            kel_verification,
            pending_events: Vec::new(),
        })
    }

    #[cfg(any(test, feature = "dev-tools"))]
    pub fn with_events(
        key_provider: K,
        kels_client: Option<KelsClient>,
        kel_store: Option<std::sync::Arc<dyn KelStore>>,
        events: Vec<SignedKeyEvent>,
    ) -> Self {
        // Verify inline to produce KelVerification
        let kel_verification = if events.is_empty() {
            None
        } else {
            let mut verifier = crate::KelVerifier::new(&events[0].event.prefix);
            match verifier.verify_page(&events) {
                Ok(()) => verifier.into_verification().ok(),
                Err(_) => None,
            }
        };

        Self {
            key_provider,
            kels_client,
            kel_store,
            kel_verification,
            pending_events: Vec::new(),
        }
    }

    // ==================== Accessors ====================

    pub fn confirmed_count(&self) -> usize {
        self.kel_verification
            .as_ref()
            .map(|v| v.event_count())
            .unwrap_or(0)
    }

    pub async fn current_public_key(&self) -> Result<VerificationKey, KelsError> {
        self.key_provider.current_public_key().await
    }

    pub fn is_decommissioned(&self) -> bool {
        if let Some(last) = self.pending_events.last() {
            return last.event.decommissions();
        }
        self.kel_verification
            .as_ref()
            .map(|v| v.is_decommissioned())
            .unwrap_or(false)
    }

    pub fn kel_verification(&self) -> &Option<KelVerification> {
        &self.kel_verification
    }

    pub fn key_provider(&self) -> &K {
        &self.key_provider
    }

    pub fn key_provider_mut(&mut self) -> &mut K {
        &mut self.key_provider
    }

    pub fn last_establishment_event(&self) -> Option<&KeyEvent> {
        // Check pending events first (most recent)
        if let Some(e) = self
            .pending_events
            .iter()
            .rev()
            .find(|e| e.event.is_establishment())
        {
            return Some(&e.event);
        }
        // Fall back to verification
        self.kel_verification
            .as_ref()
            .and_then(|v| v.last_establishment_event())
            .map(|e| &e.event)
    }

    pub fn last_event(&self) -> Option<&KeyEvent> {
        if let Some(last) = self.pending_events.last() {
            return Some(&last.event);
        }
        self.kel_verification
            .as_ref()
            .and_then(|v| v.branch_tips().first())
            .map(|bt| &bt.tip.event)
    }

    pub fn last_said(&self) -> Option<&cesr::Digest256> {
        if let Some(last) = self.pending_events.last() {
            return Some(&last.event.said);
        }
        self.kel_verification
            .as_ref()
            .and_then(|v| v.branch_tips().first())
            .map(|bt| &bt.tip.event.said)
    }

    pub fn pending_events(&self) -> &[SignedKeyEvent] {
        &self.pending_events
    }

    pub fn prefix(&self) -> Option<&cesr::Digest256> {
        if let Some(first) = self.pending_events.first() {
            return Some(&first.event.prefix);
        }
        self.kel_verification.as_ref().map(|v| v.prefix())
    }

    /// Reload the KEL from the store, if one is configured.
    /// This is useful when the KEL may have been modified externally (e.g., by a CLI tool).
    pub async fn reload(&mut self) -> Result<(), KelsError> {
        let Some(ref store) = self.kel_store else {
            return Ok(());
        };
        let Some(prefix) = self.prefix().cloned() else {
            return Ok(());
        };
        let verification = crate::completed_verification(
            &mut crate::StorePageLoader::new(store.as_ref()),
            &prefix,
            crate::page_size(),
            crate::max_pages(),
            std::iter::empty::<cesr::Digest256>(),
        )
        .await?;
        if !verification.is_empty() {
            self.kel_verification = Some(verification);
            self.pending_events.clear();
        }
        Ok(())
    }

    pub fn rotation_count(&self) -> usize {
        let verified_count = self
            .kel_verification
            .as_ref()
            .map(|v| v.rotation_count())
            .unwrap_or(0);
        let pending_count = self
            .pending_events
            .iter()
            .filter(|e| e.event.is_rotation() || e.event.is_recovery_rotation())
            .count();
        verified_count + pending_count
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
        delegating_prefix: &cesr::Digest256,
    ) -> Result<SignedKeyEvent, KelsError> {
        let signed_event = self
            .create_signed_delegated_inception_event(delegating_prefix)
            .await?;
        self.add_and_flush(std::slice::from_ref(&signed_event))
            .await?;
        Ok(signed_event)
    }

    pub async fn interact(
        &mut self,
        anchor: &cesr::Digest256,
    ) -> Result<SignedKeyEvent, KelsError> {
        if self.is_decommissioned() {
            return Err(KelsError::KelDecommissioned);
        }

        // Auto-insert ror if the proactive interval would be exceeded
        if self.needs_proactive_ror() {
            self.rotate_recovery().await?;
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

        // If proactive ror is due, use ror instead of rot — it rotates both
        // signing and recovery keys, satisfying the interval requirement.
        if self.needs_proactive_ror() {
            return self.rotate_recovery().await;
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

    /// Contest a KEL where the adversary has revealed the recovery key.
    ///
    /// If the adversary's recovery triggered archival of the owner's events,
    /// the server may no longer have the owner's chain. This method detects
    /// that by comparing local events with the server KEL and resubmits the
    /// minimal owner chain alongside the cnt event so the KEL remains
    /// verifiable after contest.
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

        // Determine which local events the server is missing (may have been
        // archived by the adversary's recovery). Include them in the batch so
        // the merge engine can verify the contest chain.
        let missing = self.find_missing_owner_events().await?;
        let mut batch = missing;
        batch.push(signed_event.clone());

        match self.add_and_flush(&batch).await {
            Err(e) => match e {
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
            },
            _ => Ok(signed_event),
        }
    }

    /// Find local owner events that the server doesn't have.
    ///
    /// Loads only the tail of the local KEL (bounded by `MINIMUM_PAGE_SIZE`)
    /// and walks backward, probing the server until finding an event that
    /// exists. Returns the missing events in forward (serial-ascending) order.
    ///
    /// Memory-bounded: the proactive ror invariant guarantees at most
    /// `MINIMUM_PAGE_SIZE` events can be missing (the adversary's recovery
    /// can only archive events back to the last recovery-revealing event).
    async fn find_missing_owner_events(&self) -> Result<Vec<SignedKeyEvent>, KelsError> {
        let client = match &self.kels_client {
            Some(c) => c,
            None => return Ok(Vec::new()),
        };
        let store = match &self.kel_store {
            Some(s) => s,
            None => return Ok(Vec::new()),
        };
        let prefix = self.prefix().ok_or(KelsError::NotIncepted)?;

        let tail = store
            .load_tail(prefix, crate::MINIMUM_PAGE_SIZE as u64)
            .await?;

        // Walk backward from the tail, probing the server for each event.
        // The first event the server has marks the boundary.
        let mut missing: Vec<SignedKeyEvent> = Vec::new();
        for event in tail.iter().rev() {
            if client.event_exists(&event.event.said).await? {
                break;
            }
            missing.push(event.clone());
        }

        missing.reverse();
        Ok(missing)
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

        let old_pending_len = self.pending_events.len();
        self.pending_events.extend(signed_events.iter().cloned());
        let flush_result = self.flush().await;
        let accepted = self.was_flush_accepted(&flush_result);

        if accepted {
            // Append new events to store
            if let Some(ref store) = self.kel_store
                && let Some(prefix) = self.prefix()
                && let Err(e) = store.append(prefix, signed_events).await
            {
                self.pending_events.truncate(old_pending_len);
                self.rollback(has_staged).await?;
                return Err(e);
            }

            // Re-verify pending events into kel_verification when connected
            // (has client or store). Leave events pending for offline builders
            // so tests and bench can access them.
            if self.kels_client.is_some() || self.kel_store.is_some() {
                self.absorb_pending()?;
            }
            self.commit(has_staged).await?;
        } else {
            self.pending_events.truncate(old_pending_len);
            self.rollback(has_staged).await?;
        }

        flush_result
    }

    /// Verify pending events and merge them into kel_verification.
    fn absorb_pending(&mut self) -> Result<(), KelsError> {
        if self.pending_events.is_empty() {
            return Ok(());
        }

        let prefix = *self.prefix().ok_or(KelsError::NotIncepted)?;

        let mut verifier = if let Some(ref v) = self.kel_verification {
            crate::KelVerifier::resume(&prefix, v)?
        } else {
            crate::KelVerifier::new(&prefix)
        };

        verifier.verify_page(&self.pending_events)?;
        self.kel_verification = Some(verifier.into_verification()?);
        self.pending_events.clear();
        Ok(())
    }

    async fn flush(&mut self) -> Result<(), KelsError> {
        let client = match &self.kels_client {
            Some(c) => c.clone(),
            None => {
                // No client — all events are considered confirmed locally
                return Ok(());
            }
        };

        if self.pending_events.is_empty() {
            return Ok(());
        }

        let response = client.submit_events(&self.pending_events).await?;

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

    /// Check if a proactive recovery rotation (ror) is needed before the next
    /// non-revealing event. Compares the counter from kel_verification (confirmed
    /// events) plus any non-revealing pending events against the limit.
    fn needs_proactive_ror(&self) -> bool {
        let confirmed_count = self
            .kel_verification
            .as_ref()
            .map(|v| v.events_since_last_revealing())
            .unwrap_or(0);

        let pending_non_revealing = self
            .pending_events
            .iter()
            .rev()
            .take_while(|e| !e.event.reveals_recovery_key())
            .count();

        // Adding one more non-revealing event would exceed the limit
        confirmed_count + pending_non_revealing >= crate::MAX_NON_REVEALING_EVENTS
    }

    async fn get_owner_tail(&self) -> Result<&SignedKeyEvent, KelsError> {
        if let Some(last) = self.pending_events.last() {
            return Ok(last);
        }
        self.kel_verification
            .as_ref()
            .and_then(|v| v.branch_tips().first())
            .map(|bt| &bt.tip)
            .ok_or(KelsError::NotIncepted)
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

        let cnt_event = KeyEvent::create_contest(base_event, rotation_key, current_recovery_pub)?;

        let said_bytes = cnt_event.said.qb64();
        let cnt_primary_signature = self.key_provider.sign(said_bytes.as_bytes()).await?;
        let cnt_secondary_signature = self
            .key_provider
            .sign_with_recovery(said_bytes.as_bytes())
            .await?;

        Ok(SignedKeyEvent::new_recovery(
            cnt_event,
            cnt_primary_signature,
            cnt_secondary_signature,
        ))
    }

    async fn create_signed_inception_event(&mut self) -> Result<SignedKeyEvent, KelsError> {
        let (current_key, rotation_hash, recovery_hash) =
            self.key_provider.generate_initial_keys().await?;

        let event = KeyEvent::create_inception(current_key, rotation_hash, recovery_hash)?;
        let signature = self.key_provider.sign(event.said.qb64().as_bytes()).await?;

        Ok(SignedKeyEvent::new(event, "signing".to_string(), signature))
    }

    async fn create_signed_delegated_inception_event(
        &mut self,
        delegating_prefix: &cesr::Digest256,
    ) -> Result<SignedKeyEvent, KelsError> {
        let (current_key, rotation_hash, recovery_hash) =
            self.key_provider.generate_initial_keys().await?;

        let event = KeyEvent::create_delegated_inception(
            current_key,
            rotation_hash,
            recovery_hash,
            *delegating_prefix,
        )?;
        let signature = self.key_provider.sign(event.said.qb64().as_bytes()).await?;

        Ok(SignedKeyEvent::new(event, "signing".to_string(), signature))
    }

    async fn create_signed_interaction_event(
        &self,
        base_event: &KeyEvent,
        anchor: &cesr::Digest256,
    ) -> Result<SignedKeyEvent, KelsError> {
        let event = KeyEvent::create_interaction(base_event, *anchor)?;
        let signature = self.key_provider.sign(event.said.qb64().as_bytes()).await?;

        Ok(SignedKeyEvent::new(event, "signing".to_string(), signature))
    }

    async fn create_signed_rotation_event(
        &mut self,
        base_event: &KeyEvent,
    ) -> Result<SignedKeyEvent, KelsError> {
        let (new_current, rotation_hash) = self.key_provider.stage_rotation().await?;

        let event = KeyEvent::create_rotation(base_event, new_current, Some(rotation_hash))?;
        let signature = self.key_provider.sign(event.said.qb64().as_bytes()).await?;

        Ok(SignedKeyEvent::new(event, "signing".to_string(), signature))
    }

    async fn create_signed_decommission_event(
        &mut self,
        base_event: &KeyEvent,
    ) -> Result<SignedKeyEvent, KelsError> {
        let (new_current, _rotation_hash) = self.key_provider.stage_rotation().await?;
        let (current_recovery_pub, _recovery_hash) =
            self.key_provider.stage_recovery_rotation().await?;

        let event = KeyEvent::create_decommission(base_event, new_current, current_recovery_pub)?;

        let said_bytes = event.said.qb64();
        let primary_signature = self.key_provider.sign(said_bytes.as_bytes()).await?;
        let secondary_signature = self
            .key_provider
            .sign_with_recovery(said_bytes.as_bytes())
            .await?;

        Ok(SignedKeyEvent::new_recovery(
            event,
            primary_signature,
            secondary_signature,
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
            new_current,
            rotation_hash,
            current_recovery_pub,
            new_recovery_hash,
        )?;

        let said_bytes = event.said.qb64();
        let primary_signature = self.key_provider.sign(said_bytes.as_bytes()).await?;
        let secondary_signature = self
            .key_provider
            .sign_with_recovery(said_bytes.as_bytes())
            .await?;

        Ok(SignedKeyEvent::new_recovery(
            event,
            primary_signature,
            secondary_signature,
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
            rotation_key,
            new_rotation_hash,
            current_recovery_pub,
            new_recovery_hash,
        )?;

        let said_bytes = rec_event.said.qb64();
        let rec_primary_signature = self.key_provider.sign(said_bytes.as_bytes()).await?;
        let rec_secondary_signature = self
            .key_provider
            .sign_with_recovery(said_bytes.as_bytes())
            .await?;

        Ok(SignedKeyEvent::new_recovery(
            rec_event,
            rec_primary_signature,
            rec_secondary_signature,
        ))
    }
}
