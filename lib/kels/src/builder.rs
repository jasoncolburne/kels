//! Key Event Builder
//!
//! Provides `KeyEventBuilder` for creating key events with auto-flush to KELS.

use crate::client::KelsClient;
use crate::crypto::KeyProvider;
use crate::error::KelsError;
use crate::kel::{Kel, KelBuilderState, compute_rotation_hash};
use crate::store::KelStore;
use crate::types::{KeyEvent, RecoveryOutcome, SignedKeyEvent};
use cesr::{Matter, PublicKey, Signature};

fn compute_rotation_hash_from_key(key: &PublicKey) -> String {
    compute_rotation_hash(&key.qb64())
}

/// Builder for creating key events with auto-flush to KELS.
///
/// When created with a KelsClient, events are automatically submitted to KELS
/// after creation, with automatic divergence recovery. Pass `None` for offline use.
///
/// When created with a KelStore, events are automatically saved locally after
/// each successful operation.
pub struct KeyEventBuilder {
    key_provider: KeyProvider,
    /// Cached state derived from events (last event, establishment, confirmed cursor)
    state: KelBuilderState,
    #[allow(dead_code)] // Used only on native/mobile for auto-flush
    kels_client: Option<KelsClient>,
    kel_store: Option<std::sync::Arc<dyn KelStore>>,
    events: Vec<SignedKeyEvent>,
}

impl KeyEventBuilder {
    /// Create a new builder with optional KELS client (no local store).
    ///
    /// For auto-save to local storage, use `with_dependencies()` instead.
    pub fn new(key_provider: KeyProvider, kels_client: Option<KelsClient>) -> Self {
        Self {
            key_provider,
            state: KelBuilderState {
                last_trusted_event: None,
                last_trusted_establishment_event: None,
                trusted_cursor: 0,
            },
            kels_client,
            kel_store: None,
            events: Vec::new(),
        }
    }

    /// Create a builder with existing KEL state.
    pub fn with_kel(key_provider: KeyProvider, kels_client: Option<KelsClient>, kel: &Kel) -> Self {
        let events: Vec<SignedKeyEvent> = kel.iter().cloned().collect();
        let state = kel.builder_state();

        Self {
            key_provider,
            state,
            kels_client,
            kel_store: None,
            events,
        }
    }

    /// Create a builder with optional KELS client, local store, and prefix.
    ///
    /// If `prefix` and `kel_store` are both provided, attempts to load existing KEL state.
    /// If no KEL exists for the prefix (or no prefix provided), the builder is ready for `incept()`.
    ///
    /// Events are automatically submitted to KELS (if client provided) and saved
    /// to the local store (if store provided) after each successful operation.
    pub async fn with_dependencies(
        key_provider: KeyProvider,
        kels_client: Option<KelsClient>,
        kel_store: Option<std::sync::Arc<dyn KelStore>>,
        prefix: Option<&str>,
    ) -> Result<Self, KelsError> {
        // Try to load existing KEL if store and prefix provided
        let kel = match (&kel_store, prefix) {
            (Some(store), Some(p)) => store.load(p).await?,
            _ => None,
        };

        if let Some(kel) = kel {
            let events: Vec<SignedKeyEvent> = kel.iter().cloned().collect();
            let state = kel.builder_state();

            Ok(Self {
                key_provider,
                state,
                kels_client,
                kel_store,
                events,
            })
        } else {
            Ok(Self {
                key_provider,
                state: KelBuilderState {
                    last_trusted_event: None,
                    last_trusted_establishment_event: None,
                    trusted_cursor: 0,
                },
                kels_client,
                kel_store,
                events: Vec::new(),
            })
        }
    }

    /// Update the events and recompute state from them.
    ///
    /// This replaces the current events with the provided ones and recomputes
    /// `last_event`, `last_establishment_event`, and `confirmed_cursor` based
    /// on the new events (handling divergence correctly).
    fn set_events(&mut self, events: Vec<SignedKeyEvent>) {
        self.events = events;
        self.state = KelBuilderState::from_events(&self.events);
    }

    /// Check if this builder's KEL is decommissioned.
    pub fn is_decommissioned(&self) -> bool {
        self.state
            .last_trusted_establishment_event
            .as_ref()
            .map(|e| e.is_decommission())
            .unwrap_or(false)
            || self.events.iter().any(|e| e.event.is_contest())
    }

    /// Create an inception event with new keys.
    /// Only available on native/mobile platforms (requires OsRng for key generation).
    ///
    /// Generates three keys: current (signing), next (pre-committed), and recovery.
    pub async fn incept(&mut self) -> Result<(KeyEvent, Signature), KelsError> {
        let current_key = self.key_provider.generate_keypair().await?;
        let next_key = self.key_provider.generate_keypair().await?;
        let recovery_key = self.key_provider.generate_recovery_key().await?;
        let rotation_hash = compute_rotation_hash_from_key(&next_key);
        let recovery_hash = compute_rotation_hash_from_key(&recovery_key);

        let event = KeyEvent::create_inception(current_key.qb64(), rotation_hash, recovery_hash)?;
        let signature = self.key_provider.sign(event.said.as_bytes()).await?;
        self.add_and_flush(event.clone(), current_key.qb64(), signature.clone(), true)
            .await?;

        Ok((event, signature))
    }

    /// Create a delegated inception event with new keys.
    /// Only available on native/mobile platforms (requires OsRng for key generation).
    ///
    /// Generates three keys: current (signing), next (pre-committed), and recovery.
    pub async fn incept_delegated(
        &mut self,
        delegating_prefix: &str,
    ) -> Result<(KeyEvent, Signature), KelsError> {
        let current_key = self.key_provider.generate_keypair().await?;
        let next_key = self.key_provider.generate_keypair().await?;
        let recovery_key = self.key_provider.generate_recovery_key().await?;
        let rotation_hash = compute_rotation_hash_from_key(&next_key);
        let recovery_hash = compute_rotation_hash_from_key(&recovery_key);

        let event = KeyEvent::create_delegated_inception(
            current_key.qb64(),
            rotation_hash,
            recovery_hash,
            delegating_prefix.to_string(),
        )?;
        let signature = self.key_provider.sign(event.said.as_bytes()).await?;
        self.add_and_flush(event.clone(), current_key.qb64(), signature.clone(), true)
            .await?;

        Ok((event, signature))
    }

    /// Create a rotation event - promotes next key to current.
    /// Only available on native/mobile platforms (requires OsRng for key generation).
    ///
    /// Uses two-phase rotation: signing key is staged first, then only committed
    /// if KELS accepts the event without divergence. On divergence, the key
    /// rotation is rolled back so recovery can use the correct keys.
    pub async fn rotate(&mut self) -> Result<(KeyEvent, Signature), KelsError> {
        if self.is_decommissioned() {
            return Err(KelsError::KelDecommissioned);
        }

        let last_event = self
            .state
            .last_trusted_event
            .as_ref()
            .ok_or(KelsError::NotIncepted)?;

        // PHASE 1: Prepare rotation (stage keys, don't commit yet)
        let new_current = self.key_provider.prepare_rotation().await?;
        let new_next = self.key_provider.pending_next_public_key().await?;
        let rotation_hash = compute_rotation_hash_from_key(&new_next);

        let event = KeyEvent::create_rotation(last_event, new_current.qb64(), Some(rotation_hash))?;
        let signature = self
            .key_provider
            .sign_with_pending(event.said.as_bytes())
            .await?;

        // PHASE 2: Submit to KELS
        let flush_result = self
            .add_and_flush(event.clone(), new_current.qb64(), signature.clone(), true)
            .await;

        // PHASE 3: Handle result
        match &flush_result {
            Ok(()) => {
                self.key_provider.commit_rotation().await;
            }
            Err(KelsError::DivergenceDetected {
                submission_accepted: true,
                ..
            }) => {
                // Event was accepted but caused divergence - commit the rotation
                self.key_provider.commit_rotation().await;
            }
            Err(KelsError::DivergenceDetected {
                submission_accepted: false,
                ..
            }) => {
                // Event was rejected (KEL already divergent) - rollback
                self.key_provider.rollback_rotation().await;
            }
            Err(_) => {
                // Rollback on other errors
                self.key_provider.rollback_rotation().await;
            }
        }

        flush_result?;
        Ok((event, signature))
    }

    /// Create a decommissioning event (no further events allowed).
    ///
    /// This creates a `dec` event which permanently freezes the KEL.
    /// Requires dual signatures (signing key + recovery key).
    ///
    /// Uses two-phase rotation: signing key is staged first, then only committed
    /// if KELS accepts the event. On failure, staged key is rolled back.
    pub async fn decommission(&mut self) -> Result<(KeyEvent, Signature), KelsError> {
        if self.is_decommissioned() {
            return Err(KelsError::KelDecommissioned);
        }

        let last_event = self
            .state
            .last_trusted_event
            .as_ref()
            .ok_or(KelsError::NotIncepted)?;

        // Prepare signing key rotation (to access pre-committed next key)
        let new_current = self.key_provider.prepare_rotation().await?;

        // Get current recovery key (just reveal, no rotation)
        let current_recovery_pub = self.key_provider.recovery_public_key().await?;

        // Create dec event (voluntary decommission)
        let event = KeyEvent::create_decommission(
            last_event,
            new_current.qb64(),
            current_recovery_pub.qb64(),
        )?;

        // Dual signatures
        let primary_signature = self
            .key_provider
            .sign_with_pending(event.said.as_bytes())
            .await?;
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

        // If no KELS client, commit and return (offline mode for tests)
        let Some(client) = self.kels_client.as_ref().cloned() else {
            self.key_provider.commit_rotation().await;
            self.events.push(signed_event);
            self.state.update_establishment(&event);
            return Ok((event, primary_signature));
        };

        // Submit to KELS
        let response = client
            .submit_events(std::slice::from_ref(&signed_event))
            .await;

        match response {
            Ok(resp) if resp.accepted => {
                // Commit signing key rotation
                self.key_provider.commit_rotation().await;

                // Update local state
                self.events.push(signed_event);
                self.state.update_establishment(&event);

                // Save to local store if configured
                if let Some(ref store) = self.kel_store {
                    store.save(&self.kel()?).await?;
                }

                Ok((event, primary_signature))
            }
            Ok(_) => {
                // Rollback on rejection
                self.key_provider.rollback_rotation().await;
                Err(KelsError::SubmissionFailed(
                    "Decommission event rejected by KELS".into(),
                ))
            }
            Err(e) => {
                // Rollback on error
                self.key_provider.rollback_rotation().await;
                Err(e)
            }
        }
    }

    /// Rotate both signing and recovery keys proactively.
    ///
    /// This creates a `ror` event that rotates both keys at once, providing
    /// stronger key hygiene than separate rotations. Requires dual signatures.
    ///
    /// Uses two-phase rotation: keys are staged first, then only committed
    /// if KELS accepts the event. On failure, staged keys are rolled back.
    ///
    /// Returns the ror event and primary signature on success.
    pub async fn rotate_recovery(&mut self) -> Result<(KeyEvent, Signature), KelsError> {
        let client = self
            .kels_client
            .as_ref()
            .ok_or_else(|| {
                KelsError::OfflineMode("Cannot rotate recovery without KELS client".into())
            })?
            .clone();

        if self.is_decommissioned() {
            return Err(KelsError::KelDecommissioned);
        }

        let last_event = self
            .state
            .last_trusted_event
            .as_ref()
            .ok_or(KelsError::NotIncepted)?;

        // PHASE 1: Prepare both rotations (staging only, no commit)

        // Prepare signing key rotation (stages next→current, generates new next)
        let new_current = self.key_provider.prepare_rotation().await?;
        let new_next = self.key_provider.pending_next_public_key().await?;
        let rotation_hash = compute_rotation_hash_from_key(&new_next);

        // Prepare recovery key rotation
        let (current_recovery_pub, new_recovery_pub) =
            self.key_provider.prepare_recovery_rotation().await?;
        let new_recovery_hash = compute_rotation_hash_from_key(&new_recovery_pub);

        // Create ror event
        let event = KeyEvent::create_recovery_rotation(
            last_event,
            new_current.qb64(),
            rotation_hash,
            current_recovery_pub.qb64(),
            new_recovery_hash,
        )?;

        // Dual signatures - sign with pending keys
        let primary_signature = self
            .key_provider
            .sign_with_pending(event.said.as_bytes())
            .await?;
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

        // PHASE 2: Submit to KELS
        let response = client
            .submit_events(std::slice::from_ref(&signed_event))
            .await;

        match response {
            Ok(resp) if resp.accepted => {
                // PHASE 3a: Commit both rotations
                self.key_provider.commit_rotation().await;
                self.key_provider.commit_recovery_rotation().await;

                // Update local state
                self.events.push(signed_event);
                self.state.update_establishment(&event);

                // Save to local store if configured
                if let Some(ref store) = self.kel_store {
                    store.save(&self.kel()?).await?;
                }

                Ok((event, primary_signature))
            }
            Ok(resp) => {
                // PHASE 3b: Rollback on rejection
                self.key_provider.rollback_rotation().await;
                self.key_provider.rollback_recovery_rotation().await;

                Err(KelsError::SubmissionFailed(format!(
                    "Recovery rotation rejected by KELS: {:?}",
                    resp.diverged_at
                )))
            }
            Err(e) => {
                // PHASE 3b: Rollback on error
                self.key_provider.rollback_rotation().await;
                self.key_provider.rollback_recovery_rotation().await;

                Err(e)
            }
        }
    }

    /// Recover from divergence by creating a recovery event.
    ///
    /// This should be called after a `DivergenceDetected` error from `flush()`, `rotate()`, etc.
    /// The recovery event proves ownership by signing with:
    /// 1. The pre-committed "next" key (matches `rotation_hash` from last establishment event)
    /// 2. The recovery key (proves recovery key ownership)
    ///
    /// If the adversary has revealed their recovery key (submitted rec/ror/dec/cnt), this will
    /// submit a contest event (`cnt`) and the KEL will be frozen.
    ///
    /// Returns the outcome (Recovered or Contested) along with the event and signature.
    pub async fn recover(&mut self) -> Result<(RecoveryOutcome, KeyEvent, Signature), KelsError> {
        let client = self
            .kels_client
            .as_ref()
            .ok_or_else(|| KelsError::OfflineMode("Cannot recover without KELS client".into()))?
            .clone();

        let prefix = self
            .state
            .last_trusted_event
            .as_ref()
            .ok_or(KelsError::NotIncepted)?
            .prefix
            .clone();

        // Fetch actual KEL state from KELS
        let kels_kel = client.fetch_full_kel(&prefix).await?;

        if kels_kel.is_empty() {
            return Err(KelsError::InvalidKel(
                "KELS returned empty KEL for existing prefix".into(),
            ));
        }

        if kels_kel.is_contested() {
            return Err(KelsError::ContestedKel("KEL already contested".to_string()));
        }

        let kels_events = kels_kel.events();
        let owner_saids = self.build_owner_saids(&kels_kel).await?;

        // Check if ADVERSARY revealed recovery key (recovery-revealing event NOT in owner's chain)
        // This catches: adversary submitted dec/rec/ror without diverging
        let adversary_recovery_revelation = kels_events
            .iter()
            .find(|e| e.event.reveals_recovery_key() && !owner_saids.contains(&e.event.said));

        let divergence_info = kels_kel.find_divergence();

        if adversary_recovery_revelation.is_none() && divergence_info.is_none() {
            return Err(KelsError::NoRecoveryNeeded(
                "No divergence or adversary recovery revelation detected".into(),
            ));
        }

        if let Some(recovery_event) = adversary_recovery_revelation {
            // CONTEST: Adversary revealed recovery key (without necessarily diverging)
            // Contest at the version of the adversary's recovery-revealing event
            self.contest_at_version(&kels_kel, recovery_event.event.version, &client)
                .await
        } else {
            // RECOVER: Divergence without adversary recovery revelation
            self.recover_from_divergence(&kels_kel, &client).await
        }
    }

    /// Contest at a specific version using current rotation key.
    /// Used when adversary has revealed the recovery key.
    async fn contest_at_version(
        &mut self,
        kels_kel: &Kel,
        contest_version: u64,
        client: &crate::client::KelsClient,
    ) -> Result<(RecoveryOutcome, KeyEvent, Signature), KelsError> {
        let kels_events = kels_kel.events();

        // Find events before the contest point to chain from
        let agreed_events: Vec<_> = kels_events
            .iter()
            .filter(|e| e.event.version < contest_version)
            .cloned()
            .collect();

        // Get the last event before contest point
        let last_agreed_event = agreed_events
            .last()
            .ok_or_else(|| KelsError::InvalidKel("No events before contest point".into()))?;

        // Get current rotation key (the next key, which proves pre-commitment)
        let rotation_key = self.key_provider.next_public_key().await?;

        // Get current recovery key
        let current_recovery_pub = self.key_provider.recovery_public_key().await?;

        // Create contest event
        let cnt_event = KeyEvent::create_contest(
            &last_agreed_event.event,
            rotation_key.qb64(),
            current_recovery_pub.qb64(),
        )?;

        // Sign with current rotation key (proves we have the pre-committed key)
        let cnt_primary_signature = self
            .key_provider
            .sign_with_pending(cnt_event.said.as_bytes())
            .await?;

        // Sign with recovery key
        let cnt_secondary_signature = self
            .key_provider
            .sign_with_recovery(cnt_event.said.as_bytes())
            .await?;

        // Create signed contest event with dual signatures
        let signed_cnt_event = SignedKeyEvent::new_recovery(
            cnt_event.clone(),
            rotation_key.qb64(),
            cnt_primary_signature.qb64(),
            current_recovery_pub.qb64(),
            cnt_secondary_signature.qb64(),
        );

        // Submit to KELS
        let response = client
            .submit_events(std::slice::from_ref(&signed_cnt_event))
            .await?;

        if response.accepted {
            // Update local state - set to agreed events plus contest
            self.set_events(agreed_events);
            self.events.push(signed_cnt_event);

            // Save to local store if configured
            if let Some(ref store) = self.kel_store {
                store.save(&self.kel()?).await?;
            }

            Ok((RecoveryOutcome::Contested, cnt_event, cnt_primary_signature))
        } else {
            Err(KelsError::SubmissionFailed(
                "Contest event rejected by KELS".into(),
            ))
        }
    }

    /// Recover from the divergence point using current rotation key.
    /// Used when adversary only has signing key (not recovery).
    async fn recover_from_divergence(
        &mut self,
        kels_kel: &Kel,
        client: &crate::client::KelsClient,
    ) -> Result<(RecoveryOutcome, KeyEvent, Signature), KelsError> {
        let kels_events = kels_kel.events();

        // Find divergence point from KELS KEL
        let divergence = kels_kel
            .find_divergence()
            .ok_or_else(|| KelsError::NoRecoveryNeeded("No divergence found in KEL".into()))?;
        let divergence_version = divergence.diverged_at_version;

        // Get events before divergence to chain from
        let agreed_events: Vec<_> = kels_events
            .iter()
            .filter(|e| e.event.version < divergence_version)
            .cloned()
            .collect();

        // Get the last event before divergence point
        let last_agreed_event = agreed_events
            .last()
            .ok_or_else(|| KelsError::InvalidKel("No events before divergence point".into()))?;

        // Get owner's tail event - this is what we chain from since it has the
        // correct rotation_hash for the owner's current key
        let chain_from_event = self
            .get_owner_tail_event(kels_kel)
            .await?
            .unwrap_or(last_agreed_event);

        let owner_saids = self.build_owner_saids(kels_kel).await?;

        // Check if owner rotated at/after divergence
        let owner_rotated = kels_events.iter().any(|e| {
            e.event.version >= divergence_version
                && e.event.is_rotation()
                && owner_saids.contains(&e.event.said)
        });

        // Check if adversary rotated at/after divergence
        let adversary_rotated = kels_events.iter().any(|e| {
            e.event.version >= divergence_version
                && e.event.is_rotation()
                && !owner_saids.contains(&e.event.said)
        });

        // Get current rotation key (the next key, which proves pre-commitment)
        let rotation_key = self.key_provider.next_public_key().await?;

        // Get current recovery key
        let current_recovery_pub = self.key_provider.recovery_public_key().await?;

        // Prepare recovery key rotation for forward security
        let (_, new_recovery_pub) = self.key_provider.prepare_recovery_rotation().await?;

        // Prepare signing key rotation - stages next→current and generates new next
        // After this: pending_current = rotation_key, pending_next = new key
        self.key_provider.prepare_rotation().await?;
        let new_next = self.key_provider.pending_next_public_key().await?;

        // Create recovery event chaining from owner's tail (not last agreed event)
        // This ensures the rotation_hash in chain_from_event matches our current key
        let rec_event = KeyEvent::create_recovery(
            &chain_from_event.event,
            rotation_key.qb64(),
            compute_rotation_hash_from_key(&new_next),
            current_recovery_pub.qb64(),
            compute_rotation_hash_from_key(&new_recovery_pub),
        )?;

        // Sign with current rotation key (proves we have the pre-committed key)
        let rec_primary_signature = self
            .key_provider
            .sign_with_pending(rec_event.said.as_bytes())
            .await?;

        // Sign with recovery key
        let rec_secondary_signature = self
            .key_provider
            .sign_with_recovery(rec_event.said.as_bytes())
            .await?;

        // Create signed recovery event with dual signatures
        let signed_rec_event = SignedKeyEvent::new_recovery(
            rec_event.clone(),
            rotation_key.qb64(),
            rec_primary_signature.qb64(),
            current_recovery_pub.qb64(),
            rec_secondary_signature.qb64(),
        );

        // Build list of events to submit
        // Need extra rot if: adversary rotated AND owner didn't rotate
        // (If owner also rotated, the adversary only knew the key that was current at divergence)
        let needs_extra_rot = adversary_rotated && !owner_rotated;

        let (events_to_submit, final_event, final_signature) = if needs_extra_rot {
            // Adversary has rotation key and owner hasn't escaped it yet
            // After rec: current = rotation_key (compromised), next = new_next (safe)
            // We need to rotate so: current = new_next (safe), next = fresh key

            // Commit the prepared rotation first (rotation_key → current, new_next → next)
            self.key_provider.commit_rotation().await;

            // Now rotate again (new_next → current, generate fresh next)
            let post_rec_current = self.key_provider.rotate().await?;
            let post_rec_next = self.key_provider.next_public_key().await?;

            // Create rot event chained from rec event
            let rot_event = KeyEvent::create_rotation(
                &rec_event,
                post_rec_current.qb64(),
                Some(compute_rotation_hash_from_key(&post_rec_next)),
            )?;

            let rot_signature = self.key_provider.sign(rot_event.said.as_bytes()).await?;
            let signed_rot_event = SignedKeyEvent::new(
                rot_event.clone(),
                post_rec_current.qb64(),
                rot_signature.qb64(),
            );

            (
                vec![signed_rec_event, signed_rot_event],
                rot_event,
                rot_signature,
            )
        } else {
            // Either adversary didn't rotate, or owner also rotated (so rotation key is still safe)
            // Just commit the prepared rotation and submit rec
            self.key_provider.commit_rotation().await;

            (
                vec![signed_rec_event.clone()],
                rec_event.clone(),
                rec_primary_signature.clone(),
            )
        };

        // Submit to KELS
        let response = client.submit_events(&events_to_submit).await?;

        if response.accepted {
            // Commit recovery key rotation
            self.key_provider.commit_recovery_rotation().await;

            // Update local state to agreed events plus submitted events
            self.set_events(agreed_events);
            for event in &events_to_submit {
                self.events.push(event.clone());
            }
            self.state = KelBuilderState::from_events(&self.events);

            // Save to local store if configured
            if let Some(ref store) = self.kel_store {
                store.save(&self.kel()?).await?;
            }

            Ok((RecoveryOutcome::Recovered, final_event, final_signature))
        } else {
            // Rollback recovery key rotation
            self.key_provider.rollback_recovery_rotation().await;
            Err(KelsError::SubmissionFailed(
                "Recovery event rejected by KELS".into(),
            ))
        }
    }

    /// Build a set of SAIDs for events created by the owner.
    /// Traces back from the owner's tail SAID through previous links.
    /// Returns empty set if no tail is saved (fail-secure: treats all events as adversary's).
    async fn build_owner_saids(
        &self,
        kels_kel: &Kel,
    ) -> Result<std::collections::HashSet<String>, KelsError> {
        let Some(ref store) = self.kel_store else {
            return Ok(std::collections::HashSet::new());
        };

        let Some(prefix) = kels_kel.prefix() else {
            return Ok(std::collections::HashSet::new());
        };

        let Some(tail_said) = store.load_owner_tail(prefix).await? else {
            return Ok(std::collections::HashSet::new());
        };

        Ok(kels_kel.trace_chain_saids(&tail_said))
    }

    /// Get the owner's tail event from the KEL.
    /// Returns None if no tail is saved or if the event isn't found in the KEL.
    async fn get_owner_tail_event<'a>(
        &self,
        kels_kel: &'a Kel,
    ) -> Result<Option<&'a SignedKeyEvent>, KelsError> {
        let Some(ref store) = self.kel_store else {
            return Ok(None);
        };

        let Some(prefix) = kels_kel.prefix() else {
            return Ok(None);
        };

        let Some(tail_said) = store.load_owner_tail(prefix).await? else {
            return Ok(None);
        };

        Ok(kels_kel.events().iter().find(|e| e.event.said == tail_said))
    }

    /// Create an interaction event (anchor a SAID in the KEL).
    /// Only available on native/mobile platforms (requires flush with auto-recovery).
    pub async fn interact(&mut self, anchor: &str) -> Result<(KeyEvent, Signature), KelsError> {
        if self.is_decommissioned() {
            return Err(KelsError::KelDecommissioned);
        }

        let last_event = self
            .state
            .last_trusted_event
            .as_ref()
            .ok_or(KelsError::NotIncepted)?;
        let current_key = self.key_provider.current_public_key().await?;

        let event = KeyEvent::create_interaction(last_event, anchor.to_string())?;
        let signature = self.key_provider.sign(event.said.as_bytes()).await?;
        self.add_and_flush(event.clone(), current_key.qb64(), signature.clone(), false)
            .await?;

        Ok((event, signature))
    }

    /// Sign arbitrary data with the current key.
    pub async fn sign(&self, data: &[u8]) -> Result<Signature, KelsError> {
        self.key_provider.sign(data).await
    }

    /// Get the KEL prefix (None if not yet incepted).
    pub fn prefix(&self) -> Option<&str> {
        self.state
            .last_trusted_event
            .as_ref()
            .map(|e| e.prefix.as_str())
    }

    /// Get the current event version.
    pub fn version(&self) -> u64 {
        self.state
            .last_trusted_event
            .as_ref()
            .map(|e| e.version)
            .unwrap_or(0)
    }

    /// Get the SAID of the last event (None if not yet incepted).
    pub fn last_said(&self) -> Option<&str> {
        self.state
            .last_trusted_event
            .as_ref()
            .map(|e| e.said.as_str())
    }

    /// Get the last event (None if not yet incepted).
    pub fn last_event(&self) -> Option<&KeyEvent> {
        self.state.last_trusted_event.as_ref()
    }

    /// Get the last establishment event (None if not yet incepted).
    pub fn last_establishment_event(&self) -> Option<&KeyEvent> {
        self.state.last_trusted_establishment_event.as_ref()
    }

    /// Get the current public key.
    pub async fn current_public_key(&self) -> Result<PublicKey, KelsError> {
        self.key_provider.current_public_key().await
    }

    /// Get a reference to the underlying key provider.
    pub fn key_provider(&self) -> &KeyProvider {
        &self.key_provider
    }

    /// Get a mutable reference to the underlying key provider.
    pub fn key_provider_mut(&mut self) -> &mut KeyProvider {
        &mut self.key_provider
    }

    /// Get all events created by this builder.
    pub fn events(&self) -> &[SignedKeyEvent] {
        &self.events
    }

    /// Get the current KEL state as a Kel struct.
    pub fn kel(&self) -> Result<Kel, KelsError> {
        Kel::from_events(self.events.clone(), true)
    }

    /// Get pending events (created but not yet confirmed in KELS).
    pub fn pending_events(&self) -> &[SignedKeyEvent] {
        &self.events[self.state.trusted_cursor..]
    }

    /// Get the number of confirmed events.
    pub fn confirmed_count(&self) -> usize {
        self.state.trusted_cursor
    }

    /// Check if all events are confirmed.
    pub fn is_fully_confirmed(&self) -> bool {
        self.state.trusted_cursor == self.events.len()
    }

    /// Flush pending events to KELS.
    ///
    /// Submits all unconfirmed events to KELS and updates the confirmed cursor.
    /// Handles divergence detection and recovery:
    /// - If divergence detected and recoverable (no rotation in pending): auto-rotates and retries
    /// - If divergence detected but contested (rotation in both): returns error
    /// - If divergence detected but unrecoverable (adversary rotated): returns error
    ///
    /// Submit pending events to KELS.
    ///
    /// Does nothing if no KELS client is configured (offline mode).
    /// Returns `DivergenceDetected` error if divergence occurs - caller should use `recover()`.
    pub async fn flush(&mut self) -> Result<(), KelsError> {
        let client = match &self.kels_client {
            Some(c) => c.clone(),
            None => return Ok(()), // Offline mode
        };

        let pending: Vec<_> = self.pending_events().to_vec();
        if pending.is_empty() {
            return Ok(());
        }

        let response = client.submit_events(&pending).await?;

        // Check diverged_at first - server now returns accepted=true with diverged_at
        // when the event is stored but causes divergence
        if let Some(diverged_at) = response.diverged_at {
            // Divergence detected - fetch full KEL from server to get all divergent events
            let prefix = self
                .events
                .first()
                .map(|e| e.event.prefix.clone())
                .ok_or_else(|| KelsError::NotIncepted)?;

            let server_kel = client.fetch_full_kel(&prefix).await?;

            // Verify server reports divergence
            if server_kel.find_divergence().is_none() {
                return Err(KelsError::InvalidKel(
                    "Server reported divergence but KEL has no divergent events".into(),
                ));
            }

            // Extract builder state before consuming the KEL
            self.state = server_kel.builder_state();
            self.events = server_kel.into_inner();

            Err(KelsError::DivergenceDetected {
                diverged_at,
                submission_accepted: response.accepted,
            })
        } else if response.accepted {
            self.state.confirm(self.events.len());
            Ok(())
        } else {
            Err(KelsError::InvalidKel(
                "Rejected without divergence".to_string(),
            ))
        }
    }

    async fn add_and_flush(
        &mut self,
        event: KeyEvent,
        public_key: String,
        signature: Signature,
        is_establishment: bool,
    ) -> Result<(), KelsError> {
        self.events.push(SignedKeyEvent::new(
            event.clone(),
            public_key,
            signature.qb64(),
        ));
        if is_establishment {
            self.state.update_establishment(&event);
        } else {
            self.state.update_non_establishment(&event);
        }

        let flush_result = if self.kels_client.is_some() {
            self.flush().await
        } else {
            Ok(())
        };

        // Determine if event was accepted (success or divergence with accepted=true)
        let event_accepted = matches!(
            &flush_result,
            Ok(())
                | Err(KelsError::DivergenceDetected {
                    submission_accepted: true,
                    ..
                })
        );

        // Save to local store if configured
        // Do this even on divergence - flush() syncs self.events with server state
        if let Some(ref store) = self.kel_store {
            store.save(&self.kel()?).await?;

            // Only save owner_tail if event was accepted
            if event_accepted {
                store.save_owner_tail(&event.prefix, &event.said).await?;
            }
        }

        flush_result
    }
}
