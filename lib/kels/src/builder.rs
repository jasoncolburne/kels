//! Key Event Builder

use crate::client::KelsClient;
use crate::crypto::KeyProvider;
use crate::error::KelsError;
use crate::kel::{Kel, compute_rotation_hash};
use crate::store::KelStore;
use crate::types::{KeyEvent, RecoveryOutcome, SignedKeyEvent};
use cesr::{Matter, PublicKey, Signature};

fn compute_rotation_hash_from_key(key: &PublicKey) -> String {
    compute_rotation_hash(&key.qb64())
}

pub struct KeyEventBuilder {
    key_provider: KeyProvider,
    #[allow(dead_code)]
    kels_client: Option<KelsClient>,
    kel_store: Option<std::sync::Arc<dyn KelStore>>,
    kel: Kel,
    confirmed_cursor: usize,
}

impl KeyEventBuilder {
    // ==================== Constructors ====================

    pub fn new(key_provider: KeyProvider, kels_client: Option<KelsClient>) -> Self {
        Self {
            key_provider,
            kels_client,
            kel_store: None,
            kel: Kel::default(),
            confirmed_cursor: 0,
        }
    }

    pub async fn with_dependencies(
        key_provider: KeyProvider,
        kels_client: Option<KelsClient>,
        kel_store: Option<std::sync::Arc<dyn KelStore>>,
        prefix: Option<&str>,
    ) -> Result<Self, KelsError> {
        let kel = match (&kel_store, prefix) {
            (Some(store), Some(p)) => store.load(p).await?.unwrap_or_default(),
            _ => Kel::default(),
        };
        let confirmed_cursor = kel.confirmed_cursor();

        Ok(Self {
            key_provider,
            kels_client,
            kel_store,
            kel,
            confirmed_cursor,
        })
    }

    pub fn with_kel(
        key_provider: KeyProvider,
        kels_client: Option<KelsClient>,
        kel_store: Option<std::sync::Arc<dyn KelStore>>,
        kel: Kel,
    ) -> Self {
        let confirmed_cursor = kel.confirmed_cursor();
        Self {
            key_provider,
            kels_client,
            kel_store,
            kel,
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

    pub fn key_provider(&self) -> &KeyProvider {
        &self.key_provider
    }

    pub fn key_provider_mut(&mut self) -> &mut KeyProvider {
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

    pub fn version(&self) -> u64 {
        self.kel.last_event().map(|e| e.event.version).unwrap_or(0)
    }

    // ==================== Event Operations ====================

    pub async fn decommission(&mut self) -> Result<(KeyEvent, Signature), KelsError> {
        if self.is_decommissioned() {
            return Err(KelsError::KelDecommissioned);
        }

        let last_event = self.get_owner_tail().await?.event.clone();
        let (signed_event, event, primary_signature) =
            match self.create_signed_decommission_event(&last_event).await {
                Ok(r) => r,
                Err(e) => {
                    self.key_provider.rollback_rotation().await;
                    return Err(e);
                }
            };

        let Some(client) = self.kels_client.as_ref().cloned() else {
            // No client - save locally
            self.kel.push(signed_event);

            if let Some(ref store) = self.kel_store {
                if let Err(e) = store.save(self.kel()).await {
                    self.kel.pop();
                    self.key_provider.rollback_rotation().await;
                    return Err(e);
                }
                if let Err(e) = store.save_owner_tail(&event.prefix, &event.said).await {
                    self.kel.pop();
                    self.key_provider.rollback_rotation().await;
                    return Err(e);
                }
            }

            self.key_provider.commit_rotation().await;
            return Ok((event, primary_signature));
        };

        let response = client
            .submit_events(std::slice::from_ref(&signed_event))
            .await;

        match response {
            Ok(resp) if resp.accepted => {
                self.kel.push(signed_event);
                self.confirmed_cursor = self.kel.len();

                // Save before commit - if save fails, we can rollback
                if let Some(ref store) = self.kel_store {
                    if let Err(e) = store.save(self.kel()).await {
                        self.kel.pop();
                        self.key_provider.rollback_rotation().await;
                        return Err(e);
                    }
                    if let Err(e) = store.save_owner_tail(&event.prefix, &event.said).await {
                        self.kel.pop();
                        self.key_provider.rollback_rotation().await;
                        return Err(e);
                    }
                }

                self.key_provider.commit_rotation().await;
                Ok((event, primary_signature))
            }
            Ok(_) => {
                self.key_provider.rollback_rotation().await;
                Err(KelsError::SubmissionFailed(
                    "Decommission event rejected by KELS".into(),
                ))
            }
            Err(e) => {
                self.key_provider.rollback_rotation().await;
                Err(e)
            }
        }
    }

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

    pub async fn interact(&mut self, anchor: &str) -> Result<(KeyEvent, Signature), KelsError> {
        if self.is_decommissioned() {
            return Err(KelsError::KelDecommissioned);
        }

        let last_event = self.get_owner_tail().await?.event.clone();
        let current_key = self.key_provider.current_public_key().await?;

        let event = KeyEvent::create_interaction(&last_event, anchor.to_string())?;
        let signature = self.key_provider.sign(event.said.as_bytes()).await?;
        self.add_and_flush(event.clone(), current_key.qb64(), signature.clone(), false)
            .await?;

        Ok((event, signature))
    }

    pub async fn recover(&mut self) -> Result<(RecoveryOutcome, KeyEvent, Signature), KelsError> {
        let client = self
            .kels_client
            .as_ref()
            .ok_or_else(|| KelsError::OfflineMode("Cannot recover without KELS client".into()))?
            .clone();

        let prefix = self.kel.prefix().ok_or(KelsError::NotIncepted)?.to_string();
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
            self.contest_at_version(&kels_kel, recovery_event.event.version, &client)
                .await
        } else {
            self.recover_from_divergence(&kels_kel, &client).await
        }
    }

    pub async fn rotate(&mut self) -> Result<(KeyEvent, Signature), KelsError> {
        if self.is_decommissioned() {
            return Err(KelsError::KelDecommissioned);
        }

        let last_event = self.get_owner_tail().await?.event.clone();

        let new_current = self.key_provider.prepare_rotation().await?;
        let new_next = self.key_provider.pending_next_public_key().await?;
        let rotation_hash = compute_rotation_hash_from_key(&new_next);

        let event =
            KeyEvent::create_rotation(&last_event, new_current.qb64(), Some(rotation_hash))?;
        let signature = self
            .key_provider
            .sign_with_pending(event.said.as_bytes())
            .await?;

        let flush_result = self
            .add_and_flush(event.clone(), new_current.qb64(), signature.clone(), true)
            .await;

        match &flush_result {
            Ok(()) => {
                self.key_provider.commit_rotation().await;
            }
            Err(KelsError::DivergenceDetected {
                submission_accepted: true,
                ..
            }) => {
                self.key_provider.commit_rotation().await;
            }
            Err(KelsError::DivergenceDetected {
                submission_accepted: false,
                ..
            }) => {
                self.key_provider.rollback_rotation().await;
            }
            Err(_) => {
                self.key_provider.rollback_rotation().await;
            }
        }

        flush_result?;
        Ok((event, signature))
    }

    pub async fn rotate_recovery(&mut self) -> Result<(KeyEvent, Signature), KelsError> {
        if self.is_decommissioned() {
            return Err(KelsError::KelDecommissioned);
        }

        let last_event = self.get_owner_tail().await?.event.clone();
        let (signed_event, event, primary_signature) = self
            .create_signed_recovery_rotation_event(&last_event)
            .await?;

        let Some(client) = self.kels_client.as_ref().cloned() else {
            // No client - save locally
            self.kel.push(signed_event);

            if let Some(ref store) = self.kel_store {
                if let Err(e) = store.save(self.kel()).await {
                    self.kel.pop();
                    self.key_provider.rollback_rotation().await;
                    self.key_provider.rollback_recovery_rotation().await;
                    return Err(e);
                }
                if let Err(e) = store.save_owner_tail(&event.prefix, &event.said).await {
                    self.kel.pop();
                    self.key_provider.rollback_rotation().await;
                    self.key_provider.rollback_recovery_rotation().await;
                    return Err(e);
                }
            }

            self.key_provider.commit_rotation().await;
            self.key_provider.commit_recovery_rotation().await;
            return Ok((event, primary_signature));
        };

        let response = client
            .submit_events(std::slice::from_ref(&signed_event))
            .await;

        match response {
            Ok(resp) if resp.accepted => {
                self.kel.push(signed_event);
                self.confirmed_cursor = self.kel.len();

                // Save before commit - if save fails, we can rollback
                if let Some(ref store) = self.kel_store {
                    if let Err(e) = store.save(self.kel()).await {
                        self.kel.pop();
                        self.key_provider.rollback_rotation().await;
                        self.key_provider.rollback_recovery_rotation().await;
                        return Err(e);
                    }
                    if let Err(e) = store.save_owner_tail(&event.prefix, &event.said).await {
                        self.kel.pop();
                        self.key_provider.rollback_rotation().await;
                        self.key_provider.rollback_recovery_rotation().await;
                        return Err(e);
                    }
                }

                // Only commit after successful save
                self.key_provider.commit_rotation().await;
                self.key_provider.commit_recovery_rotation().await;

                Ok((event, primary_signature))
            }
            Ok(resp) => {
                self.key_provider.rollback_rotation().await;
                self.key_provider.rollback_recovery_rotation().await;

                Err(KelsError::SubmissionFailed(format!(
                    "Recovery rotation rejected by KELS: {:?}",
                    resp.diverged_at
                )))
            }
            Err(e) => {
                self.key_provider.rollback_rotation().await;
                self.key_provider.rollback_recovery_rotation().await;

                Err(e)
            }
        }
    }

    /// Create a recovery event from the current tail (authoritative mode).
    /// Use this when you are the authority and need to reclaim control after compromise.
    /// Does not require a KELS client or divergence detection.
    pub async fn recover_authoritative(&mut self) -> Result<(KeyEvent, Signature), KelsError> {
        if self.is_decommissioned() {
            return Err(KelsError::KelDecommissioned);
        }

        let last_event = self.get_owner_tail().await?.event.clone();
        let (signed_event, event, signature) =
            self.create_signed_recovery_event(&last_event).await?;

        self.kel.push(signed_event);

        // Save before commit - if save fails, we can rollback
        if let Some(ref store) = self.kel_store {
            if let Err(e) = store.save(self.kel()).await {
                self.kel.pop();
                self.key_provider.rollback_rotation().await;
                self.key_provider.rollback_recovery_rotation().await;
                return Err(e);
            }
            if let Err(e) = store.save_owner_tail(&event.prefix, &event.said).await {
                self.kel.pop();
                self.key_provider.rollback_rotation().await;
                self.key_provider.rollback_recovery_rotation().await;
                return Err(e);
            }
        }

        // Only commit after successful save
        self.key_provider.commit_rotation().await;
        self.key_provider.commit_recovery_rotation().await;

        Ok((event, signature))
    }

    /// Create a contest event at a specific version (authoritative mode).
    /// Use this when an adversary revealed your recovery key at `at_version`.
    /// Does not require a KELS client.
    pub async fn contest_authoritative(
        &mut self,
        at_version: u64,
    ) -> Result<(KeyEvent, Signature), KelsError> {
        if self.is_decommissioned() {
            return Err(KelsError::KelDecommissioned);
        }

        let events = self.kel.events();
        let last_agreed_event = events
            .iter()
            .rev()
            .find(|e| e.event.version < at_version)
            .ok_or_else(|| KelsError::InvalidKel("No events before contest point".into()))?;

        let (signed_event, event, signature) = self
            .create_signed_contest_event(&last_agreed_event.event)
            .await?;

        self.kel.push(signed_event);

        // Save - if save fails, pop the event from KEL
        if let Some(ref store) = self.kel_store {
            if let Err(e) = store.save(self.kel()).await {
                self.kel.pop();
                return Err(e);
            }
            if let Err(e) = store.save_owner_tail(&event.prefix, &event.said).await {
                self.kel.pop();
                return Err(e);
            }
        }

        Ok((event, signature))
    }

    // ==================== Operations ====================

    pub async fn flush(&mut self) -> Result<(), KelsError> {
        let client = match &self.kels_client {
            Some(c) => c.clone(),
            None => return Ok(()),
        };

        let pending: Vec<_> = self.pending_events().to_vec();
        if pending.is_empty() {
            return Ok(());
        }

        let response = client.submit_events(&pending).await?;

        if let Some(diverged_at) = response.diverged_at {
            let prefix = self.kel.prefix().ok_or_else(|| KelsError::NotIncepted)?;
            let server_kel = client.fetch_full_kel(prefix).await?;

            if server_kel.find_divergence().is_none() {
                return Err(KelsError::InvalidKel(
                    "Server reported divergence but KEL has no divergent events".into(),
                ));
            }

            self.confirmed_cursor = server_kel.confirmed_cursor();
            self.kel = server_kel;

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

    pub async fn sign(&self, data: &[u8]) -> Result<Signature, KelsError> {
        self.key_provider.sign(data).await
    }

    // ==================== Private Helpers ====================

    /// Create a signed contest event from a base event.
    /// Returns (signed_event, event, primary_signature).
    async fn create_signed_contest_event(
        &self,
        base_event: &KeyEvent,
    ) -> Result<(SignedKeyEvent, KeyEvent, Signature), KelsError> {
        let rotation_key = self.key_provider.next_public_key().await?;
        let current_recovery_pub = self.key_provider.recovery_public_key().await?;

        let cnt_event =
            KeyEvent::create_contest(base_event, rotation_key.qb64(), current_recovery_pub.qb64())?;

        let cnt_primary_signature = self
            .key_provider
            .sign_with_pending(cnt_event.said.as_bytes())
            .await?;
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

    /// Create a signed decommission event from a base event.
    /// Prepares key rotation. Caller must commit/rollback.
    /// Returns (signed_event, event, primary_signature).
    async fn create_signed_decommission_event(
        &mut self,
        base_event: &KeyEvent,
    ) -> Result<(SignedKeyEvent, KeyEvent, Signature), KelsError> {
        let new_current = self.key_provider.prepare_rotation().await?;
        let current_recovery_pub = self.key_provider.recovery_public_key().await?;

        let event = KeyEvent::create_decommission(
            base_event,
            new_current.qb64(),
            current_recovery_pub.qb64(),
        )?;

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

        Ok((signed_event, event, primary_signature))
    }

    /// Create a signed recovery rotation event from a base event.
    /// Prepares key rotation and recovery rotation. Caller must commit/rollback.
    /// Returns (signed_event, event, primary_signature).
    async fn create_signed_recovery_rotation_event(
        &mut self,
        base_event: &KeyEvent,
    ) -> Result<(SignedKeyEvent, KeyEvent, Signature), KelsError> {
        let new_current = self.key_provider.prepare_rotation().await?;
        let new_next = self.key_provider.pending_next_public_key().await?;
        let rotation_hash = compute_rotation_hash_from_key(&new_next);

        let (current_recovery_pub, new_recovery_pub) =
            self.key_provider.prepare_recovery_rotation().await?;
        let new_recovery_hash = compute_rotation_hash_from_key(&new_recovery_pub);

        let event = KeyEvent::create_recovery_rotation(
            base_event,
            new_current.qb64(),
            rotation_hash,
            current_recovery_pub.qb64(),
            new_recovery_hash,
        )?;

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

        Ok((signed_event, event, primary_signature))
    }

    /// Create a signed recovery event from a base event.
    /// Prepares key rotation and recovery rotation. Caller must commit/rollback.
    /// Returns (signed_event, event, primary_signature).
    async fn create_signed_recovery_event(
        &mut self,
        base_event: &KeyEvent,
    ) -> Result<(SignedKeyEvent, KeyEvent, Signature), KelsError> {
        let rotation_key = self.key_provider.next_public_key().await?;
        let current_recovery_pub = self.key_provider.recovery_public_key().await?;
        let (_, new_recovery_pub) = self.key_provider.prepare_recovery_rotation().await?;

        self.key_provider.prepare_rotation().await?;
        let new_next = self.key_provider.pending_next_public_key().await?;

        let rec_event = KeyEvent::create_recovery(
            base_event,
            rotation_key.qb64(),
            compute_rotation_hash_from_key(&new_next),
            current_recovery_pub.qb64(),
            compute_rotation_hash_from_key(&new_recovery_pub),
        )?;

        let rec_primary_signature = self
            .key_provider
            .sign_with_pending(rec_event.said.as_bytes())
            .await?;
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

    async fn add_and_flush(
        &mut self,
        event: KeyEvent,
        public_key: String,
        signature: Signature,
        _is_establishment: bool,
    ) -> Result<(), KelsError> {
        self.kel.push(SignedKeyEvent::new(
            event.clone(),
            public_key,
            signature.qb64(),
        ));

        let flush_result = if self.kels_client.is_some() {
            self.flush().await
        } else {
            Ok(())
        };

        let event_accepted = matches!(
            &flush_result,
            Ok(())
                | Err(KelsError::DivergenceDetected {
                    submission_accepted: true,
                    ..
                })
        );

        if let Some(ref store) = self.kel_store {
            store.save(self.kel()).await?;
            if event_accepted {
                store.save_owner_tail(&event.prefix, &event.said).await?;
            }
        }

        flush_result
    }

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

    async fn contest_at_version(
        &mut self,
        kels_kel: &Kel,
        contest_version: u64,
        client: &crate::client::KelsClient,
    ) -> Result<(RecoveryOutcome, KeyEvent, Signature), KelsError> {
        let kels_events = kels_kel.events();

        let last_agreed_event = kels_events
            .iter()
            .rev()
            .find(|e| e.event.version < contest_version)
            .ok_or_else(|| KelsError::InvalidKel("No events before contest point".into()))?;

        let (signed_cnt_event, cnt_event, cnt_primary_signature) = self
            .create_signed_contest_event(&last_agreed_event.event)
            .await?;

        let response = client
            .submit_events(std::slice::from_ref(&signed_cnt_event))
            .await?;

        if response.accepted {
            // Fetch the full KEL from server to get the complete authoritative record
            let prefix = self.kel.prefix().ok_or(KelsError::NotIncepted)?;
            self.kel = client.fetch_full_kel(prefix).await?;
            self.confirmed_cursor = self.kel.len();

            if let Some(ref store) = self.kel_store {
                store.save(self.kel()).await?;
                store
                    .save_owner_tail(&cnt_event.prefix, &cnt_event.said)
                    .await?;
            }

            Ok((RecoveryOutcome::Contested, cnt_event, cnt_primary_signature))
        } else {
            Err(KelsError::SubmissionFailed(
                "Contest event rejected by KELS".into(),
            ))
        }
    }

    async fn find_owner_tail_in<'a>(
        &self,
        kel: &'a Kel,
    ) -> Result<Option<&'a SignedKeyEvent>, KelsError> {
        let Some(ref store) = self.kel_store else {
            return Ok(None);
        };
        let Some(prefix) = kel.prefix() else {
            return Ok(None);
        };
        let Some(tail_said) = store.load_owner_tail(prefix).await? else {
            return Ok(None);
        };
        Ok(kel.iter().rfind(|e| e.event.said == tail_said))
    }

    async fn get_owner_tail(&self) -> Result<&SignedKeyEvent, KelsError> {
        if let Some(event) = self.find_owner_tail_in(&self.kel).await? {
            return Ok(event);
        }
        self.kel.last_event().ok_or(KelsError::NotIncepted)
    }

    async fn recover_from_divergence(
        &mut self,
        kels_kel: &Kel,
        client: &crate::client::KelsClient,
    ) -> Result<(RecoveryOutcome, KeyEvent, Signature), KelsError> {
        let kels_events = kels_kel.events();

        let divergence = kels_kel
            .find_divergence()
            .ok_or_else(|| KelsError::NoRecoveryNeeded("No divergence found in KEL".into()))?;
        let divergence_version = divergence.diverged_at_version;

        let agreed_events: Vec<_> = kels_events
            .iter()
            .filter(|e| e.event.version < divergence_version)
            .cloned()
            .collect();

        let last_agreed_event = agreed_events
            .last()
            .ok_or_else(|| KelsError::InvalidKel("No events before divergence point".into()))?;

        let chain_from_event = self
            .find_owner_tail_in(kels_kel)
            .await?
            .unwrap_or(last_agreed_event);

        let owner_saids = self.build_owner_saids(kels_kel).await?;

        let owner_rotated = kels_events.iter().any(|e| {
            e.event.version >= divergence_version
                && e.event.is_rotation()
                && owner_saids.contains(&e.event.said)
        });
        let adversary_rotated = kels_events.iter().any(|e| {
            e.event.version >= divergence_version
                && e.event.is_rotation()
                && !owner_saids.contains(&e.event.said)
        });

        let (signed_rec_event, rec_event, rec_primary_signature) = self
            .create_signed_recovery_event(&chain_from_event.event)
            .await?;

        let needs_extra_rot = adversary_rotated && !owner_rotated;

        // Note: The extra rotation case requires committing before we can create the second
        // rotation event (we need to sign with the post-recovery current key). This means
        // if the server rejects after we've committed, we'll be in an inconsistent state.
        // This is a known limitation for this rare recovery scenario.
        let (events_to_submit, final_event, final_signature) = if needs_extra_rot {
            self.key_provider.commit_rotation().await;

            let post_rec_current = self.key_provider.rotate().await?;
            let post_rec_next = self.key_provider.next_public_key().await?;

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
            (
                vec![signed_rec_event.clone()],
                rec_event.clone(),
                rec_primary_signature.clone(),
            )
        };

        let response = match client.submit_events(&events_to_submit).await {
            Ok(resp) => resp,
            Err(e) => {
                if !needs_extra_rot {
                    self.key_provider.rollback_rotation().await;
                }
                self.key_provider.rollback_recovery_rotation().await;
                return Err(e);
            }
        };

        if response.accepted {
            // Fetch the full KEL from server to get the complete authoritative record
            // including all branches (adversary events + recovery)
            let prefix = self.kel.prefix().ok_or(KelsError::NotIncepted)?;
            self.kel = client.fetch_full_kel(prefix).await?;
            self.confirmed_cursor = self.kel.len();

            // Save before commit
            if let Some(ref store) = self.kel_store {
                if let Err(e) = store.save(self.kel()).await {
                    if !needs_extra_rot {
                        self.key_provider.rollback_rotation().await;
                    }
                    self.key_provider.rollback_recovery_rotation().await;
                    return Err(e);
                }
                if let Err(e) = store
                    .save_owner_tail(&final_event.prefix, &final_event.said)
                    .await
                {
                    if !needs_extra_rot {
                        self.key_provider.rollback_rotation().await;
                    }
                    self.key_provider.rollback_recovery_rotation().await;
                    return Err(e);
                }
            }

            // Commit after successful save
            if !needs_extra_rot {
                self.key_provider.commit_rotation().await;
            }
            self.key_provider.commit_recovery_rotation().await;

            Ok((RecoveryOutcome::Recovered, final_event, final_signature))
        } else {
            if !needs_extra_rot {
                self.key_provider.rollback_rotation().await;
            }
            self.key_provider.rollback_recovery_rotation().await;
            Err(KelsError::SubmissionFailed(
                "Recovery event rejected by KELS".into(),
            ))
        }
    }
}
