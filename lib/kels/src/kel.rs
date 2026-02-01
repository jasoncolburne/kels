//! Key Event Log (KEL) - cryptographically linked chain of key events

use crate::error::KelsError;
use crate::types::{KelMergeResult, KeyEvent, SignedKeyEvent};
use cesr::{Digest, Matter, PublicKey, Signature};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::ops::{Deref, DerefMut};
use verifiable_storage::Chained;

pub fn compute_rotation_hash(public_key: &str) -> String {
    let digest = Digest::blake3_256(public_key.as_bytes());
    digest.qb64()
}

#[derive(Debug, Clone)]
pub struct DivergenceInfo {
    pub diverged_at_generation: u64,
    pub divergent_saids: HashSet<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Kel(Vec<SignedKeyEvent>);

impl Kel {
    // ==================== Constructors ====================

    /// Only use `skip_verify: true` for trusted sources (e.g., database reads).
    pub fn from_events(events: Vec<SignedKeyEvent>, skip_verify: bool) -> Result<Self, KelsError> {
        let kel = Self(events);
        if !skip_verify && !kel.is_empty() {
            kel.verify()?;
        }
        Ok(kel)
    }

    pub fn new() -> Self {
        Self(Vec::new())
    }

    // ==================== Basic Accessors ====================

    pub fn delegating_prefix(&self) -> Option<&str> {
        self.0
            .first()
            .and_then(|e| e.event.delegating_prefix.as_deref())
    }

    pub fn events(&self) -> &[SignedKeyEvent] {
        &self.0
    }

    pub fn is_delegated(&self) -> bool {
        self.0
            .first()
            .map(|e| e.event.is_delegated_inception())
            .unwrap_or(false)
    }

    pub fn last_establishment_event(&self) -> Option<&SignedKeyEvent> {
        self.0.iter().rev().find(|e| e.event.is_establishment())
    }

    pub fn last_event(&self) -> Option<&SignedKeyEvent> {
        self.0.last()
    }

    pub fn last_said(&self) -> Option<&str> {
        self.0.last().map(|e| e.event.said.as_str())
    }

    pub fn prefix(&self) -> Option<&str> {
        self.0.first().map(|e| e.event.prefix.as_str())
    }

    // ==================== State Queries ====================

    pub fn confirmed_length(&self) -> usize {
        let divergence_info = self.find_divergence();

        if let Some(info) = divergence_info {
            // this is safe because default is 0 which fails secure
            info.diverged_at_generation.try_into().unwrap_or_default()
        } else {
            self.len()
        }
    }

    pub fn contains_anchor(&self, anchor: &str) -> bool {
        self.0
            .iter()
            .any(|e| e.event.is_interaction() && e.event.anchor.as_deref() == Some(anchor))
    }

    /// A contested KEL has a `cnt` event, meaning both parties used the recovery key.
    pub fn is_contested(&self) -> bool {
        self.0.iter().any(|e| e.event.is_contest())
    }

    pub fn is_decommissioned(&self) -> bool {
        let is_divergent = self.find_divergence().is_some();

        (!is_divergent
            && self
                .last()
                .map(|e| e.event.is_decommission())
                .unwrap_or(false))
            || self.iter().any(|e| e.event.is_contest())
    }

    // ==================== Divergence Detection ====================

    pub fn find_divergence(&self) -> Option<DivergenceInfo> {
        if self.is_empty() {
            return None;
        }

        // Build a map of generation -> SAIDs
        let saids_by_generation = self.map_saids_by_event_generation();

        // Find the first generation with multiple SAIDs
        let divergence_generation = saids_by_generation
            .iter()
            .filter(|(_, saids)| saids.len() > 1)
            .map(|(generation, _)| *generation)
            .min();

        let generation = divergence_generation?;

        let divergent_saids: HashSet<String> = saids_by_generation
            .iter()
            .filter(|(n, _)| **n >= generation)
            .flat_map(|(_, saids)| saids.iter().cloned())
            .collect();

        Some(DivergenceInfo {
            diverged_at_generation: generation,
            divergent_saids,
        })
    }

    pub fn get_owner_kel_saids_from_tail(&self, tail_said: &str) -> HashSet<String> {
        let mut saids = HashSet::new();
        let mut current_said = Some(tail_said.to_string());
        while let Some(said) = current_said {
            saids.insert(said.clone());
            current_said = self
                .0
                .iter()
                .find(|e| e.event.said == said)
                .and_then(|e| e.event.previous.clone());
        }
        saids
    }

    pub fn reveals_recovery_after_divergence(&self, divergent_saids: &HashSet<String>) -> bool {
        self.iter()
            .any(|e| e.event.reveals_recovery_key() && divergent_saids.contains(&e.event.said))
    }

    // ==================== Mutation ====================

    pub fn extend(&mut self, events: impl IntoIterator<Item = SignedKeyEvent>) {
        self.0.extend(events);
        self.sort();
    }

    pub fn push(&mut self, event: SignedKeyEvent) {
        self.0.push(event);
        self.sort();
    }

    pub fn remove_adversary_events(
        &mut self,
        owner_saids: &HashSet<String>,
    ) -> Result<Vec<SignedKeyEvent>, KelsError> {
        let owner_events = self
            .iter()
            .filter(|e| owner_saids.contains(&e.event.said))
            .cloned()
            .collect();
        let adversary_events = self
            .iter()
            .filter(|e| !owner_saids.contains(&e.event.said))
            .cloned()
            .collect();
        self.0 = owner_events;
        self.sort();
        Ok(adversary_events)
    }

    pub fn truncate(&mut self, len: usize) {
        self.0.truncate(len);
    }

    // ==================== Core Operations ====================

    /// Returns `(archived_events, added_events, KelMergeResult)`.
    pub fn merge(
        &mut self,
        events: Vec<SignedKeyEvent>,
    ) -> Result<(Vec<SignedKeyEvent>, Vec<SignedKeyEvent>, KelMergeResult), KelsError> {
        if events.is_empty() {
            return Err(KelsError::InvalidKel("No events to add".to_string()));
        }

        if self.is_contested() {
            return Err(KelsError::ContestedKel(
                "Kel is already contested".to_string(),
            ));
        }

        // Validate event structure before processing
        for signed_event in &events {
            signed_event
                .event
                .validate_structure()
                .map_err(KelsError::InvalidKel)?;
        }

        // Safe due to empty check above
        let first = &events[0];

        // Check if KEL is already divergent (frozen)
        // Only recovery-revealing events (rec/ror/dec/cnt) can unfreeze
        let divergence = self.find_divergence();
        if divergence.is_some() && !first.event.reveals_recovery_key() {
            return Ok((vec![], vec![], KelMergeResult::Frozen));
        }

        // If KEL is divergent and we're receiving a recovery event, use special handling.
        // The normal overlap logic uses array indices as versions, which breaks for divergent KELs.
        if let Some(divergence_info) = divergence
            && first.event.reveals_recovery_key()
        {
            if first.event.is_contest() {
                if self.reveals_recovery_after_divergence(&divergence_info.divergent_saids) {
                    if events.len() > 1 {
                        return Err(KelsError::InvalidKel(
                            "Cannot append events after contest".to_string(),
                        ));
                    }

                    // Contest: Just append cnt event, don't truncate. KEL stays divergent but frozen.
                    // This gives visibility to the contested state while preserving all events.
                    self.extend(events.iter().cloned());
                    self.verify()?;
                    return Ok((vec![], events, KelMergeResult::Contested)); // Empty vec = nothing to archive
                } else {
                    return Err(KelsError::Frozen);
                }
            } else if first.event.is_recover() {
                if !self.reveals_recovery_after_divergence(&divergence_info.divergent_saids) {
                    // Recovery: Keep owner's chain, archive adversary events.
                    // Owner's chain is identified by tracing back from rec's previous field.
                    let Some(owner_tail_said) = &first.event.previous else {
                        return Err(KelsError::InvalidKel(
                            "Recovery event has no previous".into(),
                        ));
                    };

                    let owner_kel_saids = self.get_owner_kel_saids_from_tail(owner_tail_said);
                    let adversary_events = self.remove_adversary_events(&owner_kel_saids)?;

                    self.extend(events.iter().cloned());
                    self.verify()?;
                    return Ok((adversary_events, events, KelMergeResult::Recovered));
                } else {
                    return Err(KelsError::ContestRequired);
                }
            } else {
                return Err(KelsError::Frozen);
            }
        }

        let Some(first_previous) = events.first().map(|e| e.event.previous.clone()) else {
            return Err(KelsError::InvalidKel("No events to add".to_string()));
        };

        let last_said = self.last().map(|e| e.event.said.clone());

        // Track old events that get removed (for archiving) and the merge result
        let (old_events_removed, new_events_added, result) = if first_previous == last_said {
            // Normal append - no overlap, no divergence
            // Contest requires divergence - cannot append normally
            if first.event.is_contest() {
                return Err(KelsError::InvalidKel(
                    "Contest requires divergence".to_string(),
                ));
            }

            // Decommission blocks normal appends (but not divergence detection)
            if self.is_decommissioned() {
                return Err(KelsError::KelDecommissioned);
            }

            self.extend(events.iter().cloned());
            (vec![], events, KelMergeResult::Verified)
        } else if let Some(previous) = first_previous
            && self.iter().any(|e| e.event.said == previous)
        {
            // Overlap - check for matching or divergent events
            let events_by_said = self.map_events_by_said();
            let all_saids_present = events
                .iter()
                .all(|e| events_by_said.contains_key(e.event.said.as_str()));

            if all_saids_present {
                (vec![], vec![], KelMergeResult::Verified)
            } else {
                let divergent_new_events: Vec<_> = events
                    .iter()
                    .filter(|e| !events_by_said.contains_key(e.event.said.as_str()))
                    .cloned()
                    .collect();

                let new_event_previouses: Vec<_> = events
                    .iter()
                    .filter_map(|e| e.event.previous.clone())
                    .collect();
                let mut divergent_old_events: Vec<SignedKeyEvent> = vec![];
                let mut previous_event = self.last();

                while previous_event.is_some() {
                    let Some(event) = previous_event else {
                        unreachable!();
                    };

                    // convergence
                    if new_event_previouses.contains(&event.event.said) {
                        previous_event = None
                    } else {
                        divergent_old_events.push(event.clone());

                        if let Some(previous) = event.event.previous.clone() {
                            previous_event = events_by_said.get(previous.as_str()).map(|v| &**v);
                        } else {
                            return Err(KelsError::InvalidKel(
                                "Reached inception without finding convergence".to_string(),
                            ));
                        }
                    }
                }

                let divergent_old_saids: HashSet<String> = divergent_old_events
                    .iter()
                    .map(|e| e.event.said.clone())
                    .collect();

                let Some(divergent_new_event) = divergent_new_events
                    .iter()
                    .find(|&e| {
                        e.event
                            .previous
                            .as_ref()
                            .map(|p| p == &previous)
                            .unwrap_or(false)
                    })
                    .cloned()
                else {
                    return Err(KelsError::InvalidKel(
                        "Cannot find divergent event".to_string(),
                    ));
                };

                // now that we have all the information, return
                if self.reveals_recovery_after_divergence(&divergent_old_saids) {
                    if divergent_new_event.event.is_contest() {
                        if events.len() > 1 {
                            return Err(KelsError::InvalidKel(
                                "Cannot append events after contest".to_string(),
                            ));
                        }

                        self.push(divergent_new_event.clone());
                        (vec![], vec![divergent_new_event], KelMergeResult::Contested)
                    } else {
                        return Ok((vec![], vec![], KelMergeResult::RecoveryProtected));
                    }
                } else if divergent_new_event.event.is_recover() {
                    self.extend(divergent_new_events.iter().cloned());
                    let Some(new_tail_said) =
                        divergent_new_events.last().map(|e| e.event.said.clone())
                    else {
                        return Err(KelsError::InvalidKel(
                            "Divergence detected but no new divergent events".to_string(),
                        ));
                    };
                    let owner_saids = self.get_owner_kel_saids_from_tail(&new_tail_said);
                    let removed_events = self.remove_adversary_events(&owner_saids)?;
                    (
                        removed_events,
                        divergent_new_events,
                        KelMergeResult::Recovered,
                    )
                } else {
                    self.push(divergent_new_event.clone());
                    (
                        vec![],
                        vec![divergent_new_event],
                        KelMergeResult::Recoverable,
                    )
                }
            }
        } else {
            // Gap in chain - invalid
            return Err(KelsError::InvalidKel("Events not contiguous".to_string()));
        };

        self.verify()?;

        Ok((old_events_removed, new_events_added, result))
    }

    /// Does NOT verify delegation anchoring for delegated KELs.
    pub fn verify(&self) -> Result<Option<DivergenceInfo>, KelsError> {
        if self.is_empty() {
            return Err(KelsError::NotIncepted);
        }

        // Build SAID -> event lookup
        let events_by_said = self.map_events_by_said();
        let saids_by_generation = self.map_saids_by_event_generation();
        let prefix = self.prefix().ok_or(KelsError::NotIncepted)?;

        // FORWARD PASS: Verify structure (SAID, prefix) and detect divergence
        let mut valid_tails: HashSet<&str> = HashSet::new();
        let mut divergence_info: Option<DivergenceInfo> = None;

        for (generation, saids) in saids_by_generation.iter() {
            let events_at_generation: Vec<_> = saids
                .iter()
                .filter_map(|said| events_by_said.get(said.as_str()))
                .cloned()
                .collect();
            let is_first_divergence = events_at_generation.len() > 1 && divergence_info.is_none();
            if is_first_divergence {
                divergence_info = Some(DivergenceInfo {
                    diverged_at_generation: *generation,
                    divergent_saids: events_at_generation
                        .iter()
                        .map(|e| e.event.said.clone())
                        .collect(),
                });
            }

            for signed_event in events_at_generation {
                let event = &signed_event.event;
                Self::verify_event_basics(event, prefix)?;
                if let Some(previous) = &event.previous {
                    valid_tails.remove(previous.as_str());
                }
                valid_tails.insert(&event.said);
            }
        }

        // BACKWARD PASS: For each tail, walk backward verifying cryptographic chain
        for tail_said in &valid_tails {
            self.verify_branch_from_tail(tail_said, &events_by_said)?;
        }

        Ok(divergence_info)
    }

    // ==================== Private Helpers - Chain Walking ====================

    fn map_events_by_said(&self) -> HashMap<&str, &SignedKeyEvent> {
        self.0.iter().map(|e| (e.event.said.as_str(), e)).collect()
    }

    pub fn map_saids_by_event_generation(&self) -> HashMap<u64, Vec<String>> {
        self.walk_generations()
            .map(|(generation, events)| {
                (
                    generation,
                    events.iter().map(|e| e.event.said.clone()).collect(),
                )
            })
            .collect()
    }

    pub fn sort(&mut self) {
        let sorted: Vec<SignedKeyEvent> = self
            .walk_generations()
            .flat_map(|(_, events)| events.into_iter().cloned())
            .collect();
        self.0 = sorted;
    }

    /// Walk the KEL generation by generation, yielding events at each generation.
    /// Returns an iterator of (generation, events_at_generation) tuples.
    fn walk_generations(&self) -> impl Iterator<Item = (u64, Vec<&SignedKeyEvent>)> {
        let events_by_said: HashMap<&str, &SignedKeyEvent> =
            self.0.iter().map(|e| (e.event.said.as_str(), e)).collect();

        let mut generations = Vec::new();
        let mut generation: u64 = 0;

        // Start with inception events (no previous)
        let mut current_saids: HashSet<&str> = self
            .iter()
            .filter(|e| e.event.previous.is_none())
            .map(|e| e.event.said.as_str())
            .collect();

        while !current_saids.is_empty() {
            let events_at_gen: Vec<&SignedKeyEvent> = current_saids
                .iter()
                .filter_map(|said| events_by_said.get(said).copied())
                .collect();

            generations.push((generation, events_at_gen));

            // Find next generation: events whose previous is in current_saids
            let next_saids: HashSet<&str> = self
                .iter()
                .filter(|e| {
                    e.event
                        .previous
                        .as_ref()
                        .map(|p| current_saids.contains(p.as_str()))
                        .unwrap_or(false)
                })
                .map(|e| e.event.said.as_str())
                .collect();

            current_saids = next_saids;
            generation += 1;
        }

        generations.into_iter()
    }

    // ==================== Private Helpers - Verification ====================

    fn verify_branch_from_tail(
        &self,
        tail_said: &str,
        events_by_said: &HashMap<&str, &SignedKeyEvent>,
    ) -> Result<(), KelsError> {
        let mut current_said = tail_said;

        // Track the next establishment event (later in time) as we walk backward
        // Used for verifying rotation_hash → public_key commitment
        let mut next_establishment: Option<&SignedKeyEvent> = None;

        let mut revealed_recovery_key: Option<&String> = None;

        // Pending non-establishment events to verify once we find their signing key
        let mut pending_events: Vec<&SignedKeyEvent> = Vec::new();

        loop {
            let signed_event = events_by_said.get(current_said).ok_or_else(|| {
                KelsError::InvalidKel(format!("Event {} not found in KEL", current_said))
            })?;
            let event = &signed_event.event;

            if event.is_establishment() {
                let qb64 = event.public_key.as_ref().ok_or_else(|| {
                    KelsError::InvalidKel("Establishment event missing public key".to_string())
                })?;
                let public_key = PublicKey::from_qb64(qb64)?;

                // Verify this event's rotation_hash matches the next establishment's public_key
                if let Some(next_est) = next_establishment {
                    self.verify_establishment_security(event, &next_est.event)?;
                }

                if event.has_recovery_hash()
                    && let Some(recovery_key) = revealed_recovery_key
                {
                    self.verify_recovery_key_revelation(event, recovery_key)?;
                }

                if event.reveals_recovery_key() {
                    revealed_recovery_key = event.recovery_key.as_ref()
                } else if event.has_recovery_hash() {
                    revealed_recovery_key = None
                }

                // Now we can verify signatures for pending non-establishment events
                // They were signed with this establishment's key
                for pending in &pending_events {
                    self.verify_signatures(pending, Some(&public_key))?;
                }
                pending_events.clear();

                // Verify this establishment event's signature with its own key
                self.verify_signatures(signed_event, Some(&public_key))?;

                next_establishment = Some(signed_event);
            } else {
                // Non-establishment: queue for signature verification when we find the signing key
                pending_events.push(signed_event);
            }

            match event.previous.as_deref() {
                Some(prev) => current_said = prev,
                None => break, // Reached inception
            }
        }

        // Any remaining pending events would be before inception, which is invalid
        if !pending_events.is_empty() {
            return Err(KelsError::InvalidKel(
                "Non-establishment events before inception".to_string(),
            ));
        }

        if revealed_recovery_key.is_some() {
            return Err(KelsError::InvalidKel(
                "Recovery key revealed before commitment".to_string(),
            ));
        }

        Ok(())
    }

    fn verify_event_basics(event: &KeyEvent, prefix: &str) -> Result<(), KelsError> {
        // Verify SAID is self-consistent
        event.verify().map_err(|e| {
            KelsError::InvalidKel(format!(
                "Event {} SAID verification failed: {}",
                &event.said, e
            ))
        })?;

        // Verify prefix matches
        if event.prefix != prefix {
            return Err(KelsError::InvalidKel(format!(
                "Event {} has different prefix",
                &event.said,
            )));
        }

        Ok(())
    }

    fn verify_establishment_security(
        &self,
        event: &KeyEvent,
        future_event: &KeyEvent,
    ) -> Result<(), KelsError> {
        if let Some(rotation_hash) = event.rotation_hash.as_deref() {
            let Some(next_pubkey_qb64) = future_event.public_key.as_ref() else {
                return Err(KelsError::InvalidKel(
                    "Establishment event missing public key".to_string(),
                ));
            };
            let computed = compute_rotation_hash(next_pubkey_qb64);
            if computed != rotation_hash {
                return Err(KelsError::InvalidKel(
                    "Public key does not match previous rotation hash".to_string(),
                ));
            }
        }

        Ok(())
    }

    fn verify_recovery_key_revelation(
        &self,
        event: &KeyEvent,
        recovery_key: &str,
    ) -> Result<(), KelsError> {
        let hash = compute_rotation_hash(recovery_key);
        let Some(event_hash) = event.recovery_hash.clone() else {
            return Err(KelsError::InvalidKel(
                "Event expected to contain recovery hash".to_string(),
            ));
        };

        if hash != event_hash {
            return Err(KelsError::InvalidKel(
                "Recovery key does not match previous recovery hash".to_string(),
            ));
        }

        Ok(())
    }

    fn verify_signatures(
        &self,
        signed_event: &SignedKeyEvent,
        current_public_key: Option<&PublicKey>,
    ) -> Result<(), KelsError> {
        let event = &signed_event.event;
        let public_key = current_public_key.ok_or_else(|| {
            KelsError::InvalidKel(format!(
                "No public key available to verify event {}",
                &event.said,
            ))
        })?;

        let expected_qb64 = public_key.qb64();
        let sig = signed_event.signature(&expected_qb64).ok_or_else(|| {
            KelsError::InvalidKel(format!(
                "Event {} has no signature for expected key",
                &event.said,
            ))
        })?;

        let signature = Signature::from_qb64(&sig.signature)?;
        public_key
            .verify(event.said.as_bytes(), &signature)
            .map_err(|_| {
                KelsError::InvalidKel(format!(
                    "Event {} signature verification failed",
                    &event.said,
                ))
            })?;

        // Recovery events require dual signatures
        if event.reveals_recovery_key() {
            let recovery_key_qb64 = event.recovery_key.as_ref().ok_or_else(|| {
                KelsError::InvalidKel(format!(
                    "Recovery event {} has no recovery_key field",
                    &event.said,
                ))
            })?;

            let recovery_sig = signed_event.signature(recovery_key_qb64).ok_or_else(|| {
                KelsError::InvalidKel(format!(
                    "Recovery event {} has no signature for recovery key",
                    &event.said,
                ))
            })?;

            let recovery_public_key = PublicKey::from_qb64(recovery_key_qb64)?;
            let recovery_signature = Signature::from_qb64(&recovery_sig.signature)?;
            recovery_public_key
                .verify(event.said.as_bytes(), &recovery_signature)
                .map_err(|_| {
                    KelsError::InvalidKel(format!(
                        "Recovery event {} recovery signature verification failed",
                        &event.said,
                    ))
                })?;
        }

        Ok(())
    }
}

impl Deref for Kel {
    type Target = Vec<SignedKeyEvent>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Kel {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl IntoIterator for Kel {
    type Item = SignedKeyEvent;
    type IntoIter = std::vec::IntoIter<SignedKeyEvent>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::KeyEventBuilder;
    use crate::crypto::{KeyProvider, SoftwareKeyProvider};
    use cesr::PrivateKey;
    use verifiable_storage::SelfAddressed;

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

    #[tokio::test]
    async fn test_incept() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);

        let (event, signature) = builder.incept().await.unwrap();

        assert!(event.is_inception());
        assert!(!event.said.is_empty());
        assert!(event.previous.is_none());
        assert!(event.public_key.is_some());
        assert!(event.rotation_hash.is_some());

        let public_key = builder.current_public_key().await.unwrap();
        assert!(public_key.verify(event.said.as_bytes(), &signature).is_ok());

        assert_eq!(builder.prefix(), Some(event.prefix.as_str()));
    }

    #[tokio::test]
    async fn test_interact() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);

        let (icp_event, _) = builder.incept().await.unwrap();

        let anchor = "ESAID_of_some_credential";
        let (ixn_event, signature) = builder.interact(anchor).await.unwrap();

        assert!(ixn_event.is_interaction());
        assert_ne!(ixn_event.said, icp_event.said);
        assert_eq!(ixn_event.prefix, icp_event.prefix);
        assert_eq!(ixn_event.previous, Some(icp_event.said));
        assert_eq!(ixn_event.anchor, Some(anchor.to_string()));
        assert!(ixn_event.public_key.is_none());
        assert!(ixn_event.rotation_hash.is_none());

        let public_key = builder.current_public_key().await.unwrap();
        assert!(
            public_key
                .verify(ixn_event.said.as_bytes(), &signature)
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_rotate() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);

        let (icp_event, _) = builder.incept().await.unwrap();
        let original_public_key = builder.current_public_key().await.unwrap();

        let (rot_event, signature) = builder.rotate().await.unwrap();

        assert!(rot_event.is_rotation());
        assert_ne!(rot_event.said, icp_event.said);
        assert_eq!(rot_event.prefix, icp_event.prefix);
        assert_eq!(rot_event.previous, Some(icp_event.said));
        assert!(rot_event.public_key.is_some());
        assert!(rot_event.rotation_hash.is_some());

        let new_public_key = builder.current_public_key().await.unwrap();
        assert_ne!(original_public_key.qb64(), new_public_key.qb64());

        let rotation_hash = icp_event.rotation_hash.unwrap();
        let expected_hash = compute_rotation_hash(&new_public_key.qb64());
        assert_eq!(rotation_hash, expected_hash);

        assert!(
            new_public_key
                .verify(rot_event.said.as_bytes(), &signature)
                .is_ok()
        );
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
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);

        let (event, _) = builder.incept().await.unwrap();
        assert!(event.verify_prefix().is_ok());

        let (ixn_event, _) = builder.interact("anchor").await.unwrap();
        assert!(ixn_event.verify_said().is_ok());
    }

    #[tokio::test]
    async fn test_with_kel() {
        let mut builder1 = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let (icp_event, icp_sig) = builder1.incept().await.unwrap();
        let public_key = icp_event.public_key.clone().unwrap();

        let (current_key, next_key, recovery_key) = clone_keys(&builder1);

        let mut kel = Kel::new();
        kel.push(SignedKeyEvent::new(
            icp_event.clone(),
            public_key,
            icp_sig.qb64(),
        ));
        let mut builder2 = KeyEventBuilder::with_kel(
            SoftwareKeyProvider::with_all_keys(current_key, next_key, recovery_key),
            None,
            None,
            kel.clone(),
        )
        .unwrap();

        let (ixn_event, _) = builder2.interact("anchor").await.unwrap();
        assert_eq!(ixn_event.prefix, icp_event.prefix);
        assert_eq!(ixn_event.previous, Some(icp_event.said));
    }

    #[tokio::test]
    async fn test_rotation_after_interactions() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let (icp_event, icp_sig) = builder.incept().await.unwrap();
        let (ixn1, ixn1_sig) = builder.interact("anchor1").await.unwrap();
        let (ixn2, ixn2_sig) = builder.interact("anchor2").await.unwrap();
        let public_key = icp_event.public_key.clone().unwrap();

        let kel = Kel::from_events(
            vec![
                SignedKeyEvent::new(icp_event.clone(), public_key.clone(), icp_sig.qb64()),
                SignedKeyEvent::new(ixn1.clone(), public_key.clone(), ixn1_sig.qb64()),
                SignedKeyEvent::new(ixn2.clone(), public_key.clone(), ixn2_sig.qb64()),
            ],
            false,
        )
        .unwrap();

        let (current_key, next_key, recovery_key) = clone_keys(&builder);
        let mut builder2 = KeyEventBuilder::with_kel(
            SoftwareKeyProvider::with_all_keys(current_key, next_key, recovery_key),
            None,
            None,
            kel.clone(),
        )
        .unwrap();

        assert_eq!(builder2.last_event().unwrap().said, ixn2.said);
        assert_eq!(
            builder2.last_establishment_event().unwrap().said,
            icp_event.said
        );

        let (rot_event, _) = builder2.rotate().await.unwrap();
        assert_eq!(rot_event.previous, Some(ixn2.said));
    }

    #[tokio::test]
    async fn test_kel_struct() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);

        let (icp_event, icp_sig) = builder.incept().await.unwrap();
        let (ixn_event, ixn_sig) = builder.interact("test_anchor").await.unwrap();

        let mut kel = Kel::new();
        assert!(kel.is_empty());
        assert!(kel.prefix().is_none());

        let icp_public_key = icp_event.public_key.clone().unwrap();
        kel.push(SignedKeyEvent::new(
            icp_event.clone(),
            icp_public_key.clone(),
            icp_sig.qb64(),
        ));

        assert_eq!(kel.len(), 1);
        assert_eq!(kel.prefix(), Some(icp_event.prefix.as_str()));
        assert_eq!(kel.last_said(), Some(icp_event.said.as_str()));

        kel.push(SignedKeyEvent::new(
            ixn_event.clone(),
            icp_public_key, // ixn signed with same key as icp
            ixn_sig.qb64(),
        ));

        assert_eq!(kel.len(), 2);
        assert_eq!(kel.last_said(), Some(ixn_event.said.as_str()));
        assert!(kel.contains_anchor("test_anchor"));
        assert!(!kel.contains_anchor("other_anchor"));

        assert!(kel.verify().is_ok());
    }

    #[tokio::test]
    async fn test_json_roundtrip() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let (event, signature) = builder.incept().await.unwrap();

        let public_key = event.public_key.clone().unwrap();
        let signed = SignedKeyEvent::new(event.clone(), public_key.clone(), signature.qb64());

        // Serialize to JSON
        let json = serde_json::to_string(&signed).unwrap();

        // Deserialize from JSON
        let deserialized: SignedKeyEvent = serde_json::from_str(&json).unwrap();

        // Verify the roundtrip worked
        assert_eq!(deserialized.event.said, event.said);
        assert_eq!(deserialized.event.prefix, event.prefix);

        let sig = deserialized.signature(&public_key).unwrap();
        assert_eq!(sig.signature, signature.qb64());

        // Verify the KEL works with deserialized event
        let mut kel = Kel::new();
        kel.push(deserialized);
        assert!(kel.verify().is_ok());
    }

    #[tokio::test]
    async fn test_find_divergence_none() {
        // Normal KEL with no divergence
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let (icp_event, icp_sig) = builder.incept().await.unwrap();
        let (ixn_event, ixn_sig) = builder.interact("anchor").await.unwrap();

        let public_key = icp_event.public_key.clone().unwrap();
        let kel = Kel::from_events(
            vec![
                SignedKeyEvent::new(icp_event.clone(), public_key.clone(), icp_sig.qb64()),
                SignedKeyEvent::new(ixn_event.clone(), public_key.clone(), ixn_sig.qb64()),
            ],
            true, // skip verify for test
        )
        .unwrap();

        assert!(kel.find_divergence().is_none());
    }

    #[tokio::test]
    async fn test_find_divergence_two_way() {
        // KEL with 2 events at same version (2-way divergence)
        let mut builder1 = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let (icp_event, icp_sig) = builder1.incept().await.unwrap();

        // Clone builder after inception to create adversary with same state
        let mut builder2 = builder1.clone();

        let (ixn1, ixn1_sig) = builder1.interact("anchor1").await.unwrap();
        let (ixn2, ixn2_sig) = builder2.interact("anchor2").await.unwrap();

        // Both ixn1 and ixn2 chain from icp
        assert_ne!(ixn1.said, ixn2.said);

        let icp_public_key = icp_event.public_key.clone().unwrap();

        // Create KEL with both divergent events
        let kel = Kel::from_events(
            vec![
                SignedKeyEvent::new(icp_event.clone(), icp_public_key.clone(), icp_sig.qb64()),
                SignedKeyEvent::new(ixn1.clone(), icp_public_key.clone(), ixn1_sig.qb64()),
                SignedKeyEvent::new(ixn2.clone(), icp_public_key.clone(), ixn2_sig.qb64()),
            ],
            true, // skip verify - divergent KEL won't pass normal verification
        )
        .unwrap();

        let divergence = kel.find_divergence();
        assert!(divergence.is_some());
        let info = divergence.unwrap();
        assert_eq!(info.diverged_at_generation, 1);
        assert_eq!(info.divergent_saids.len(), 2);
        assert!(info.divergent_saids.contains(&ixn1.said));
        assert!(info.divergent_saids.contains(&ixn2.said));
    }

    #[tokio::test]
    async fn test_find_divergence_three_way() {
        // KEL with 3 events at same version (3-way divergence from race condition)
        let mut builder1 = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let (icp_event, icp_sig) = builder1.incept().await.unwrap();

        // Clone builder after inception to create two adversaries
        let mut builder2 = builder1.clone();
        let mut builder3 = builder1.clone();

        let (ixn1, ixn1_sig) = builder1.interact("anchor1").await.unwrap();
        let (ixn2, ixn2_sig) = builder2.interact("anchor2").await.unwrap();
        let (ixn3, ixn3_sig) = builder3.interact("anchor3").await.unwrap();

        // All three ixn events chain from icp
        assert_ne!(ixn1.said, ixn2.said);
        assert_ne!(ixn2.said, ixn3.said);
        assert_ne!(ixn1.said, ixn3.said);

        let icp_public_key = icp_event.public_key.clone().unwrap();

        // Create KEL with all three divergent events
        let kel = Kel::from_events(
            vec![
                SignedKeyEvent::new(icp_event.clone(), icp_public_key.clone(), icp_sig.qb64()),
                SignedKeyEvent::new(ixn1.clone(), icp_public_key.clone(), ixn1_sig.qb64()),
                SignedKeyEvent::new(ixn2.clone(), icp_public_key.clone(), ixn2_sig.qb64()),
                SignedKeyEvent::new(ixn3.clone(), icp_public_key.clone(), ixn3_sig.qb64()),
            ],
            true, // skip verify
        )
        .unwrap();

        let divergence = kel.find_divergence();
        assert!(divergence.is_some());
        let info = divergence.unwrap();
        assert_eq!(info.diverged_at_generation, 1);
        assert_eq!(info.divergent_saids.len(), 3);
        assert!(info.divergent_saids.contains(&ixn1.said));
        assert!(info.divergent_saids.contains(&ixn2.said));
        assert!(info.divergent_saids.contains(&ixn3.said));
    }

    #[tokio::test]
    async fn test_with_kel_divergent_sets_correct_state() {
        // When loading a divergent KEL, with_kel should set state to last non-divergent event
        let mut builder1 = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let (icp_event, icp_sig) = builder1.incept().await.unwrap();
        let (ixn1, ixn1_sig) = builder1.interact("anchor1").await.unwrap();

        let (current_key, next_key, recovery_key) = clone_keys(&builder1);

        let icp_public_key = icp_event.public_key.clone().unwrap();
        let mut kel_for_builder2 = Kel::new();
        kel_for_builder2.push(SignedKeyEvent::new(
            icp_event.clone(),
            icp_public_key.clone(),
            icp_sig.qb64(),
        ));

        let mut builder2 = KeyEventBuilder::with_kel(
            SoftwareKeyProvider::with_all_keys(
                current_key.clone(),
                next_key.clone(),
                recovery_key.clone(),
            ),
            None,
            None,
            kel_for_builder2.clone(),
        )
        .unwrap();
        let (ixn2, ixn2_sig) = builder2.interact("anchor2").await.unwrap();

        // Create divergent KEL with events at v0 (icp) and two at v1
        let divergent_kel = Kel::from_events(
            vec![
                SignedKeyEvent::new(icp_event.clone(), icp_public_key.clone(), icp_sig.qb64()),
                SignedKeyEvent::new(ixn1.clone(), icp_public_key.clone(), ixn1_sig.qb64()),
                SignedKeyEvent::new(ixn2.clone(), icp_public_key.clone(), ixn2_sig.qb64()),
            ],
            true, // skip verify
        )
        .unwrap();

        // Verify it's divergent
        assert!(divergent_kel.find_divergence().is_some());

        // Load with with_kel
        let builder3 = KeyEventBuilder::with_kel(
            SoftwareKeyProvider::with_all_keys(current_key, next_key, recovery_key),
            None,
            None,
            divergent_kel.clone(),
        )
        .unwrap();

        // last_event returns the actual last event in the KEL (one of the divergent events)
        // In divergent KEL, confirmed_cursor points to first divergent event
        assert_eq!(builder3.confirmed_count(), 1);

        // pending_events should be the two divergent events
        assert_eq!(builder3.pending_events().len(), 2);

        // The KEL itself reports divergence correctly
        assert!(divergent_kel.find_divergence().is_some());
    }

    #[tokio::test]
    async fn test_with_kel_three_way_divergent() {
        // Test that 3-way divergence is handled correctly by with_kel
        let mut builder1 = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let (icp_event, icp_sig) = builder1.incept().await.unwrap();
        let (ixn1, ixn1_sig) = builder1.interact("anchor1").await.unwrap();

        let (current_key, next_key, recovery_key) = clone_keys(&builder1);

        let icp_public_key = icp_event.public_key.clone().unwrap();
        let mut kel_for_others = Kel::new();
        kel_for_others.push(SignedKeyEvent::new(
            icp_event.clone(),
            icp_public_key.clone(),
            icp_sig.qb64(),
        ));

        let mut builder2 = KeyEventBuilder::with_kel(
            SoftwareKeyProvider::with_all_keys(
                current_key.clone(),
                next_key.clone(),
                recovery_key.clone(),
            ),
            None,
            None,
            kel_for_others.clone(),
        )
        .unwrap();
        let (ixn2, ixn2_sig) = builder2.interact("anchor2").await.unwrap();

        let mut builder3 = KeyEventBuilder::with_kel(
            SoftwareKeyProvider::with_all_keys(
                current_key.clone(),
                next_key.clone(),
                recovery_key.clone(),
            ),
            None,
            None,
            kel_for_others.clone(),
        )
        .unwrap();
        let (ixn3, ixn3_sig) = builder3.interact("anchor3").await.unwrap();

        // Create 3-way divergent KEL
        let divergent_kel = Kel::from_events(
            vec![
                SignedKeyEvent::new(icp_event.clone(), icp_public_key.clone(), icp_sig.qb64()),
                SignedKeyEvent::new(ixn1.clone(), icp_public_key.clone(), ixn1_sig.qb64()),
                SignedKeyEvent::new(ixn2.clone(), icp_public_key.clone(), ixn2_sig.qb64()),
                SignedKeyEvent::new(ixn3.clone(), icp_public_key.clone(), ixn3_sig.qb64()),
            ],
            true, // skip verify
        )
        .unwrap();

        // Verify 3-way divergence
        let info = divergent_kel.find_divergence().unwrap();
        assert_eq!(info.divergent_saids.len(), 3);

        // Load with with_kel
        let loaded_builder = KeyEventBuilder::with_kel(
            SoftwareKeyProvider::with_all_keys(current_key, next_key, recovery_key),
            None,
            None,
            divergent_kel.clone(),
        )
        .unwrap();

        // confirmed_cursor should be 1, pending should have 3 events
        assert_eq!(loaded_builder.confirmed_count(), 1);
        assert_eq!(loaded_builder.pending_events().len(), 3);
    }

    #[tokio::test]
    async fn test_adversary_rotation_detection() {
        // Test that we correctly detect when adversary rotated vs when we rotated
        // This is critical for knowing when to submit [rec, rot] vs just [rec]

        let mut owner = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let (icp, icp_sig) = owner.incept().await.unwrap();
        let (owner_ixn, owner_ixn_sig) = owner.interact("owner-anchor").await.unwrap();

        // Save owner's keys for adversary simulation
        let (current_key, next_key, recovery_key) = clone_keys(&owner);
        let icp_public_key = icp.public_key.clone().unwrap();

        // Adversary creates a rotation at v1 (same version as owner's ixn)
        let mut adversary_kel = Kel::new();
        adversary_kel.push(SignedKeyEvent::new(
            icp.clone(),
            icp_public_key.clone(),
            icp_sig.qb64(),
        ));

        let mut adversary = KeyEventBuilder::with_kel(
            SoftwareKeyProvider::with_all_keys(
                current_key.clone(),
                next_key.clone(),
                recovery_key.clone(),
            ),
            None,
            None,
            adversary_kel.clone(),
        )
        .unwrap();
        let (adversary_rot, adversary_rot_sig) = adversary.rotate().await.unwrap();

        // Both events are at version 1
        assert!(adversary_rot.is_rotation());

        // Create the server KEL with both divergent events
        let rot_public_key = adversary_rot.public_key.clone().unwrap();
        let server_kel = Kel::from_events(
            vec![
                SignedKeyEvent::new(icp.clone(), icp_public_key.clone(), icp_sig.qb64()),
                SignedKeyEvent::new(
                    owner_ixn.clone(),
                    icp_public_key.clone(),
                    owner_ixn_sig.qb64(),
                ),
                SignedKeyEvent::new(
                    adversary_rot.clone(),
                    rot_public_key.clone(),
                    adversary_rot_sig.qb64(),
                ),
            ],
            true, // skip verify - divergent
        )
        .unwrap();

        // Verify divergence exists
        let divergence = server_kel.find_divergence().unwrap();
        assert_eq!(divergence.diverged_at_generation, 1);

        // Owner's local events (what they know about)
        let owner_events = owner.kel();
        let owner_saids: HashSet<_> = owner_events.iter().map(|e| &e.event.said).collect();

        // Check: adversary_rot should NOT be in owner's SAIDs (it's adversary's event)
        assert!(!owner_saids.contains(&adversary_rot.said));

        // Check: owner_ixn SHOULD be in owner's SAIDs
        assert!(owner_saids.contains(&owner_ixn.said));

        // Simulate the adversary rotation detection logic from recover_from_divergence
        let adversary_rotated = server_kel.events().iter().any(|e| {
            divergence.divergent_saids.contains(&e.event.said)
                && e.event.is_rotation()
                && !owner_saids.contains(&e.event.said)
        });

        // Should detect adversary rotation
        assert!(adversary_rotated, "Should detect adversary rotation");
    }

    #[tokio::test]
    async fn test_owner_rotation_not_detected_as_adversary() {
        // Test that owner's own rotation is NOT detected as adversary rotation

        let mut owner = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let (icp, icp_sig) = owner.incept().await.unwrap();

        // Save keys for adversary BEFORE rotation (adversary has inception-era keys)
        let (pre_rot_current, pre_rot_next, pre_rot_recovery) = clone_keys(&owner);

        let (owner_rot, owner_rot_sig) = owner.rotate().await.unwrap();

        let icp_public_key = icp.public_key.clone().unwrap();
        let rot_public_key = owner_rot.public_key.clone().unwrap();

        // Adversary injects ixn at v1 (same version as owner's rot) using inception key
        let mut adversary_kel = Kel::new();
        adversary_kel.push(SignedKeyEvent::new(
            icp.clone(),
            icp_public_key.clone(),
            icp_sig.qb64(),
        ));

        let mut adversary = KeyEventBuilder::with_kel(
            SoftwareKeyProvider::with_all_keys(pre_rot_current, pre_rot_next, pre_rot_recovery),
            None,
            None,
            adversary_kel.clone(),
        )
        .unwrap();
        let (adversary_ixn, adversary_ixn_sig) =
            adversary.interact("adversary-anchor").await.unwrap();

        // Both events at version 1
        assert!(owner_rot.is_rotation());
        assert!(!adversary_ixn.is_rotation());

        // Create server KEL with divergence
        let server_kel = Kel::from_events(
            vec![
                SignedKeyEvent::new(icp.clone(), icp_public_key.clone(), icp_sig.qb64()),
                SignedKeyEvent::new(
                    owner_rot.clone(),
                    rot_public_key.clone(),
                    owner_rot_sig.qb64(),
                ),
                SignedKeyEvent::new(
                    adversary_ixn.clone(),
                    icp_public_key.clone(),
                    adversary_ixn_sig.qb64(),
                ),
            ],
            true, // skip verify
        )
        .unwrap();

        let divergence = server_kel.find_divergence().unwrap();
        assert_eq!(divergence.diverged_at_generation, 1);

        // Owner's local events
        let owner_events = owner.kel();
        let owner_saids: HashSet<_> = owner_events.iter().map(|e| &e.event.said).collect();

        // Owner's rot IS in owner's SAIDs
        assert!(owner_saids.contains(&owner_rot.said));

        // Simulate adversary rotation detection
        let adversary_rotated = server_kel.events().iter().any(|e| {
            divergence.divergent_saids.contains(&e.event.said)
                && e.event.is_rotation()
                && !owner_saids.contains(&e.event.said)
        });

        // Should NOT detect adversary rotation (it was owner who rotated)
        assert!(
            !adversary_rotated,
            "Should NOT detect owner rotation as adversary rotation"
        );
    }

    // ==================== Basic Kel tests ====================

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

    #[test]
    fn test_kel_new_is_empty() {
        let kel = Kel::new();
        assert!(kel.is_empty());
        assert_eq!(kel.len(), 0);
        assert!(kel.prefix().is_none());
        assert!(kel.last_said().is_none());
        assert!(kel.last_event().is_none());
    }

    #[tokio::test]
    async fn test_kel_truncate() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let (icp, icp_sig) = builder.incept().await.unwrap();
        let (ixn1, ixn1_sig) = builder.interact("anchor1").await.unwrap();
        let (ixn2, ixn2_sig) = builder.interact("anchor2").await.unwrap();

        let public_key = icp.public_key.clone().unwrap();
        let mut kel = Kel::from_events(
            vec![
                SignedKeyEvent::new(icp.clone(), public_key.clone(), icp_sig.qb64()),
                SignedKeyEvent::new(ixn1.clone(), public_key.clone(), ixn1_sig.qb64()),
                SignedKeyEvent::new(ixn2.clone(), public_key.clone(), ixn2_sig.qb64()),
            ],
            true,
        )
        .unwrap();

        assert_eq!(kel.len(), 3);
        kel.truncate(2);
        assert_eq!(kel.len(), 2);
        assert_eq!(kel.last_said(), Some(ixn1.said.as_str()));
    }

    #[tokio::test]
    async fn test_kel_confirmed_length_no_divergence() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let (icp, icp_sig) = builder.incept().await.unwrap();
        let (ixn, ixn_sig) = builder.interact("anchor").await.unwrap();

        let public_key = icp.public_key.clone().unwrap();
        let kel = Kel::from_events(
            vec![
                SignedKeyEvent::new(icp.clone(), public_key.clone(), icp_sig.qb64()),
                SignedKeyEvent::new(ixn.clone(), public_key.clone(), ixn_sig.qb64()),
            ],
            true,
        )
        .unwrap();

        // No divergence, so confirmed length equals total length
        assert_eq!(kel.confirmed_length(), 2);
    }

    #[tokio::test]
    async fn test_kel_confirmed_length_with_divergence() {
        let mut builder1 = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let (icp, icp_sig) = builder1.incept().await.unwrap();
        let (ixn1, ixn1_sig) = builder1.interact("anchor1").await.unwrap();

        let (current_key, next_key, recovery_key) = clone_keys(&builder1);
        let public_key = icp.public_key.clone().unwrap();

        let mut kel_for_builder2 = Kel::new();
        kel_for_builder2.push(SignedKeyEvent::new(
            icp.clone(),
            public_key.clone(),
            icp_sig.qb64(),
        ));

        let mut builder2 = KeyEventBuilder::with_kel(
            SoftwareKeyProvider::with_all_keys(current_key, next_key, recovery_key),
            None,
            None,
            kel_for_builder2,
        )
        .unwrap();
        let (ixn2, ixn2_sig) = builder2.interact("anchor2").await.unwrap();

        // Divergent KEL at generation 1
        let kel = Kel::from_events(
            vec![
                SignedKeyEvent::new(icp.clone(), public_key.clone(), icp_sig.qb64()),
                SignedKeyEvent::new(ixn1.clone(), public_key.clone(), ixn1_sig.qb64()),
                SignedKeyEvent::new(ixn2.clone(), public_key.clone(), ixn2_sig.qb64()),
            ],
            true,
        )
        .unwrap();

        // Divergence at generation 1, so confirmed length is 1 (just inception)
        assert_eq!(kel.confirmed_length(), 1);
    }

    #[tokio::test]
    async fn test_kel_last_establishment_event() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let (icp, icp_sig) = builder.incept().await.unwrap();
        let (ixn, ixn_sig) = builder.interact("anchor").await.unwrap();
        let (rot, rot_sig) = builder.rotate().await.unwrap();
        let (ixn2, ixn2_sig) = builder.interact("anchor2").await.unwrap();

        let icp_key = icp.public_key.clone().unwrap();
        let rot_key = rot.public_key.clone().unwrap();

        let kel = Kel::from_events(
            vec![
                SignedKeyEvent::new(icp.clone(), icp_key.clone(), icp_sig.qb64()),
                SignedKeyEvent::new(ixn.clone(), icp_key.clone(), ixn_sig.qb64()),
                SignedKeyEvent::new(rot.clone(), rot_key.clone(), rot_sig.qb64()),
                SignedKeyEvent::new(ixn2.clone(), rot_key.clone(), ixn2_sig.qb64()),
            ],
            false,
        )
        .unwrap();

        // Last event is ixn2, but last establishment is rot
        assert_eq!(kel.last_event().unwrap().event.said, ixn2.said);
        assert_eq!(kel.last_establishment_event().unwrap().event.said, rot.said);
    }

    #[tokio::test]
    async fn test_kel_from_events_empty_with_verify_succeeds() {
        // Empty events with skip_verify=false should succeed (no verification needed)
        let kel = Kel::from_events(vec![], false).unwrap();
        assert!(kel.is_empty());
    }

    #[tokio::test]
    async fn test_kel_verify_empty_fails() {
        let kel = Kel::new();
        let result = kel.verify();
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_kel_extend() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let (icp, icp_sig) = builder.incept().await.unwrap();
        let (ixn1, ixn1_sig) = builder.interact("anchor1").await.unwrap();
        let (ixn2, ixn2_sig) = builder.interact("anchor2").await.unwrap();

        let public_key = icp.public_key.clone().unwrap();

        let mut kel = Kel::new();
        kel.push(SignedKeyEvent::new(
            icp.clone(),
            public_key.clone(),
            icp_sig.qb64(),
        ));
        assert_eq!(kel.len(), 1);

        // Extend with multiple events
        kel.extend(vec![
            SignedKeyEvent::new(ixn1.clone(), public_key.clone(), ixn1_sig.qb64()),
            SignedKeyEvent::new(ixn2.clone(), public_key.clone(), ixn2_sig.qb64()),
        ]);
        assert_eq!(kel.len(), 3);
    }

    #[tokio::test]
    async fn test_kel_into_iterator() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let (icp, icp_sig) = builder.incept().await.unwrap();
        let (ixn, ixn_sig) = builder.interact("anchor").await.unwrap();

        let public_key = icp.public_key.clone().unwrap();
        let kel = Kel::from_events(
            vec![
                SignedKeyEvent::new(icp.clone(), public_key.clone(), icp_sig.qb64()),
                SignedKeyEvent::new(ixn.clone(), public_key.clone(), ixn_sig.qb64()),
            ],
            true,
        )
        .unwrap();

        let events: Vec<_> = kel.into_iter().collect();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event.said, icp.said);
        assert_eq!(events[1].event.said, ixn.said);
    }

    #[tokio::test]
    async fn test_kel_deref() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let (icp, icp_sig) = builder.incept().await.unwrap();

        let public_key = icp.public_key.clone().unwrap();
        let kel = Kel::from_events(
            vec![SignedKeyEvent::new(
                icp.clone(),
                public_key.clone(),
                icp_sig.qb64(),
            )],
            true,
        )
        .unwrap();

        // Test Deref - can use Vec methods
        assert_eq!(kel.first().unwrap().event.said, icp.said);
    }

    #[tokio::test]
    async fn test_kel_merge_empty_events_fails() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let (icp, icp_sig) = builder.incept().await.unwrap();

        let public_key = icp.public_key.clone().unwrap();
        let mut kel = Kel::from_events(
            vec![SignedKeyEvent::new(
                icp.clone(),
                public_key.clone(),
                icp_sig.qb64(),
            )],
            true,
        )
        .unwrap();

        let result = kel.merge(vec![]);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_kel_merge_gap_in_chain_fails() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let (icp, icp_sig) = builder.incept().await.unwrap();
        let (_ixn1, _) = builder.interact("anchor1").await.unwrap();
        let (ixn2, ixn2_sig) = builder.interact("anchor2").await.unwrap();

        let icp_key = icp.public_key.clone().unwrap();

        let mut kel = Kel::from_events(
            vec![SignedKeyEvent::new(
                icp.clone(),
                icp_key.clone(),
                icp_sig.qb64(),
            )],
            true,
        )
        .unwrap();

        // Try to add ixn2 directly (skipping ixn1) - should fail due to gap
        let result = kel.merge(vec![SignedKeyEvent::new(
            ixn2.clone(),
            icp_key.clone(),
            ixn2_sig.qb64(),
        )]);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_kel_map_saids_by_event_generation() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let (icp, icp_sig) = builder.incept().await.unwrap();
        let (ixn, ixn_sig) = builder.interact("anchor").await.unwrap();
        let (rot, rot_sig) = builder.rotate().await.unwrap();

        let icp_key = icp.public_key.clone().unwrap();
        let rot_key = rot.public_key.clone().unwrap();

        let kel = Kel::from_events(
            vec![
                SignedKeyEvent::new(icp.clone(), icp_key.clone(), icp_sig.qb64()),
                SignedKeyEvent::new(ixn.clone(), icp_key.clone(), ixn_sig.qb64()),
                SignedKeyEvent::new(rot.clone(), rot_key.clone(), rot_sig.qb64()),
            ],
            false,
        )
        .unwrap();

        let saids = kel.map_saids_by_event_generation();
        assert_eq!(saids.len(), 3);
        assert!(saids.get(&0).unwrap().contains(&icp.said));
        assert!(saids.get(&1).unwrap().contains(&ixn.said));
        assert!(saids.get(&2).unwrap().contains(&rot.said));
    }

    #[tokio::test]
    async fn test_kel_get_owner_kel_saids_from_tail() {
        let mut owner = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let (icp, icp_sig) = owner.incept().await.unwrap();

        // Clone builder state after inception for adversary
        let mut adversary = owner.clone();

        let (owner_ixn, owner_ixn_sig) = owner.interact("owner-anchor").await.unwrap();
        let (adversary_ixn, adversary_ixn_sig) =
            adversary.interact("adversary-anchor").await.unwrap();

        // Both ixn events are at the same generation (both point to icp) but have different SAIDs
        assert_eq!(owner_ixn.previous, adversary_ixn.previous);
        assert_ne!(owner_ixn.said, adversary_ixn.said);

        let icp_public_key = icp.public_key.clone().unwrap();

        // Create divergent KEL with both owner and adversary events
        let kel = Kel::from_events(
            vec![
                SignedKeyEvent::new(icp.clone(), icp_public_key.clone(), icp_sig.qb64()),
                SignedKeyEvent::new(
                    owner_ixn.clone(),
                    icp_public_key.clone(),
                    owner_ixn_sig.qb64(),
                ),
                SignedKeyEvent::new(
                    adversary_ixn.clone(),
                    icp_public_key.clone(),
                    adversary_ixn_sig.qb64(),
                ),
            ],
            true,
        )
        .unwrap();

        // Verify KEL is divergent
        assert!(kel.find_divergence().is_some());

        // Get owner SAIDs starting from owner's ixn (tail)
        // Should only include owner's chain, not adversary's event
        let owner_saids = kel.get_owner_kel_saids_from_tail(&owner_ixn.said);
        assert_eq!(owner_saids.len(), 2);
        assert!(owner_saids.contains(&icp.said));
        assert!(owner_saids.contains(&owner_ixn.said));
        assert!(!owner_saids.contains(&adversary_ixn.said));

        // Get adversary SAIDs starting from adversary's ixn
        // Should only include adversary's chain
        let adversary_saids = kel.get_owner_kel_saids_from_tail(&adversary_ixn.said);
        assert_eq!(adversary_saids.len(), 2);
        assert!(adversary_saids.contains(&icp.said));
        assert!(adversary_saids.contains(&adversary_ixn.said));
        assert!(!adversary_saids.contains(&owner_ixn.said));
    }

    #[tokio::test]
    async fn test_kel_sort_orders_by_generation() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let (icp, icp_sig) = builder.incept().await.unwrap();
        let (ixn, ixn_sig) = builder.interact("anchor").await.unwrap();

        let public_key = icp.public_key.clone().unwrap();

        // Create KEL with events in wrong order
        let mut kel = Kel(vec![
            SignedKeyEvent::new(ixn.clone(), public_key.clone(), ixn_sig.qb64()),
            SignedKeyEvent::new(icp.clone(), public_key.clone(), icp_sig.qb64()),
        ]);

        // Sort should reorder them
        kel.sort();
        assert_eq!(kel.0[0].event.said, icp.said);
        assert_eq!(kel.0[1].event.said, ixn.said);
    }

    #[tokio::test]
    async fn test_kel_merge_normal_append() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let (icp, icp_sig) = builder.incept().await.unwrap();
        // Use a valid Blake3 anchor (computed from test data)
        let anchor = Digest::blake3_256(b"test_anchor").qb64();
        let (ixn, ixn_sig) = builder.interact(&anchor).await.unwrap();

        let public_key = icp.public_key.clone().unwrap();

        let mut kel = Kel::from_events(
            vec![SignedKeyEvent::new(
                icp.clone(),
                public_key.clone(),
                icp_sig.qb64(),
            )],
            true,
        )
        .unwrap();

        // Normal append
        let result = kel.merge(vec![SignedKeyEvent::new(
            ixn.clone(),
            public_key.clone(),
            ixn_sig.qb64(),
        )]);
        assert!(result.is_ok());
        let (archived, added, merge_result) = result.unwrap();
        assert!(archived.is_empty());
        assert_eq!(added.len(), 1);
        assert_eq!(merge_result, KelMergeResult::Verified);
        assert_eq!(kel.len(), 2);
    }

    #[tokio::test]
    async fn test_kel_is_decommissioned() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let (icp, icp_sig) = builder.incept().await.unwrap();
        let icp_key = icp.public_key.clone().unwrap();

        let mut kel = Kel::from_events(
            vec![SignedKeyEvent::new(
                icp.clone(),
                icp_key.clone(),
                icp_sig.qb64(),
            )],
            true,
        )
        .unwrap();

        // Not decommissioned initially
        assert!(!kel.is_decommissioned());

        // Create decommission event
        let _ = builder.decommission().await.unwrap();
        let dec_event = builder.events().last().unwrap().clone();

        kel.push(dec_event);

        // Now decommissioned
        assert!(kel.is_decommissioned());
    }

    #[tokio::test]
    async fn test_kel_is_contested() {
        let kel = Kel::new();
        assert!(!kel.is_contested());
    }

    #[tokio::test]
    async fn test_kel_delegating_prefix_none() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let (icp, icp_sig) = builder.incept().await.unwrap();
        let icp_key = icp.public_key.clone().unwrap();

        let kel = Kel::from_events(
            vec![SignedKeyEvent::new(icp, icp_key, icp_sig.qb64())],
            true,
        )
        .unwrap();

        // Non-delegated KEL has no delegating prefix
        assert!(kel.delegating_prefix().is_none());
        assert!(!kel.is_delegated());
    }

    #[tokio::test]
    async fn test_kel_empty_delegating_prefix() {
        let kel = Kel::new();
        assert!(kel.delegating_prefix().is_none());
        assert!(!kel.is_delegated());
    }

    #[tokio::test]
    async fn test_kel_find_divergence_empty() {
        let kel = Kel::new();
        assert!(kel.find_divergence().is_none());
    }

    #[tokio::test]
    async fn test_kel_reveals_recovery_after_divergence() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let (icp, icp_sig) = builder.incept().await.unwrap();
        let icp_key = icp.public_key.clone().unwrap();

        let kel = Kel::from_events(
            vec![SignedKeyEvent::new(icp.clone(), icp_key, icp_sig.qb64())],
            true,
        )
        .unwrap();

        // No recovery revealed with empty divergent set
        let empty_set: HashSet<String> = HashSet::new();
        assert!(!kel.reveals_recovery_after_divergence(&empty_set));

        // No recovery revealed even with icp in set (icp doesn't reveal recovery)
        let mut with_icp: HashSet<String> = HashSet::new();
        with_icp.insert(icp.said.clone());
        assert!(!kel.reveals_recovery_after_divergence(&with_icp));
    }

    #[tokio::test]
    async fn test_kel_merge_duplicate_events() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let (icp, icp_sig) = builder.incept().await.unwrap();
        let anchor = Digest::blake3_256(b"test").qb64();
        let (ixn, ixn_sig) = builder.interact(&anchor).await.unwrap();

        let icp_key = icp.public_key.clone().unwrap();

        let mut kel = Kel::from_events(
            vec![
                SignedKeyEvent::new(icp.clone(), icp_key.clone(), icp_sig.qb64()),
                SignedKeyEvent::new(ixn.clone(), icp_key.clone(), ixn_sig.qb64()),
            ],
            true,
        )
        .unwrap();

        // Try to merge the same event again (overlap, all SAIDs present)
        let result = kel.merge(vec![SignedKeyEvent::new(
            ixn.clone(),
            icp_key.clone(),
            ixn_sig.qb64(),
        )]);
        assert!(result.is_ok());
        let (archived, added, merge_result) = result.unwrap();
        assert!(archived.is_empty());
        assert!(added.is_empty()); // No new events added
        assert_eq!(merge_result, KelMergeResult::Verified);
    }

    #[tokio::test]
    async fn test_kel_deref_mut() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let (icp, icp_sig) = builder.incept().await.unwrap();

        let public_key = icp.public_key.clone().unwrap();
        let mut kel = Kel::from_events(
            vec![SignedKeyEvent::new(icp.clone(), public_key, icp_sig.qb64())],
            true,
        )
        .unwrap();

        // Test DerefMut - can use Vec mutable methods
        assert_eq!(kel.len(), 1);
        kel.clear(); // Using Vec::clear via DerefMut
        assert!(kel.is_empty());
    }

    #[tokio::test]
    async fn test_kel_contains_anchor_no_interactions() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let (icp, icp_sig) = builder.incept().await.unwrap();
        let icp_key = icp.public_key.clone().unwrap();

        let kel = Kel::from_events(
            vec![SignedKeyEvent::new(icp, icp_key, icp_sig.qb64())],
            true,
        )
        .unwrap();

        // KEL with only inception has no anchors
        assert!(!kel.contains_anchor("any_anchor"));
    }

    #[tokio::test]
    async fn test_remove_adversary_events() {
        let mut builder1 = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let (icp, icp_sig) = builder1.incept().await.unwrap();
        let (ixn1, ixn1_sig) = builder1.interact("owner_anchor").await.unwrap();

        let (current_key, next_key, recovery_key) = clone_keys(&builder1);
        let icp_key = icp.public_key.clone().unwrap();

        // Create adversary ixn
        let mut adversary_kel = Kel::new();
        adversary_kel.push(SignedKeyEvent::new(
            icp.clone(),
            icp_key.clone(),
            icp_sig.qb64(),
        ));

        let mut builder2 = KeyEventBuilder::with_kel(
            SoftwareKeyProvider::with_all_keys(current_key, next_key, recovery_key),
            None,
            None,
            adversary_kel,
        )
        .unwrap();
        let (ixn2, ixn2_sig) = builder2.interact("adversary_anchor").await.unwrap();

        // Create divergent KEL
        let mut kel = Kel::from_events(
            vec![
                SignedKeyEvent::new(icp.clone(), icp_key.clone(), icp_sig.qb64()),
                SignedKeyEvent::new(ixn1.clone(), icp_key.clone(), ixn1_sig.qb64()),
                SignedKeyEvent::new(ixn2.clone(), icp_key.clone(), ixn2_sig.qb64()),
            ],
            true,
        )
        .unwrap();

        // Owner SAIDs (icp and ixn1)
        let mut owner_saids = HashSet::new();
        owner_saids.insert(icp.said.clone());
        owner_saids.insert(ixn1.said.clone());

        let removed = kel.remove_adversary_events(&owner_saids).unwrap();

        // Should have removed adversary event
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].event.said, ixn2.said);

        // KEL should now only have owner events
        assert_eq!(kel.len(), 2);
    }

    // ==================== Complex Merge/Divergence Tests ====================

    #[tokio::test]
    async fn test_merge_on_contested_kel_fails() {
        // When a KEL is already contested, merge should fail with ContestedKel error
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let (icp, icp_sig) = builder.incept().await.unwrap();
        let icp_key = icp.public_key.clone().unwrap();

        // Create a contest event
        let (cnt, _) = builder.contest().await.unwrap();
        let cnt_event = builder.events().last().unwrap().clone();
        let cnt_key = cnt.public_key.clone().unwrap();

        let mut kel = Kel::from_events(
            vec![
                SignedKeyEvent::new(icp.clone(), icp_key.clone(), icp_sig.qb64()),
                cnt_event,
            ],
            true, // skip verify for test setup
        )
        .unwrap();

        assert!(kel.is_contested());

        // Try to merge new events - should fail
        // Create a fresh builder to make an ixn (since contested builder won't allow interact)
        let mut builder2 = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        builder2.incept().await.unwrap();
        let anchor = Digest::blake3_256(b"test").qb64();
        let (ixn, ixn_sig) = builder2.interact(&anchor).await.unwrap();

        // Manually fix the ixn to chain from cnt
        let mut fake_ixn = ixn.clone();
        fake_ixn.previous = Some(cnt.said.clone());
        fake_ixn.prefix = icp.prefix.clone();

        let result = kel.merge(vec![SignedKeyEvent::new(fake_ixn, cnt_key, ixn_sig.qb64())]);

        assert!(result.is_err());
        assert!(matches!(result, Err(KelsError::ContestedKel(_))));
    }

    #[tokio::test]
    async fn test_merge_non_recovery_on_frozen_kel_returns_frozen() {
        // When KEL is divergent (frozen) and new event doesn't reveal recovery key,
        // merge should return Frozen result
        let mut builder1 = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let (icp, icp_sig) = builder1.incept().await.unwrap();
        let anchor1 = Digest::blake3_256(b"anchor1").qb64();
        let (ixn1, ixn1_sig) = builder1.interact(&anchor1).await.unwrap();

        let (current_key, next_key, recovery_key) = clone_keys(&builder1);
        let icp_key = icp.public_key.clone().unwrap();

        // Create adversary's divergent ixn
        let mut adversary_kel = Kel::new();
        adversary_kel.push(SignedKeyEvent::new(
            icp.clone(),
            icp_key.clone(),
            icp_sig.qb64(),
        ));

        let mut builder2 = KeyEventBuilder::with_kel(
            SoftwareKeyProvider::with_all_keys(current_key, next_key, recovery_key),
            None,
            None,
            adversary_kel,
        )
        .unwrap();
        let anchor2 = Digest::blake3_256(b"anchor2").qb64();
        let (ixn2, ixn2_sig) = builder2.interact(&anchor2).await.unwrap();

        // Create divergent KEL (frozen state)
        let mut kel = Kel::from_events(
            vec![
                SignedKeyEvent::new(icp.clone(), icp_key.clone(), icp_sig.qb64()),
                SignedKeyEvent::new(ixn1.clone(), icp_key.clone(), ixn1_sig.qb64()),
                SignedKeyEvent::new(ixn2.clone(), icp_key.clone(), ixn2_sig.qb64()),
            ],
            true,
        )
        .unwrap();

        assert!(kel.find_divergence().is_some());

        // Try to merge another ixn (non-recovery event) - should return Frozen
        let anchor3 = Digest::blake3_256(b"anchor3").qb64();
        let (ixn3, ixn3_sig) = builder1.interact(&anchor3).await.unwrap();
        let result = kel.merge(vec![SignedKeyEvent::new(
            ixn3.clone(),
            icp_key.clone(),
            ixn3_sig.qb64(),
        )]);

        assert!(result.is_ok());
        let (_, _, merge_result) = result.unwrap();
        assert_eq!(merge_result, KelMergeResult::Frozen);
    }

    #[tokio::test]
    async fn test_merge_recovery_on_divergent_kel_succeeds() {
        // Recovery event on divergent KEL (where recovery not yet revealed) should succeed
        let mut builder1 = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let (icp, icp_sig) = builder1.incept().await.unwrap();
        let anchor1 = Digest::blake3_256(b"anchor1").qb64();
        let (ixn1, ixn1_sig) = builder1.interact(&anchor1).await.unwrap();

        let (current_key, next_key, recovery_key) = clone_keys(&builder1);
        let icp_key = icp.public_key.clone().unwrap();

        // Create adversary's divergent ixn
        let mut adversary_kel = Kel::new();
        adversary_kel.push(SignedKeyEvent::new(
            icp.clone(),
            icp_key.clone(),
            icp_sig.qb64(),
        ));

        let mut builder2 = KeyEventBuilder::with_kel(
            SoftwareKeyProvider::with_all_keys(
                current_key.clone(),
                next_key.clone(),
                recovery_key.clone(),
            ),
            None,
            None,
            adversary_kel,
        )
        .unwrap();
        let anchor2 = Digest::blake3_256(b"anchor2").qb64();
        let (ixn2, ixn2_sig) = builder2.interact(&anchor2).await.unwrap();

        // Create divergent KEL
        let mut kel = Kel::from_events(
            vec![
                SignedKeyEvent::new(icp.clone(), icp_key.clone(), icp_sig.qb64()),
                SignedKeyEvent::new(ixn1.clone(), icp_key.clone(), ixn1_sig.qb64()),
                SignedKeyEvent::new(ixn2.clone(), icp_key.clone(), ixn2_sig.qb64()),
            ],
            true,
        )
        .unwrap();

        assert!(kel.find_divergence().is_some());

        // Create recovery event from builder1 (original owner)
        let (_rec, _) = builder1.recover(false).await.unwrap();
        let rec_event = builder1.events().last().unwrap().clone();

        // Merge recovery event
        let result = kel.merge(vec![rec_event]);

        assert!(result.is_ok());
        let (archived, added, merge_result) = result.unwrap();
        assert_eq!(merge_result, KelMergeResult::Recovered);
        // Adversary event should be archived
        assert_eq!(archived.len(), 1);
        assert_eq!(archived[0].event.said, ixn2.said);
        // Recovery event should be added
        assert_eq!(added.len(), 1);
        assert!(added[0].event.is_recover());
    }

    #[tokio::test]
    async fn test_merge_recoverable_divergence() {
        // When divergent events arrive but neither side has used recovery key,
        // merge should return Recoverable
        let mut builder1 = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let (icp, icp_sig) = builder1.incept().await.unwrap();
        let anchor1 = Digest::blake3_256(b"anchor1").qb64();
        let (ixn1, ixn1_sig) = builder1.interact(&anchor1).await.unwrap();

        let (current_key, next_key, recovery_key) = clone_keys(&builder1);
        let icp_key = icp.public_key.clone().unwrap();

        // Start with just icp in KEL
        let mut kel = Kel::from_events(
            vec![SignedKeyEvent::new(
                icp.clone(),
                icp_key.clone(),
                icp_sig.qb64(),
            )],
            true,
        )
        .unwrap();

        // Add owner's ixn1
        kel.merge(vec![SignedKeyEvent::new(
            ixn1.clone(),
            icp_key.clone(),
            ixn1_sig.qb64(),
        )])
        .unwrap();

        // Create adversary's divergent ixn at same generation
        let mut adversary_kel = Kel::new();
        adversary_kel.push(SignedKeyEvent::new(
            icp.clone(),
            icp_key.clone(),
            icp_sig.qb64(),
        ));

        let mut builder2 = KeyEventBuilder::with_kel(
            SoftwareKeyProvider::with_all_keys(current_key, next_key, recovery_key),
            None,
            None,
            adversary_kel,
        )
        .unwrap();
        let anchor2 = Digest::blake3_256(b"anchor2").qb64();
        let (ixn2, ixn2_sig) = builder2.interact(&anchor2).await.unwrap();

        // Merge adversary's divergent event - should detect recoverable divergence
        let result = kel.merge(vec![SignedKeyEvent::new(
            ixn2.clone(),
            icp_key.clone(),
            ixn2_sig.qb64(),
        )]);

        assert!(result.is_ok());
        let (archived, added, merge_result) = result.unwrap();
        assert_eq!(merge_result, KelMergeResult::Recoverable);
        assert!(archived.is_empty()); // Nothing archived yet
        assert_eq!(added.len(), 1); // Divergent event was added
    }

    #[tokio::test]
    async fn test_merge_decommissioned_kel_blocks_append() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let (icp, icp_sig) = builder.incept().await.unwrap();
        let icp_key = icp.public_key.clone().unwrap();

        // Create decommission event
        let _ = builder.decommission().await.unwrap();
        let dec_event = builder.events().last().unwrap().clone();

        let mut kel = Kel::from_events(
            vec![
                SignedKeyEvent::new(icp.clone(), icp_key.clone(), icp_sig.qb64()),
                dec_event.clone(),
            ],
            true,
        )
        .unwrap();

        assert!(kel.is_decommissioned());

        // Try to merge new ixn after decommission - should fail
        // First create a new builder to make an ixn
        let mut builder2 = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        builder2.incept().await.unwrap();
        let anchor = Digest::blake3_256(b"test").qb64();
        let (ixn, ixn_sig) = builder2.interact(&anchor).await.unwrap();

        // Manually create a fake ixn that chains from dec
        let mut fake_ixn = ixn.clone();
        fake_ixn.previous = Some(dec_event.event.said.clone());
        fake_ixn.prefix = icp.prefix.clone();

        let result = kel.merge(vec![SignedKeyEvent::new(
            fake_ixn,
            dec_event.event.public_key.clone().unwrap(),
            ixn_sig.qb64(),
        )]);

        assert!(result.is_err());
        assert!(matches!(result, Err(KelsError::KelDecommissioned)));
    }

    #[tokio::test]
    async fn test_merge_recovery_protected_scenario() {
        // When old (existing) events have revealed recovery key and new event is not contest,
        // merge should return RecoveryProtected
        let mut builder1 = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let (icp, icp_sig) = builder1.incept().await.unwrap();
        let icp_key = icp.public_key.clone().unwrap();

        // Owner does a recovery rotation (reveals recovery key)
        let (ror, _) = builder1.rotate_recovery().await.unwrap();
        let ror_event = builder1.events().last().unwrap().clone();
        let _ror_key = ror.public_key.clone().unwrap();

        let (current_key, next_key, recovery_key) = clone_keys(&builder1);

        // Create adversary who starts from icp (before ror)
        let mut adversary_kel = Kel::new();
        adversary_kel.push(SignedKeyEvent::new(
            icp.clone(),
            icp_key.clone(),
            icp_sig.qb64(),
        ));

        let mut builder2 = KeyEventBuilder::with_kel(
            SoftwareKeyProvider::with_all_keys(current_key, next_key, recovery_key),
            None,
            None,
            adversary_kel,
        )
        .unwrap();
        let anchor = Digest::blake3_256(b"adversary").qb64();
        let (adv_ixn, adv_ixn_sig) = builder2.interact(&anchor).await.unwrap();

        // Create KEL with owner's ror (has recovery revealed)
        let mut kel = Kel::from_events(
            vec![
                SignedKeyEvent::new(icp.clone(), icp_key.clone(), icp_sig.qb64()),
                ror_event.clone(),
            ],
            true,
        )
        .unwrap();

        // Merge adversary's divergent ixn (not a contest event)
        // Since owner revealed recovery, adversary should need to contest
        let result = kel.merge(vec![SignedKeyEvent::new(
            adv_ixn.clone(),
            icp_key.clone(),
            adv_ixn_sig.qb64(),
        )]);

        assert!(result.is_ok());
        let (_, _, merge_result) = result.unwrap();
        assert_eq!(merge_result, KelMergeResult::RecoveryProtected);
    }

    #[tokio::test]
    async fn test_merge_contest_on_divergent_with_recovery_revealed() {
        // When KEL is divergent and owner's events revealed recovery, adversary's contest should succeed
        // This tests the overlap path where old events have revealed recovery

        let mut builder1 = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let (icp, icp_sig) = builder1.incept().await.unwrap();
        let icp_key = icp.public_key.clone().unwrap();

        // Save keys before any rotation for adversary
        let (pre_ror_current, pre_ror_next, pre_ror_recovery) = clone_keys(&builder1);

        // Owner does a recovery rotation (reveals recovery key) - this rotates keys
        let (_ror, _) = builder1.rotate_recovery().await.unwrap();
        let ror_event = builder1.events().last().unwrap().clone();

        // Create adversary with pre-rotation keys (starts from icp)
        let mut adversary_kel = Kel::new();
        adversary_kel.push(SignedKeyEvent::new(
            icp.clone(),
            icp_key.clone(),
            icp_sig.qb64(),
        ));

        let mut builder2 = KeyEventBuilder::with_kel(
            SoftwareKeyProvider::with_all_keys(pre_ror_current, pre_ror_next, pre_ror_recovery),
            None,
            None,
            adversary_kel,
        )
        .unwrap();

        // Adversary creates a contest event
        let (_cnt, _) = builder2.contest().await.unwrap();
        let cnt_event = builder2.events().last().unwrap().clone();

        // Create KEL with owner's ror (has recovery revealed)
        let mut kel = Kel::from_events(
            vec![
                SignedKeyEvent::new(icp.clone(), icp_key.clone(), icp_sig.qb64()),
                ror_event.clone(),
            ],
            true,
        )
        .unwrap();

        // Merge adversary's contest event - this creates divergence at gen 1
        // Since owner revealed recovery (ror), contest should succeed
        let result = kel.merge(vec![cnt_event]);

        assert!(result.is_ok());
        let (_, added, merge_result) = result.unwrap();
        assert_eq!(merge_result, KelMergeResult::Contested);
        assert_eq!(added.len(), 1);
        assert!(added[0].event.is_contest());
    }

    #[tokio::test]
    async fn test_merge_contest_with_extra_events_fails() {
        // Contest event should not have additional events after it
        // Scenario: owner creates icp, adversary does ror, owner tries cnt + ixn

        let mut owner = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let (icp, icp_sig) = owner.incept().await.unwrap();
        let icp_key = icp.public_key.clone().unwrap();

        // Clone builder for adversary before any further events
        let mut adversary = owner.clone();

        // Adversary does recovery rotation (reveals recovery key)
        let (ror, ror_sig) = adversary.rotate_recovery().await.unwrap();
        let ror_key = ror.public_key.clone().unwrap();

        // Server KEL has icp + adversary's ror
        let mut kel = Kel::from_events(
            vec![
                SignedKeyEvent::new(icp.clone(), icp_key.clone(), icp_sig.qb64()),
                SignedKeyEvent::new(ror.clone(), ror_key.clone(), ror_sig.qb64()),
            ],
            true,
        )
        .unwrap();

        // Owner creates contest event
        let (cnt, cnt_sig) = owner.contest().await.unwrap();
        let cnt_key = cnt.public_key.clone().unwrap();

        // Manually create an ixn that chains from cnt (builder won't allow after contest)
        let anchor = Digest::blake3_256(b"owner_anchor").qb64();
        let fake_ixn = KeyEvent::create_interaction(&cnt, anchor).unwrap();
        let fake_ixn_sig = owner
            .key_provider()
            .sign(fake_ixn.said.as_bytes())
            .await
            .unwrap();

        // Try to merge cnt + ixn together - should fail
        let result = kel.merge(vec![
            SignedKeyEvent::new(cnt.clone(), cnt_key.clone(), cnt_sig.qb64()),
            SignedKeyEvent::new(fake_ixn.clone(), cnt_key.clone(), fake_ixn_sig.qb64()),
        ]);

        // Should fail because contest must be final (no events after it)
        assert!(result.is_err());
        assert!(matches!(result, Err(KelsError::InvalidKel(_))));
    }

    #[tokio::test]
    async fn test_verify_detects_divergence() {
        // verify() should detect and return divergence info
        let mut builder1 = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let (icp, icp_sig) = builder1.incept().await.unwrap();
        let anchor1 = Digest::blake3_256(b"anchor1").qb64();
        let (ixn1, ixn1_sig) = builder1.interact(&anchor1).await.unwrap();

        let (current_key, next_key, recovery_key) = clone_keys(&builder1);
        let icp_key = icp.public_key.clone().unwrap();

        // Create adversary
        let mut adversary_kel = Kel::new();
        adversary_kel.push(SignedKeyEvent::new(
            icp.clone(),
            icp_key.clone(),
            icp_sig.qb64(),
        ));

        let mut builder2 = KeyEventBuilder::with_kel(
            SoftwareKeyProvider::with_all_keys(current_key, next_key, recovery_key),
            None,
            None,
            adversary_kel,
        )
        .unwrap();
        let anchor2 = Digest::blake3_256(b"anchor2").qb64();
        let (ixn2, ixn2_sig) = builder2.interact(&anchor2).await.unwrap();

        // Create divergent KEL
        let kel = Kel::from_events(
            vec![
                SignedKeyEvent::new(icp.clone(), icp_key.clone(), icp_sig.qb64()),
                SignedKeyEvent::new(ixn1.clone(), icp_key.clone(), ixn1_sig.qb64()),
                SignedKeyEvent::new(ixn2.clone(), icp_key.clone(), ixn2_sig.qb64()),
            ],
            true,
        )
        .unwrap();

        // verify() should succeed but report divergence
        let result = kel.verify();
        assert!(result.is_ok());
        let divergence = result.unwrap();
        assert!(divergence.is_some());
        let info = divergence.unwrap();
        assert_eq!(info.diverged_at_generation, 1);
    }

    // ==================== Already-Divergent KEL Merge Tests ====================
    // These tests cover the code paths at lines 233-274 where KEL is already divergent

    #[tokio::test]
    async fn test_merge_contest_on_already_divergent_kel_with_recovery_revealed() {
        // KEL is already divergent, and one branch revealed recovery.
        // Contest event should succeed via lines 236-248.

        let mut builder1 = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let (icp, icp_sig) = builder1.incept().await.unwrap();
        let icp_key = icp.public_key.clone().unwrap();

        // Save keys before recovery rotation
        let (pre_ror_current, pre_ror_next, pre_ror_recovery) = clone_keys(&builder1);

        // Owner does recovery rotation (reveals recovery key)
        let (_ror, _) = builder1.rotate_recovery().await.unwrap();
        let ror_event = builder1.events().last().unwrap().clone();

        // Create adversary from inception state
        let mut adversary_kel = Kel::new();
        adversary_kel.push(SignedKeyEvent::new(
            icp.clone(),
            icp_key.clone(),
            icp_sig.qb64(),
        ));

        let mut builder2 = KeyEventBuilder::with_kel(
            SoftwareKeyProvider::with_all_keys(pre_ror_current, pre_ror_next, pre_ror_recovery),
            None,
            None,
            adversary_kel,
        )
        .unwrap();

        // Adversary does an ixn (creating divergence)
        let anchor = Digest::blake3_256(b"adv_anchor").qb64();
        let (adv_ixn, adv_ixn_sig) = builder2.interact(&anchor).await.unwrap();

        // Create already-divergent KEL with ror (reveals recovery) and adversary ixn
        let mut kel = Kel::from_events(
            vec![
                SignedKeyEvent::new(icp.clone(), icp_key.clone(), icp_sig.qb64()),
                ror_event.clone(),
                SignedKeyEvent::new(adv_ixn.clone(), icp_key.clone(), adv_ixn_sig.qb64()),
            ],
            true,
        )
        .unwrap();

        // Verify it's divergent
        assert!(kel.find_divergence().is_some());

        // Now adversary creates contest event (after their ixn was already in KEL)
        let (_, _) = builder2.contest().await.unwrap();
        let cnt_event = builder2.events().last().unwrap().clone();

        // Merge contest on already-divergent KEL where recovery is revealed
        let result = kel.merge(vec![cnt_event]);

        assert!(result.is_ok());
        let (_, added, merge_result) = result.unwrap();
        assert_eq!(merge_result, KelMergeResult::Contested);
        assert_eq!(added.len(), 1);
        assert!(added[0].event.is_contest());
    }

    #[tokio::test]
    async fn test_merge_contest_on_already_divergent_kel_without_recovery_revealed_fails() {
        // KEL is already divergent, but no recovery revealed.
        // Contest event should fail with Frozen error (line 250).

        let mut builder1 = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let (icp, icp_sig) = builder1.incept().await.unwrap();
        let icp_key = icp.public_key.clone().unwrap();

        // Save keys for adversary
        let (current_key, next_key, recovery_key) = clone_keys(&builder1);

        // Owner does normal ixn (no recovery revealed)
        let anchor1 = Digest::blake3_256(b"owner_anchor").qb64();
        let (ixn1, ixn1_sig) = builder1.interact(&anchor1).await.unwrap();

        // Create adversary from inception state
        let mut adversary_kel = Kel::new();
        adversary_kel.push(SignedKeyEvent::new(
            icp.clone(),
            icp_key.clone(),
            icp_sig.qb64(),
        ));

        let mut builder2 = KeyEventBuilder::with_kel(
            SoftwareKeyProvider::with_all_keys(current_key, next_key, recovery_key),
            None,
            None,
            adversary_kel,
        )
        .unwrap();

        // Adversary does an ixn (creating divergence)
        let anchor2 = Digest::blake3_256(b"adv_anchor").qb64();
        let (adv_ixn, adv_ixn_sig) = builder2.interact(&anchor2).await.unwrap();

        // Create already-divergent KEL with NO recovery revealed
        let mut kel = Kel::from_events(
            vec![
                SignedKeyEvent::new(icp.clone(), icp_key.clone(), icp_sig.qb64()),
                SignedKeyEvent::new(ixn1.clone(), icp_key.clone(), ixn1_sig.qb64()),
                SignedKeyEvent::new(adv_ixn.clone(), icp_key.clone(), adv_ixn_sig.qb64()),
            ],
            true,
        )
        .unwrap();

        // Verify it's divergent
        assert!(kel.find_divergence().is_some());

        // Adversary creates contest event
        let (_, _) = builder2.contest().await.unwrap();
        let cnt_event = builder2.events().last().unwrap().clone();

        // Merge contest should fail with Frozen (recovery not revealed)
        let result = kel.merge(vec![cnt_event]);

        assert!(result.is_err());
        assert!(matches!(result, Err(KelsError::Frozen)));
    }

    #[tokio::test]
    async fn test_merge_contest_on_clean_kel_fails() {
        // Contest on a clean (non-divergent) KEL should fail.
        // Contest requires divergence to be valid.

        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let (icp, icp_sig) = builder.incept().await.unwrap();
        let icp_key = icp.public_key.clone().unwrap();

        // Create a clean KEL with just inception
        let mut kel = Kel::from_events(
            vec![SignedKeyEvent::new(icp, icp_key.clone(), icp_sig.qb64())],
            false,
        )
        .unwrap();

        // Verify KEL is not divergent
        assert!(kel.find_divergence().is_none());

        // Try to contest - should fail because no divergence
        let (_, _) = builder.contest().await.unwrap();
        let cnt_event = builder.events().last().unwrap().clone();

        let result = kel.merge(vec![cnt_event]);

        assert!(result.is_err());
        assert!(
            matches!(result, Err(KelsError::InvalidKel(ref msg)) if msg.contains("Contest requires divergence"))
        );
    }

    #[tokio::test]
    async fn test_merge_recovery_on_already_divergent_kel_succeeds() {
        // KEL is already divergent, no recovery revealed yet.
        // Recovery event should succeed via lines 252-267.

        let mut builder1 = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let (icp, icp_sig) = builder1.incept().await.unwrap();
        let icp_key = icp.public_key.clone().unwrap();

        // Save keys for adversary
        let (current_key, next_key, recovery_key) = clone_keys(&builder1);

        // Owner does normal ixn (no recovery revealed)
        let anchor1 = Digest::blake3_256(b"owner_anchor").qb64();
        let (ixn1, ixn1_sig) = builder1.interact(&anchor1).await.unwrap();

        // Create adversary from inception state
        let mut adversary_kel = Kel::new();
        adversary_kel.push(SignedKeyEvent::new(
            icp.clone(),
            icp_key.clone(),
            icp_sig.qb64(),
        ));

        let mut builder2 = KeyEventBuilder::with_kel(
            SoftwareKeyProvider::with_all_keys(current_key, next_key, recovery_key),
            None,
            None,
            adversary_kel,
        )
        .unwrap();

        // Adversary does an ixn (creating divergence)
        let anchor2 = Digest::blake3_256(b"adv_anchor").qb64();
        let (adv_ixn, adv_ixn_sig) = builder2.interact(&anchor2).await.unwrap();

        // Create already-divergent KEL with NO recovery revealed
        let mut kel = Kel::from_events(
            vec![
                SignedKeyEvent::new(icp.clone(), icp_key.clone(), icp_sig.qb64()),
                SignedKeyEvent::new(ixn1.clone(), icp_key.clone(), ixn1_sig.qb64()),
                SignedKeyEvent::new(adv_ixn.clone(), icp_key.clone(), adv_ixn_sig.qb64()),
            ],
            true,
        )
        .unwrap();

        // Verify it's divergent
        assert!(kel.find_divergence().is_some());

        // Owner creates recovery event
        let (_, _) = builder1.recover(false).await.unwrap();
        let rec_event = builder1.events().last().unwrap().clone();

        // Merge recovery on already-divergent KEL
        let result = kel.merge(vec![rec_event]);

        assert!(result.is_ok());
        let (archived, added, merge_result) = result.unwrap();
        assert_eq!(merge_result, KelMergeResult::Recovered);
        // Adversary ixn should be archived
        assert_eq!(archived.len(), 1);
        assert_eq!(archived[0].event.said, adv_ixn.said);
        // Recovery event should be added
        assert_eq!(added.len(), 1);
        assert!(added[0].event.is_recover());
    }

    #[tokio::test]
    async fn test_merge_recovery_on_already_divergent_kel_with_recovery_revealed_fails() {
        // KEL is already divergent and recovery WAS revealed (by owner).
        // Recovery event from adversary should fail with ContestRequired (line 269).

        let mut builder1 = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let (icp, icp_sig) = builder1.incept().await.unwrap();
        let icp_key = icp.public_key.clone().unwrap();

        // Save keys for adversary BEFORE owner rotates
        let (pre_ror_current, pre_ror_next, pre_ror_recovery) = clone_keys(&builder1);

        // Owner does recovery rotation (reveals recovery key)
        let (_ror, _) = builder1.rotate_recovery().await.unwrap();
        let ror_event = builder1.events().last().unwrap().clone();

        // Create adversary from inception state (with pre-rotation keys)
        let mut adversary_kel = Kel::new();
        adversary_kel.push(SignedKeyEvent::new(
            icp.clone(),
            icp_key.clone(),
            icp_sig.qb64(),
        ));

        let mut builder2 = KeyEventBuilder::with_kel(
            SoftwareKeyProvider::with_all_keys(pre_ror_current, pre_ror_next, pre_ror_recovery),
            None,
            None,
            adversary_kel,
        )
        .unwrap();

        // Adversary does an ixn (creating divergence)
        let anchor = Digest::blake3_256(b"adv_anchor").qb64();
        let (adv_ixn, adv_ixn_sig) = builder2.interact(&anchor).await.unwrap();

        // Create already-divergent KEL with recovery revealed (ror)
        let mut kel = Kel::from_events(
            vec![
                SignedKeyEvent::new(icp.clone(), icp_key.clone(), icp_sig.qb64()),
                ror_event.clone(),
                SignedKeyEvent::new(adv_ixn.clone(), icp_key.clone(), adv_ixn_sig.qb64()),
            ],
            true,
        )
        .unwrap();

        // Verify it's divergent
        assert!(kel.find_divergence().is_some());

        // Adversary creates recovery event
        let (_, _) = builder2.recover(false).await.unwrap();
        let rec_event = builder2.events().last().unwrap().clone();

        // Merge recovery should fail with ContestRequired (owner already revealed recovery)
        let result = kel.merge(vec![rec_event]);

        assert!(result.is_err());
        assert!(matches!(result, Err(KelsError::ContestRequired)));
    }

    #[tokio::test]
    async fn test_merge_contest_on_already_divergent_with_extra_events_fails() {
        // Contest on already-divergent KEL with extra events should fail (line 238-241)

        let mut builder1 = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let (icp, icp_sig) = builder1.incept().await.unwrap();
        let icp_key = icp.public_key.clone().unwrap();

        // Save keys for adversary BEFORE owner rotates
        let (pre_ror_current, pre_ror_next, pre_ror_recovery) = clone_keys(&builder1);

        // Owner does recovery rotation (reveals recovery key)
        let (_ror, _) = builder1.rotate_recovery().await.unwrap();
        let ror_event = builder1.events().last().unwrap().clone();

        // Create adversary from inception state
        let mut adversary_kel = Kel::new();
        adversary_kel.push(SignedKeyEvent::new(
            icp.clone(),
            icp_key.clone(),
            icp_sig.qb64(),
        ));

        let mut builder2 = KeyEventBuilder::with_kel(
            SoftwareKeyProvider::with_all_keys(pre_ror_current, pre_ror_next, pre_ror_recovery),
            None,
            None,
            adversary_kel,
        )
        .unwrap();

        // Adversary does an ixn (creating divergence)
        let anchor = Digest::blake3_256(b"adv_anchor").qb64();
        let (adv_ixn, adv_ixn_sig) = builder2.interact(&anchor).await.unwrap();

        // Create already-divergent KEL with recovery revealed
        let mut kel = Kel::from_events(
            vec![
                SignedKeyEvent::new(icp.clone(), icp_key.clone(), icp_sig.qb64()),
                ror_event.clone(),
                SignedKeyEvent::new(adv_ixn.clone(), icp_key.clone(), adv_ixn_sig.qb64()),
            ],
            true,
        )
        .unwrap();

        // Adversary creates contest
        let (cnt, _) = builder2.contest().await.unwrap();
        let cnt_event = builder2.events().last().unwrap().clone();
        let cnt_key = cnt.public_key.clone().unwrap();

        // Create a fake event after contest
        let fake_anchor = Digest::blake3_256(b"fake").qb64();
        let fake_ixn = KeyEvent::create_interaction(&cnt, fake_anchor).unwrap();
        let fake_sig = builder2
            .key_provider()
            .sign(fake_ixn.said.as_bytes())
            .await
            .unwrap();

        // Merge contest + extra event should fail
        let result = kel.merge(vec![
            cnt_event,
            SignedKeyEvent::new(fake_ixn, cnt_key, fake_sig.qb64()),
        ]);

        assert!(
            matches!(
                result,
                Err(KelsError::InvalidKel(ref msg)) if msg.contains("Cannot append events after contest")
            ) || matches!(result, Err(KelsError::ContestedKel(_)))
        );
    }

    // ==================== Overlap Path Tests ====================
    // These tests cover the code paths at lines 292-397 (overlap detection)

    #[tokio::test]
    async fn test_merge_overlap_recovery_succeeds() {
        // Test the overlap recovery path (lines 373-388)
        // The recovery event must be the first divergent event (directly after common ancestor)

        let mut builder1 = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let (icp, icp_sig) = builder1.incept().await.unwrap();
        let icp_key = icp.public_key.clone().unwrap();

        // Save keys for adversary
        let (current_key, next_key, recovery_key) = clone_keys(&builder1);

        // Owner does an ixn at gen 1
        let anchor1 = Digest::blake3_256(b"owner_anchor").qb64();
        let (ixn1, ixn1_sig) = builder1.interact(&anchor1).await.unwrap();

        // Create KEL with icp + owner ixn (NOT divergent yet)
        let mut kel = Kel::from_events(
            vec![
                SignedKeyEvent::new(icp.clone(), icp_key.clone(), icp_sig.qb64()),
                SignedKeyEvent::new(ixn1.clone(), icp_key.clone(), ixn1_sig.qb64()),
            ],
            true,
        )
        .unwrap();

        assert!(kel.find_divergence().is_none());

        // Create adversary from inception state
        let mut adversary_kel = Kel::new();
        adversary_kel.push(SignedKeyEvent::new(
            icp.clone(),
            icp_key.clone(),
            icp_sig.qb64(),
        ));

        let mut builder2 = KeyEventBuilder::with_kel(
            SoftwareKeyProvider::with_all_keys(current_key, next_key, recovery_key),
            None,
            None,
            adversary_kel,
        )
        .unwrap();

        // Adversary creates recovery event directly from icp (at gen 1)
        // This makes the recovery event the first divergent event
        let (_, _) = builder2.recover(false).await.unwrap();
        let rec_event = builder2.events().last().unwrap().clone();

        // Merge recovery event that creates divergence at gen 1
        // Owner has ixn1 at gen 1, adversary has rec at gen 1
        let result = kel.merge(vec![rec_event]);

        assert!(result.is_ok());
        let (archived, added, merge_result) = result.unwrap();
        assert_eq!(merge_result, KelMergeResult::Recovered);
        // Owner's ixn should be archived
        assert_eq!(archived.len(), 1);
        assert_eq!(archived[0].event.said, ixn1.said);
        // Recovery event should be added
        assert_eq!(added.len(), 1);
        assert!(added[0].event.is_recover());
    }

    #[tokio::test]
    async fn test_merge_events_not_contiguous_fails() {
        // Test line 400: Events not contiguous (gap in chain)
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let (icp, icp_sig) = builder.incept().await.unwrap();
        let icp_key = icp.public_key.clone().unwrap();

        let mut kel = Kel::from_events(
            vec![SignedKeyEvent::new(
                icp.clone(),
                icp_key.clone(),
                icp_sig.qb64(),
            )],
            true,
        )
        .unwrap();

        // Create a separate builder and make events that don't chain from our KEL
        let mut builder2 = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        builder2.incept().await.unwrap();
        let anchor = Digest::blake3_256(b"other").qb64();
        let (other_ixn, other_ixn_sig) = builder2.interact(&anchor).await.unwrap();

        // This ixn chains from a different icp, so it's not contiguous
        let result = kel.merge(vec![SignedKeyEvent::new(
            other_ixn.clone(),
            builder2.current_public_key().await.unwrap().qb64(),
            other_ixn_sig.qb64(),
        )]);

        assert!(matches!(
            result,
            Err(KelsError::InvalidKel(ref msg)) if msg.contains("not contiguous")
        ));
    }
}
