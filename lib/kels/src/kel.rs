//! Key Event Log (KEL) - cryptographically linked chain of key events

use crate::error::KelsError;
use crate::types::{KelMergeResult, KeyEvent, SignedKeyEvent};
use cesr::{Digest, Matter, PublicKey, Signature};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ops::{Deref, DerefMut};
use verifiable_storage::{StorageDatetime, Versioned};

pub fn compute_rotation_hash(public_key: &str) -> String {
    let digest = Digest::blake3_256(public_key.as_bytes());
    digest.qb64()
}

#[derive(Debug, Clone)]
pub struct DivergenceInfo {
    pub diverged_at_version: u64,
    pub divergent_saids: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Kel(Vec<SignedKeyEvent>);

impl Kel {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Only use `skip_verify: true` for trusted sources (e.g., database reads).
    pub fn from_events(events: Vec<SignedKeyEvent>, skip_verify: bool) -> Result<Self, KelsError> {
        let kel = Self(events);
        if !skip_verify && !kel.is_empty() {
            kel.verify()?;
        }
        Ok(kel)
    }

    pub fn events(&self) -> &[SignedKeyEvent] {
        &self.0
    }

    pub fn prefix(&self) -> Option<&str> {
        self.0.first().map(|e| e.event.prefix.as_str())
    }

    pub fn is_delegated(&self) -> bool {
        self.0
            .first()
            .map(|e| e.event.is_delegated_inception())
            .unwrap_or(false)
    }

    pub fn delegating_prefix(&self) -> Option<&str> {
        self.0
            .first()
            .and_then(|e| e.event.delegating_prefix.as_deref())
    }

    pub fn inception_time(&self) -> Option<&StorageDatetime> {
        self.0.first().map(|e| &e.event.created_at)
    }

    /// For timestamp-based incremental queries.
    pub fn max_event_timestamp(&self) -> Option<&StorageDatetime> {
        self.0.iter().map(|e| &e.event.created_at).max()
    }

    pub fn last_event(&self) -> Option<&SignedKeyEvent> {
        self.0.last()
    }

    pub fn last_said(&self) -> Option<&str> {
        self.0.last().map(|e| e.event.said.as_str())
    }

    pub fn last_establishment_event(&self) -> Option<&SignedKeyEvent> {
        self.0.iter().rev().find(|e| e.event.is_establishment())
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

    /// A contested KEL has a `cnt` event, meaning both parties used the recovery key.
    pub fn is_contested(&self) -> bool {
        self.0.iter().any(|e| e.event.is_contest())
    }

    pub fn push(&mut self, event: SignedKeyEvent) {
        self.0.push(event);
        self.sort_by_version();
    }

    pub fn extend(&mut self, events: impl IntoIterator<Item = SignedKeyEvent>) {
        self.0.extend(events);
        self.sort_by_version();
    }

    pub fn remove_adversary_events(&mut self, owner_saids: &std::collections::HashSet<String>) -> Result<Vec<SignedKeyEvent>, KelsError> {
        let owner_events = self.iter().filter(|e| owner_saids.contains(&e.event.said)).cloned().collect();
        let adversary_events = self.iter().filter(|e| !owner_saids.contains(&e.event.said)).cloned().collect();
        self.0 = owner_events;
        self.sort_by_version();
        Ok(adversary_events)
    }

    pub fn truncate(&mut self, len: usize) {
        self.0.truncate(len);
    }

    fn sort_by_version(&mut self) {
        self.0.sort_by_key(|e| e.event.version);
    }

    pub fn contains_anchor(&self, anchor: &str) -> bool {
        self.0
            .iter()
            .any(|e| e.event.is_interaction() && e.event.anchor.as_deref() == Some(anchor))
    }

    pub fn contains_anchors(&self, anchors: &[&str]) -> bool {
        anchors.iter().cloned().all(|a| self.contains_anchor(a))
    }

    pub fn find_divergence(&self) -> Option<DivergenceInfo> {
        if self.is_empty() {
            return None;
        }

        // Build a map of version -> SAIDs
        let mut version_saids: std::collections::HashMap<u64, Vec<String>> =
            std::collections::HashMap::new();

        for event in &self.0 {
            version_saids
                .entry(event.event.version)
                .or_default()
                .push(event.event.said.clone());
        }

        // Find the first version with multiple SAIDs
        let divergence_version = version_saids
            .iter()
            .filter(|(_, saids)| saids.len() > 1)
            .map(|(version, _)| *version)
            .min();

        divergence_version.map(|version| DivergenceInfo {
            diverged_at_version: version,
            divergent_saids: version_saids.remove(&version).unwrap_or_default(),
        })
    }

    pub fn get_owner_kel_saids_from_tail(&self, tail_said: &str) -> std::collections::HashSet<String> {
        let mut saids = std::collections::HashSet::new();
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

    pub fn last_valid_version(&self) -> Option<u64> {
        if self.0.is_empty() {
            return None;
        }

        match self.find_divergence() {
            Some(info) if info.diverged_at_version > 0 => Some(info.diverged_at_version - 1),
            Some(_) => None, // Divergence at version 0, no valid version
            None => self.0.last().map(|e| e.event.version),
        }
    }

    /// Generation 0 = inception key, generation N = key after N rotations.
    pub fn key_generation_at_version(&self, version: u64) -> usize {
        self.0
            .iter()
            .filter(|e| e.event.version < version && e.event.is_rotation())
            .count()
    }

    /// Dual-signature events protect against re-divergence at earlier versions.
    pub fn reveals_recovery_at_or_after(&self, version: u64) -> bool {
        self.0
            .iter()
            .any(|e| e.event.version >= version && e.event.reveals_recovery_key())
    }

    pub fn confirmed_cursor(&self) -> Result<usize, KelsError> {
        if let Some(divergence) = self.find_divergence() {
            self.0
                .iter()
                .position(|e| e.event.version == divergence.diverged_at_version)
                .ok_or_else(|| {
                    KelsError::InvalidKel(
                        "Divergence detected but no events at diverged version".to_string(),
                    )
                })
        } else {
            Ok(self.0.len())
        }
    }

    /// Returns `(archived_events, KelMergeResult)`.
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
        if divergence.is_some() && first.event.reveals_recovery_key()
        {
            if first.event.is_contest() {
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
                // Recovery: Keep owner's chain, archive adversary events.
                // Owner's chain is identified by tracing back from rec's previous field.
                let Some(owner_tail_said) = &first.event.previous else {
                    return Err(KelsError::InvalidKel("Recovery event has no previous".into()));
                };

                let owner_kel_saids = self.get_owner_kel_saids_from_tail(owner_tail_said);

                let adversary_events = self.remove_adversary_events(&owner_kel_saids)?;
                self.extend(events.iter().cloned());
                self.verify()?;
                return Ok((adversary_events, events, KelMergeResult::Recovered));
            }
        }

        if first.event.version > usize::MAX as u64 {
            return Err(KelsError::InvalidKel("Version exceeds maximum".to_string()));
        }

        let index = first.event.version as usize;
        let existing_length = self.len();
        let events_length = events.len();

        // Track old events that get removed (for archiving) and the merge result
        let (old_events_removed, new_events_added, result) = if existing_length == index {
            // Normal append - no overlap, no divergence
            // Decommission blocks normal appends (but not divergence detection)
            if self.is_decommissioned() {
                return Err(KelsError::KelDecommissioned);
            }
            self.extend(events.iter().cloned());
            (vec![], events, KelMergeResult::Verified)
        } else if existing_length > index {
            // Overlap - check for matching or divergent events
            let mut i = 0;
            loop {
                let offset = i + index;

                if offset < existing_length {
                    let old_event = &self.0[offset];
                    let new_event = &events[i];

                    if old_event.event.said != new_event.event.said {
                        // Divergence detected at this point
                        let divergent_new_events = &events[i..];
                        let divergent_old_events = self.0[offset..].to_vec();

                        // Check if existing KEL has any recovery-revealing event at or after this version.
                        // Such events require dual signatures and protect this version from re-divergence.
                        // Only contest (cnt) events are allowed through - once anyone reveals recovery,
                        // the only valid response is to contest, not attempt another recovery.
                        if self.reveals_recovery_at_or_after(old_event.event.version)
                            && !new_event.event.is_contest()
                        {
                            return Ok((vec![], vec![], KelMergeResult::RecoveryProtected));
                        }

                        // Check for recovery event in new events
                        let recovery_event = divergent_new_events
                            .iter()
                            .find(|s| s.event.reveals_recovery_key());

                        // Check adversary events for recovery key revelation (true compromise)
                        let old_has_recovery = divergent_old_events
                            .iter()
                            .any(|s| s.event.reveals_recovery_key());

                        if let Some(rec) = recovery_event {
                            if old_has_recovery && rec.event.is_contest() {
                                // Contest: Adversary revealed recovery key, owner contests.
                                // Just append cnt event, don't truncate. KEL stays divergent but frozen.
                                self.extend(divergent_new_events.iter().cloned());
                                break (
                                    vec![],
                                    divergent_new_events.to_vec(),
                                    KelMergeResult::Contested,
                                );
                            } else if old_has_recovery {
                                // FATAL: Adversary revealed recovery key, but owner submitted rec not cnt
                                // Truncate and archive - this shouldn't normally happen
                                break (vec![], vec![], KelMergeResult::Contestable);
                            } else {
                                // Recovery: Owner recovers - truncate and archive adversary events
                                self.truncate(offset);
                                self.extend(divergent_new_events.iter().cloned());
                                break (
                                    divergent_old_events,
                                    divergent_new_events.to_vec(),
                                    KelMergeResult::Recovered,
                                );
                            }
                        } else {
                            // No recovery event - accept divergent event and freeze KEL
                            // Add only the first divergent event (at the conflict version)
                            // Subsequent events in submission are rejected (KEL is frozen)
                            self.push(new_event.clone());

                            // Return the divergent event so handler can store it
                            // and get the diverged_at SAID
                            if old_has_recovery {
                                // Adversary revealed recovery key - user must contest
                                break (
                                    vec![],
                                    vec![new_event.clone()],
                                    KelMergeResult::Contestable,
                                );
                            } else {
                                // Adversary has ixn/rot only - user can recover
                                break (
                                    vec![],
                                    vec![new_event.clone()],
                                    KelMergeResult::Recoverable,
                                );
                            }
                        }
                    }
                } else {
                    // Past the overlap - just append remaining new events
                    self.extend(events[i..].iter().cloned());
                    break (vec![], events[i..].to_vec(), KelMergeResult::Verified);
                }

                i += 1;
                if i >= events_length {
                    // All submitted events matched existing - idempotent
                    break (vec![], vec![], KelMergeResult::Verified);
                }
            }
        } else {
            // Gap in indices - invalid
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
        let events_by_said = self.group_events_by_said();
        let events_by_version = self.group_events_by_version();
        let prefix = self.prefix().ok_or(KelsError::NotIncepted)?;

        // FORWARD PASS: Verify structure (SAID, prefix, chaining) and detect divergence
        let mut valid_tails: std::collections::HashSet<&str> = std::collections::HashSet::new();
        let mut divergence_info: Option<DivergenceInfo> = None;

        for (expected_version, (version, events_at_version)) in events_by_version.iter().enumerate()
        {
            Self::verify_version_continuity(*version, expected_version as u64)?;

            let is_first_divergence = events_at_version.len() > 1 && divergence_info.is_none();
            if is_first_divergence {
                divergence_info = Some(DivergenceInfo {
                    diverged_at_version: *version,
                    divergent_saids: events_at_version
                        .iter()
                        .map(|e| e.event.said.clone())
                        .collect(),
                });
            }

            for signed_event in events_at_version {
                let event = &signed_event.event;
                Self::verify_event_basics(event, prefix, *version)?;
                self.verify_chaining(event, *version, &events_by_version)?;
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

    fn verify_branch_from_tail(
        &self,
        tail_said: &str,
        events_by_said: &std::collections::HashMap<&str, &SignedKeyEvent>,
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
                    self.verify_signatures(pending, pending.event.version, Some(&public_key))?;
                }
                pending_events.clear();

                // Verify this establishment event's signature with its own key
                self.verify_signatures(signed_event, event.version, Some(&public_key))?;

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

    fn group_events_by_said(&self) -> std::collections::HashMap<&str, &SignedKeyEvent> {
        self.0.iter().map(|e| (e.event.said.as_str(), e)).collect()
    }

    fn group_events_by_version(&self) -> std::collections::BTreeMap<u64, Vec<&SignedKeyEvent>> {
        let mut events_by_version = std::collections::BTreeMap::new();
        for event in &self.0 {
            events_by_version
                .entry(event.event.version)
                .or_insert_with(Vec::new)
                .push(event);
        }
        events_by_version
    }

    fn verify_version_continuity(version: u64, expected: u64) -> Result<(), KelsError> {
        if version != expected {
            return Err(KelsError::InvalidKel(format!(
                "Missing version {}, found {}",
                expected, version
            )));
        }
        Ok(())
    }

    fn verify_event_basics(event: &KeyEvent, prefix: &str, version: u64) -> Result<(), KelsError> {
        // Verify SAID is self-consistent
        event.verify().map_err(|e| {
            KelsError::InvalidKel(format!(
                "Event {} at version {} SAID verification failed: {}",
                event.said, version, e
            ))
        })?;

        // Verify prefix matches
        if event.prefix != prefix {
            return Err(KelsError::InvalidKel(format!(
                "Event at version {} has different prefix",
                version
            )));
        }

        Ok(())
    }

    fn verify_chaining(
        &self,
        event: &KeyEvent,
        version: u64,
        events: &BTreeMap<u64, Vec<&SignedKeyEvent>>,
    ) -> Result<(), KelsError> {
        if version == 0 {
            if !event.is_inception() && !event.is_delegated_inception() {
                return Err(KelsError::InvalidKel(
                    "KEL does not start with inception event (icp or dip)".to_string(),
                ));
            }
            if event.previous.is_some() {
                return Err(KelsError::InvalidKel(
                    "Inception event has populated previous field".to_string(),
                ));
            }
            return Ok(());
        }

        let prev = event.previous.as_deref().ok_or_else(|| {
            KelsError::InvalidKel(format!(
                "Event at version {} has no previous field",
                version
            ))
        })?;

        let previous_version = event.version - 1;
        let valid_events = events.get(&previous_version);

        if let Some(events) = valid_events {
            if !events.iter().any(|e| e.event.said == prev) {
                return Err(KelsError::InvalidKel(format!(
                    "Event at version {} chains from unknown previous {}, valid tails: {:?}",
                    version, prev, events,
                )));
            }

            Ok(())
        } else {
            Err(KelsError::InvalidKel(format!(
                "No events for version {}",
                previous_version
            )))
        }
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
        version: u64,
        current_public_key: Option<&PublicKey>,
    ) -> Result<(), KelsError> {
        let event = &signed_event.event;
        let public_key = current_public_key.ok_or_else(|| {
            KelsError::InvalidKel(format!(
                "No public key available to verify event at version {}",
                version
            ))
        })?;

        let expected_qb64 = public_key.qb64();
        let sig = signed_event.signature(&expected_qb64).ok_or_else(|| {
            KelsError::InvalidKel(format!(
                "Event at version {} has no signature for expected key",
                version
            ))
        })?;

        let signature = Signature::from_qb64(&sig.signature)?;
        public_key
            .verify(event.said.as_bytes(), &signature)
            .map_err(|_| {
                KelsError::InvalidKel(format!(
                    "Event at version {} signature verification failed",
                    version
                ))
            })?;

        // Recovery events require dual signatures
        if event.reveals_recovery_key() {
            let recovery_key_qb64 = event.recovery_key.as_ref().ok_or_else(|| {
                KelsError::InvalidKel(format!(
                    "Recovery event at version {} has no recovery_key field",
                    version
                ))
            })?;

            let recovery_sig = signed_event.signature(recovery_key_qb64).ok_or_else(|| {
                KelsError::InvalidKel(format!(
                    "Recovery event at version {} has no signature for recovery key",
                    version
                ))
            })?;

            let recovery_public_key = PublicKey::from_qb64(recovery_key_qb64)?;
            let recovery_signature = Signature::from_qb64(&recovery_sig.signature)?;
            recovery_public_key
                .verify(event.said.as_bytes(), &recovery_signature)
                .map_err(|_| {
                    KelsError::InvalidKel(format!(
                        "Recovery event at version {} recovery signature verification failed",
                        version
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
    use crate::crypto::SoftwareKeyProvider;
    use verifiable_storage::SelfAddressed;

    #[tokio::test]
    async fn test_incept() {
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);

        let (event, signature) = builder.incept().await.unwrap();

        assert!(event.is_inception());
        assert!(!event.said.is_empty());
        assert_eq!(event.said, event.prefix);
        assert_eq!(event.version, 0);
        assert!(event.previous.is_none());
        assert!(event.public_key.is_some());
        assert!(event.rotation_hash.is_some());

        let public_key = builder.current_public_key().await.unwrap();
        assert!(public_key.verify(event.said.as_bytes(), &signature).is_ok());

        assert_eq!(builder.prefix(), Some(event.prefix.as_str()));
        assert_eq!(builder.version(), 0);
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
        assert_eq!(ixn_event.version, 1);
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
        assert_eq!(rot_event.version, 1);
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

        let software = builder1.key_provider();
        let current_key = software.current_private_key().unwrap().clone();
        let next_key = software.next_private_key().unwrap().clone();
        let recovery_key = software.recovery_private_key().unwrap().clone();

        let mut kel = Kel::new();
        kel.push(SignedKeyEvent::new(
            icp_event.clone(),
            public_key,
            icp_sig.qb64(),
        ));
        let mut builder2 = KeyEventBuilder::with_kel(
            SoftwareKeyProvider::with_all_keys(
                Some(current_key),
                Some(next_key),
                Some(recovery_key),
            ),
            None,
            None,
            kel.clone(),
        )
        .unwrap();

        let (ixn_event, _) = builder2.interact("anchor").await.unwrap();
        assert_eq!(ixn_event.prefix, icp_event.prefix);
        assert_eq!(ixn_event.previous, Some(icp_event.said));
        assert_eq!(ixn_event.version, 1);
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

        let software = builder.key_provider();
        let current_key = software.current_private_key().unwrap().clone();
        let next_key = software.next_private_key().unwrap().clone();
        let recovery_key = software.recovery_private_key().unwrap().clone();
        let mut builder2 = KeyEventBuilder::with_kel(
            SoftwareKeyProvider::with_all_keys(
                Some(current_key),
                Some(next_key),
                Some(recovery_key),
            ),
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
        assert_eq!(rot_event.version, 3);
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
        let (ixn1, ixn1_sig) = builder1.interact("anchor1").await.unwrap();

        // Create a second builder from the same icp to make a divergent event
        let software = builder1.key_provider();
        let current_key = software.current_private_key().unwrap().clone();
        let next_key = software.next_private_key().unwrap().clone();
        let recovery_key = software.recovery_private_key().unwrap().clone();

        let icp_public_key = icp_event.public_key.clone().unwrap();
        let mut kel_for_builder2 = Kel::new();
        kel_for_builder2.push(SignedKeyEvent::new(
            icp_event.clone(),
            icp_public_key.clone(),
            icp_sig.qb64(),
        ));

        let mut builder2 = KeyEventBuilder::with_kel(
            SoftwareKeyProvider::with_all_keys(
                Some(current_key),
                Some(next_key),
                Some(recovery_key),
            ),
            None,
            None,
            kel_for_builder2.clone(),
        )
        .unwrap();
        let (ixn2, ixn2_sig) = builder2.interact("anchor2").await.unwrap();

        // Both ixn1 and ixn2 are at version 1, chaining from icp
        assert_eq!(ixn1.version, 1);
        assert_eq!(ixn2.version, 1);
        assert_ne!(ixn1.said, ixn2.said);

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
        assert_eq!(info.diverged_at_version, 1);
        assert_eq!(info.divergent_saids.len(), 2);
        assert!(info.divergent_saids.contains(&ixn1.said));
        assert!(info.divergent_saids.contains(&ixn2.said));
    }

    #[tokio::test]
    async fn test_find_divergence_three_way() {
        // KEL with 3 events at same version (3-way divergence from race condition)
        let mut builder1 = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let (icp_event, icp_sig) = builder1.incept().await.unwrap();
        let (ixn1, ixn1_sig) = builder1.interact("anchor1").await.unwrap();

        let software = builder1.key_provider();
        let current_key = software.current_private_key().unwrap().clone();
        let next_key = software.next_private_key().unwrap().clone();
        let recovery_key = software.recovery_private_key().unwrap().clone();

        let icp_public_key = icp_event.public_key.clone().unwrap();
        let mut kel_for_builder2 = Kel::new();
        kel_for_builder2.push(SignedKeyEvent::new(
            icp_event.clone(),
            icp_public_key.clone(),
            icp_sig.qb64(),
        ));

        // Create second divergent event
        let mut builder2 = KeyEventBuilder::with_kel(
            SoftwareKeyProvider::with_all_keys(
                Some(current_key.clone()),
                Some(next_key.clone()),
                Some(recovery_key.clone()),
            ),
            None,
            None,
            kel_for_builder2.clone(),
        )
        .unwrap();
        let (ixn2, ixn2_sig) = builder2.interact("anchor2").await.unwrap();

        // Create third divergent event
        let mut builder3 = KeyEventBuilder::with_kel(
            SoftwareKeyProvider::with_all_keys(
                Some(current_key),
                Some(next_key),
                Some(recovery_key),
            ),
            None,
            None,
            kel_for_builder2.clone(),
        )
        .unwrap();
        let (ixn3, ixn3_sig) = builder3.interact("anchor3").await.unwrap();

        // All three ixn events are at version 1
        assert_eq!(ixn1.version, 1);
        assert_eq!(ixn2.version, 1);
        assert_eq!(ixn3.version, 1);
        assert_ne!(ixn1.said, ixn2.said);
        assert_ne!(ixn2.said, ixn3.said);
        assert_ne!(ixn1.said, ixn3.said);

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
        assert_eq!(info.diverged_at_version, 1);
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

        let software = builder1.key_provider();
        let current_key = software.current_private_key().unwrap().clone();
        let next_key = software.next_private_key().unwrap().clone();
        let recovery_key = software.recovery_private_key().unwrap().clone();

        let icp_public_key = icp_event.public_key.clone().unwrap();
        let mut kel_for_builder2 = Kel::new();
        kel_for_builder2.push(SignedKeyEvent::new(
            icp_event.clone(),
            icp_public_key.clone(),
            icp_sig.qb64(),
        ));

        let mut builder2 = KeyEventBuilder::with_kel(
            SoftwareKeyProvider::with_all_keys(
                Some(current_key.clone()),
                Some(next_key.clone()),
                Some(recovery_key.clone()),
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
            true,
        )
        .unwrap();

        // Verify it's divergent
        assert!(divergent_kel.find_divergence().is_some());

        // Load with with_kel
        let builder3 = KeyEventBuilder::with_kel(
            SoftwareKeyProvider::with_all_keys(
                Some(current_key),
                Some(next_key),
                Some(recovery_key),
            ),
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

        let software = builder1.key_provider();
        let current_key = software.current_private_key().unwrap().clone();
        let next_key = software.next_private_key().unwrap().clone();
        let recovery_key = software.recovery_private_key().unwrap().clone();

        let icp_public_key = icp_event.public_key.clone().unwrap();
        let mut kel_for_others = Kel::new();
        kel_for_others.push(SignedKeyEvent::new(
            icp_event.clone(),
            icp_public_key.clone(),
            icp_sig.qb64(),
        ));

        let mut builder2 = KeyEventBuilder::with_kel(
            SoftwareKeyProvider::with_all_keys(
                Some(current_key.clone()),
                Some(next_key.clone()),
                Some(recovery_key.clone()),
            ),
            None,
            None,
            kel_for_others.clone(),
        )
        .unwrap();
        let (ixn2, ixn2_sig) = builder2.interact("anchor2").await.unwrap();

        let mut builder3 = KeyEventBuilder::with_kel(
            SoftwareKeyProvider::with_all_keys(
                Some(current_key.clone()),
                Some(next_key.clone()),
                Some(recovery_key.clone()),
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
            true,
        )
        .unwrap();

        // Verify 3-way divergence
        let info = divergent_kel.find_divergence().unwrap();
        assert_eq!(info.divergent_saids.len(), 3);

        // Load with with_kel
        let loaded_builder = KeyEventBuilder::with_kel(
            SoftwareKeyProvider::with_all_keys(
                Some(current_key),
                Some(next_key),
                Some(recovery_key),
            ),
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
        let software = owner.key_provider();
        let current_key = software.current_private_key().unwrap().clone();
        let next_key = software.next_private_key().unwrap().clone();
        let recovery_key = software.recovery_private_key().unwrap().clone();
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
                Some(current_key.clone()),
                Some(next_key.clone()),
                Some(recovery_key.clone()),
            ),
            None,
            None,
            adversary_kel.clone(),
        )
        .unwrap();
        let (adversary_rot, adversary_rot_sig) = adversary.rotate().await.unwrap();

        // Both events are at version 1
        assert_eq!(owner_ixn.version, 1);
        assert_eq!(adversary_rot.version, 1);
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
        assert_eq!(divergence.diverged_at_version, 1);

        // Owner's local events (what they know about)
        let owner_events = owner.kel();
        let owner_saids: std::collections::HashSet<_> =
            owner_events.iter().map(|e| &e.event.said).collect();

        // Check: adversary_rot should NOT be in owner's SAIDs (it's adversary's event)
        assert!(!owner_saids.contains(&adversary_rot.said));

        // Check: owner_ixn SHOULD be in owner's SAIDs
        assert!(owner_saids.contains(&owner_ixn.said));

        // Simulate the adversary rotation detection logic from recover_from_divergence
        let adversary_rotated = server_kel.events().iter().any(|e| {
            e.event.version >= divergence.diverged_at_version
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
        let software = owner.key_provider();
        let pre_rot_current = software.current_private_key().unwrap().clone(); // inception key
        let pre_rot_next = software.next_private_key().unwrap().clone(); // first rotation key
        let pre_rot_recovery = software.recovery_private_key().unwrap().clone();

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
            SoftwareKeyProvider::with_all_keys(
                Some(pre_rot_current),
                Some(pre_rot_next),
                Some(pre_rot_recovery),
            ),
            None,
            None,
            adversary_kel.clone(),
        )
        .unwrap();
        let (adversary_ixn, adversary_ixn_sig) =
            adversary.interact("adversary-anchor").await.unwrap();

        // Both events at version 1
        assert_eq!(owner_rot.version, 1);
        assert_eq!(adversary_ixn.version, 1);
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
            true,
        )
        .unwrap();

        let divergence = server_kel.find_divergence().unwrap();
        assert_eq!(divergence.diverged_at_version, 1);

        // Owner's local events
        let owner_events = owner.kel();
        let owner_saids: std::collections::HashSet<_> =
            owner_events.iter().map(|e| &e.event.said).collect();

        // Owner's rot IS in owner's SAIDs
        assert!(owner_saids.contains(&owner_rot.said));

        // Simulate adversary rotation detection
        let adversary_rotated = server_kel.events().iter().any(|e| {
            e.event.version >= divergence.diverged_at_version
                && e.event.is_rotation()
                && !owner_saids.contains(&e.event.said)
        });

        // Should NOT detect adversary rotation (it was owner who rotated)
        assert!(
            !adversary_rotated,
            "Should NOT detect owner rotation as adversary rotation"
        );
    }
}
