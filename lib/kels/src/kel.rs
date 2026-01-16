//! Key Event Log (KEL) Builder
//!
//! This module provides builders for creating key events using pluggable
//! `KeyProvider` implementations. The same API works with software keys,
//! HSM keys, or mobile hardware keys.
//!
//! # Key Event Kinds
//!
//! Defined in `src/types.rs` as `EventKind`.

use async_trait::async_trait;

use crate::client::KelsClient;
use crate::crypto::KeyProvider;
use crate::error::KelsError;
use crate::types::{KelMergeResult, KeyEvent, RecoveryOutcome, SignedKeyEvent};
use cesr::{Digest, Matter, PublicKey, Signature};
use serde::{Deserialize, Serialize};
use std::ops::{Deref, DerefMut};
use verifiable_storage::{StorageDatetime, Versioned};

/// Computes the rotation hash (pre-rotation commitment) for a public key.
///
/// The rotation hash is a Blake3 digest of the public key's raw bytes,
/// encoded in CESR qb64 format.
pub fn compute_rotation_hash(public_key: &PublicKey) -> String {
    let digest = Digest::blake3_256(public_key.raw());
    digest.qb64()
}

/// Result of divergence detection during verification.
///
/// A KEL is divergent when multiple events exist at the same version,
/// indicating an adversary has submitted conflicting events.
#[derive(Debug, Clone)]
pub struct DivergenceInfo {
    /// The version at which divergence was detected
    pub diverged_at_version: u64,
    /// SAIDs of all events at the divergent version
    pub divergent_saids: Vec<String>,
}

/// State extracted from a KEL for building new events.
///
/// Handles both normal and divergent KELs by computing the correct
/// last event, last establishment event, and confirmed cursor.
#[derive(Debug, Clone)]
pub struct KelBuilderState {
    /// The last event to chain from (last non-divergent event if divergent)
    pub last_trusted_event: Option<KeyEvent>,
    /// The last establishment event (last non-divergent if divergent)
    pub last_trusted_establishment_event: Option<KeyEvent>,
    /// Index of first unconfirmed/divergent event (equals len if no divergence)
    pub trusted_cursor: usize,
}

impl KelBuilderState {
    /// Update state after adding an establishment event (rot/ror/dec/rec/cnt).
    /// Does NOT update confirmed_cursor - caller should do that after flush succeeds.
    pub fn update_establishment(&mut self, event: &KeyEvent) {
        self.last_trusted_event = Some(event.clone());
        self.last_trusted_establishment_event = Some(event.clone());
    }

    /// Update state after adding a non-establishment event (ixn).
    /// Does NOT update confirmed_cursor - caller should do that after flush succeeds.
    pub fn update_non_establishment(&mut self, event: &KeyEvent) {
        self.last_trusted_event = Some(event.clone());
    }

    /// Mark events as confirmed up to the given cursor position.
    pub fn confirm(&mut self, cursor: usize) {
        self.trusted_cursor = cursor;
    }

    /// Compute builder state from a slice of events.
    ///
    /// Handles divergence detection: if multiple events share the same version,
    /// returns state pointing to the last non-divergent position.
    pub fn from_events(events: &[SignedKeyEvent]) -> Self {
        // Check for divergence (multiple events at same version)
        let divergence_version = Self::find_divergence_version(events);

        if let Some(div_ver) = divergence_version {
            let last_event = events
                .iter()
                .filter(|e| e.event.version < div_ver)
                .next_back()
                .map(|s| s.event.clone());

            let last_establishment_event = events
                .iter()
                .filter(|e| e.event.version < div_ver && e.event.is_establishment())
                .next_back()
                .map(|s| s.event.clone());

            let confirmed_cursor = events
                .iter()
                .position(|e| e.event.version >= div_ver)
                .unwrap_or(events.len());

            Self {
                last_trusted_event: last_event,
                last_trusted_establishment_event: last_establishment_event,
                trusted_cursor: confirmed_cursor,
            }
        } else {
            Self {
                last_trusted_event: events.last().map(|s| s.event.clone()),
                last_trusted_establishment_event: events
                    .iter()
                    .rev()
                    .find(|e| e.event.is_establishment())
                    .map(|s| s.event.clone()),
                trusted_cursor: events.len(),
            }
        }
    }

    /// Find the version where divergence occurs (multiple events at same version).
    fn find_divergence_version(events: &[SignedKeyEvent]) -> Option<u64> {
        let mut seen_versions = std::collections::HashSet::new();
        for event in events {
            if !seen_versions.insert(event.event.version) {
                return Some(event.event.version);
            }
        }
        None
    }
}

/// A Key Event Log (KEL) - a cryptographically linked chain of key events.
///
/// The KEL is the authoritative record of an identity's key state. It contains:
/// - An inception event (first event, establishes the prefix/identifier)
/// - Zero or more rotation events (key changes with pre-rotation commitment)
/// - Zero or more interaction events (anchoring external data)
///
/// # Example
///
/// ```
/// use kels::Kel;
///
/// // Create empty KEL
/// let kel = Kel::new();
/// assert!(kel.is_empty());
///
/// // KELs are serializable
/// let json = serde_json::to_string(&kel).unwrap();
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Kel(Vec<SignedKeyEvent>);

impl Kel {
    /// Create a new empty KEL.
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Create a KEL from a vector of signed events.
    ///
    /// Verifies the KEL structure and signatures unless `skip_verify` is true.
    /// Only use `skip_verify: true` for trusted sources (e.g., database reads
    /// where events were already verified on storage).
    pub fn from_events(events: Vec<SignedKeyEvent>, skip_verify: bool) -> Result<Self, KelsError> {
        let kel = Self(events);
        if !skip_verify && !kel.is_empty() {
            kel.verify()?;
        }
        Ok(kel)
    }

    /// Get a reference to the underlying events.
    pub fn events(&self) -> &[SignedKeyEvent] {
        &self.0
    }

    /// Get the KEL prefix (from the inception event).
    ///
    /// Returns `None` if the KEL is empty.
    pub fn prefix(&self) -> Option<&str> {
        self.0.first().map(|e| e.event.prefix.as_str())
    }

    /// Check if this is a delegated KEL (first event is `dip`).
    pub fn is_delegated(&self) -> bool {
        self.0
            .first()
            .map(|e| e.event.is_delegated_inception())
            .unwrap_or(false)
    }

    /// Get the delegating prefix (for delegated KELs).
    ///
    /// Returns `None` if not a delegated KEL or if empty.
    pub fn delegating_prefix(&self) -> Option<&str> {
        self.0
            .first()
            .and_then(|e| e.event.delegating_prefix.as_deref())
    }

    /// Get the inception event's created_at time (for time-bounding delegated KELs).
    pub fn inception_time(&self) -> Option<&StorageDatetime> {
        self.0.first().map(|e| &e.event.created_at)
    }

    /// Get the maximum (most recent) timestamp from all events in the KEL.
    ///
    /// Used for timestamp-based incremental queries to fetch events newer than
    /// the latest event in the cache.
    pub fn max_event_timestamp(&self) -> Option<&StorageDatetime> {
        self.0.iter().map(|e| &e.event.created_at).max()
    }

    /// Get the last event in the KEL.
    pub fn last_event(&self) -> Option<&SignedKeyEvent> {
        self.0.last()
    }

    /// Get the SAID of the last event.
    pub fn last_said(&self) -> Option<&str> {
        self.0.last().map(|e| e.event.said.as_str())
    }

    /// Get the last establishment event (inception or rotation).
    pub fn last_establishment_event(&self) -> Option<&SignedKeyEvent> {
        self.0.iter().rev().find(|e| e.event.is_establishment())
    }

    /// Check if this KEL is decommissioned.
    ///
    /// A KEL is decommissioned if its last establishment event (rotation) has
    /// no rotation_hash, signaling that no further events can be added.
    ///
    /// Returns `false` for empty KELs (they can receive events).
    pub fn is_decommissioned(&self) -> bool {
        self.last()
            .map(|e| e.event.decommissions())
            .unwrap_or(false)
    }

    /// Get the current public key (from the last establishment event).
    ///
    /// Returns an error if the KEL is empty or decommissioned.
    pub fn current_public_key(&self) -> Result<PublicKey, KelsError> {
        if self.is_decommissioned() {
            return Err(KelsError::InvalidKel("KEL is decommissioned".to_string()));
        }

        let event = self
            .last_establishment_event()
            .ok_or_else(|| KelsError::InvalidKel("KEL has no establishment event".to_string()))?;

        let qb64 = event.event.public_key.as_ref().ok_or_else(|| {
            KelsError::InvalidKel("Establishment event has no public key".to_string())
        })?;

        PublicKey::from_qb64(qb64).map_err(KelsError::from)
    }

    /// Verify a signature against the current public key.
    ///
    /// This verifies that `signature` is a valid signature of `data` using
    /// the current key from the most recent establishment event.
    ///
    /// Returns an error if the KEL is decommissioned or the signature is invalid.
    pub fn verify_signature(&self, data: &[u8], signature: &Signature) -> Result<(), KelsError> {
        let public_key = self.current_public_key()?;

        public_key
            .verify(data, signature)
            .map_err(|_| KelsError::SignatureVerificationFailed)
    }

    /// Append a signed event to the KEL.
    pub fn push(&mut self, event: SignedKeyEvent) {
        self.0.push(event);
    }

    /// Check if the KEL contains an anchor for the given SAID.
    pub fn contains_anchor(&self, anchor: &str) -> bool {
        self.0
            .iter()
            .any(|e| e.event.is_interaction() && e.event.anchor.as_deref() == Some(anchor))
    }

    pub fn contains_anchors(&self, anchors: &[&str]) -> bool {
        anchors.iter().cloned().all(|a| self.contains_anchor(a))
    }

    /// Consume self and return the inner Vec.
    pub fn into_inner(self) -> Vec<SignedKeyEvent> {
        self.0
    }

    /// Check if this KEL is divergent (multiple events at the same version).
    ///
    /// Returns `Some(DivergenceInfo)` if divergence is detected, `None` otherwise.
    /// A divergent KEL cannot be trusted and requires recovery.
    pub fn find_divergence(&self) -> Option<DivergenceInfo> {
        if self.0.is_empty() {
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

    /// Get the last valid version before any divergence.
    ///
    /// If the KEL is not divergent, returns the version of the last event.
    /// If divergent, returns the version just before the divergence point.
    /// Returns `None` if the KEL is empty.
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

    /// Check if the KEL has any event that reveals the recovery key at or after the given version.
    ///
    /// Events that reveal recovery keys (rec/ror/dec/cnt) require dual signatures and
    /// prove ownership of both signing and recovery keys. Once such an event exists,
    /// single-signature events cannot supersede the dual-signature proof.
    pub fn reveals_recovery_at_or_after(&self, version: u64) -> bool {
        self.0
            .iter()
            .any(|e| e.event.version >= version && e.event.reveals_recovery_key())
    }

    /// Extract builder state from this KEL, handling divergence correctly.
    ///
    /// For normal KELs: returns the last event, last establishment event, and full length as cursor.
    /// For divergent KELs: returns the last non-divergent event/establishment and divergence index.
    ///
    /// This method consolidates the logic for computing state that `KeyEventBuilder` needs,
    /// whether loading from storage or updating after divergence detection.
    pub fn builder_state(&self) -> KelBuilderState {
        if let Some(divergence) = self.find_divergence() {
            let divergence_version = divergence.diverged_at_version;

            let last_event = self
                .0
                .iter()
                .filter(|e| e.event.version < divergence_version)
                .next_back()
                .map(|s| s.event.clone());

            let last_establishment_event = self
                .0
                .iter()
                .filter(|e| e.event.version < divergence_version && e.event.is_establishment())
                .next_back()
                .map(|s| s.event.clone());

            let confirmed_cursor = self
                .0
                .iter()
                .position(|e| e.event.version >= divergence_version)
                .unwrap_or(self.0.len());

            KelBuilderState {
                last_trusted_event: last_event,
                last_trusted_establishment_event: last_establishment_event,
                trusted_cursor: confirmed_cursor,
            }
        } else {
            KelBuilderState {
                last_trusted_event: self.last_event().map(|s| s.event.clone()),
                last_trusted_establishment_event: self.last_establishment_event().map(|s| s.event.clone()),
                trusted_cursor: self.0.len(),
            }
        }
    }

    /// Merge submitted events into this KEL.
    ///
    /// Returns `(diverged_at, accepted)` compatible with `BatchSubmitResponse`:
    /// - `(None, true)` = success, all events accepted
    /// - `(Some(said), true)` = divergence detected and recovered
    /// - `(Some(said), false)` = divergence, not recovered (contested or needs rec event)
    /// - `(None, false)` = validation error
    ///
    /// # Divergence Recovery Algorithm
    ///
    /// Given existing events [0..n] and new events [m..m+c] where m <= n:
    /// 1. Find minimal position y where SAIDs differ (first divergence point)
    /// 2. Check: adversary did NOT reveal recovery key (no rec/ror in existing[y..n])
    /// 3. Check: owner has recovery event in new[y..m+c] (proves recovery key ownership)
    /// 4. If both conditions met: truncate existing at y, append new[y..m+c], verify
    /// 5. If BOTH have revealed recovery keys → contested KEL (unrecoverable)
    ///
    /// # Arguments
    ///
    /// * `events` - Events to merge (may overlap with existing events)
    ///
    /// # Returns
    ///
    ///
    /// Merge submitted events into this KEL.
    ///
    /// Returns a tuple of (old_events_removed, result):
    /// - `old_events_removed`: Events that were removed from the existing KEL (for archiving)
    /// - `result`: The merge result (Verified, Contested, Recoverable, Unrecoverable)
    ///
    /// For normal appends (no divergence), `old_events_removed` is empty.
    /// For divergence recovery, `old_events_removed` contains the adversary's events that were replaced.
    pub fn merge(
        &mut self,
        events: Vec<SignedKeyEvent>,
    ) -> Result<(Vec<SignedKeyEvent>, KelMergeResult), KelsError> {
        if events.is_empty() {
            return Err(KelsError::InvalidKel("No events to add".to_string()));
        }

        // Decommission is final - no further events allowed
        if self.is_decommissioned() {
            return Err(KelsError::KelDecommissioned);
        }

        let first = &events[0];

        // Check if KEL is already divergent (frozen)
        // Only recovery-revealing events (rec/ror/dec/cnt) can unfreeze
        if self.find_divergence().is_some() && !first.event.reveals_recovery_key() {
            return Ok((vec![], KelMergeResult::Frozen));
        }

        if first.event.version > usize::MAX as u64 {
            return Err(KelsError::InvalidKel(
                "This is one huge KEL. One may even say: That's a hell of a KEL.".to_string(),
            ));
        }

        let index = first.event.version as usize;
        let existing_length = self.len();
        let events_length = events.len();

        // Track old events that get removed (for archiving) and the merge result
        let (old_events_removed, result) = if existing_length == index {
            // Normal append - no overlap, no divergence
            self.0.extend(events.iter().cloned());
            (vec![], KelMergeResult::Verified)
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

                        // Check if new event reveals recovery key (rec/ror/dec/cnt)
                        let new_reveals_recovery = new_event.event.reveals_recovery_key();

                        // Check if existing KEL has any recovery-revealing event at or after divergence.
                        // Such events require dual signatures and cannot be superseded by single-sig events.
                        if self.reveals_recovery_at_or_after(old_event.event.version)
                            && !new_reveals_recovery
                        {
                            return Ok((vec![], KelMergeResult::RecoveryProtected));
                        }

                        // Check for recovery event in new events
                        let recovery_event = divergent_new_events
                            .iter()
                            .find(|s| s.event.reveals_recovery_key());

                        // Check adversary events for recovery key revelation (true compromise)
                        let old_has_recovery = divergent_old_events
                            .iter()
                            .any(|s| s.event.reveals_recovery_key());

                        if let Some(_rec) = recovery_event {
                            if old_has_recovery {
                                // FATAL: Adversary revealed recovery key - true key compromise
                                // Both parties have recovery keys = contested, KEL is dead
                                self.0.truncate(offset);
                                self.0.extend(divergent_new_events.iter().cloned());
                                break (divergent_old_events, KelMergeResult::Contested);
                            }

                            // Adversary did NOT reveal recovery key - owner can recover
                            // This works whether adversary has ixn only OR rot (without rec/ror)
                            // The dual-signature on rec proves recovery key ownership
                            self.0.truncate(offset);
                            self.0.extend(divergent_new_events.iter().cloned());
                            break (divergent_old_events, KelMergeResult::Recovered);
                        } else {
                            // No recovery event - accept divergent event and freeze KEL
                            // Add only the first divergent event (at the conflict version)
                            // Subsequent events in submission are rejected (KEL is frozen)
                            self.0.push(new_event.clone());

                            // Return the divergent event so handler can store it
                            // and get the diverged_at SAID
                            if old_has_recovery {
                                // Adversary revealed recovery key - user must contest
                                break (vec![new_event.clone()], KelMergeResult::Contestable);
                            } else {
                                // Adversary has ixn/rot only - user can recover
                                break (vec![new_event.clone()], KelMergeResult::Recoverable);
                            }
                        }
                    }
                } else {
                    // Past the overlap - just append remaining new events
                    self.0.extend(events[i..].iter().cloned());
                    break (vec![], KelMergeResult::Verified);
                }

                i += 1;
                if i >= events_length {
                    // All submitted events matched existing - idempotent
                    break (vec![], KelMergeResult::Verified);
                }
            }
        } else {
            // Gap in indices - invalid
            return Err(KelsError::InvalidKel("Events not contiguous".to_string()));
        };

        self.verify()?;

        Ok((old_events_removed, result))
    }

    /// Verify the structural integrity and signatures of this KEL.
    ///
    /// This method checks:
    /// 1. The KEL is non-empty
    /// 2. The first event is an inception event (icp or dip)
    /// 3. Each event's `previous` field references the prior event's SAID
    /// 4. Each event's SAID matches its content (self-addressing verification)
    /// 5. All events share the same prefix
    /// 6. Pre-rotation commitments are honored
    /// 7. Signatures are valid
    ///
    /// # Divergent KELs
    ///
    /// If the KEL contains divergent events (multiple events at the same version),
    /// verification proceeds as follows:
    /// 1. The non-divergent prefix is verified normally
    /// 2. Each divergent event is verified against the key state from the common prefix
    /// 3. Only events that are properly signed and chained are considered valid divergence
    /// 4. Returns `Ok(Some(DivergenceInfo))` if valid divergence is detected
    /// 5. Invalid divergent events (bad signature, bad chain) are ignored
    ///
    /// # Note
    ///
    /// For delegated KELs, this method does NOT verify that the delegation is
    /// anchored in the delegating KEL. The caller should verify that separately
    /// by fetching the delegating KEL and checking for the anchor.
    pub fn verify(&self) -> Result<Option<DivergenceInfo>, KelsError> {
        if self.0.is_empty() {
            return Err(KelsError::InvalidKel("KEL is empty".to_string()));
        }

        // Group events by version using BTreeMap (sorted)
        let mut events_by_version: std::collections::BTreeMap<u64, Vec<&SignedKeyEvent>> =
            std::collections::BTreeMap::new();
        for event in &self.0 {
            events_by_version
                .entry(event.event.version)
                .or_default()
                .push(event);
        }

        // Get prefix from first event (version 0 must exist, we checked non-empty)
        let first_events = events_by_version
            .get(&0)
            .ok_or_else(|| KelsError::InvalidKel("KEL has no event at version 0".to_string()))?;
        let prefix = &first_events[0].event.prefix;

        // Track valid tails (SAIDs we can chain from) - supports multiple branches after divergence
        let mut valid_tails: std::collections::HashSet<&str> = std::collections::HashSet::new();

        // Verification state for non-divergent prefix
        let mut last_rotation_hash: Option<&str> = None;
        let mut last_recovery_hash: Option<&str> = None;
        let mut current_public_key: Option<PublicKey> = None;
        let mut is_decommissioned = false;
        let mut divergence_info: Option<DivergenceInfo> = None;

        // Process version by version
        for (expected_version, (version, events_at_version)) in events_by_version.iter().enumerate()
        {
            let expected_version = expected_version as u64;
            // Check version continuity
            if *version != expected_version {
                return Err(KelsError::InvalidKel(format!(
                    "Missing version {}, found {}",
                    expected_version, version
                )));
            }

            let mut next_tails: std::collections::HashSet<&str> = std::collections::HashSet::new();
            let is_divergent = events_at_version.len() > 1;

            // Record first divergence point
            if is_divergent && divergence_info.is_none() {
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

                // Verify SAID is self-consistent
                event.verify().map_err(|e| {
                    KelsError::InvalidKel(format!(
                        "Event {} at version {} SAID verification failed: {}",
                        event.said, version, e
                    ))
                })?;

                // Verify prefix matches
                if &event.prefix != prefix {
                    return Err(KelsError::InvalidKel(format!(
                        "Event at version {} has different prefix",
                        version
                    )));
                }

                // Verify chaining
                if *version == 0 {
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
                } else {
                    // Must chain from one of the valid tails
                    let prev = event.previous.as_deref().ok_or_else(|| {
                        KelsError::InvalidKel(format!(
                            "Event at version {} has no previous field",
                            version
                        ))
                    })?;
                    if !valid_tails.contains(prev) {
                        return Err(KelsError::InvalidKel(format!(
                            "Event at version {} chains from unknown previous {}, valid tails: {:?}",
                            version, prev, valid_tails
                        )));
                    }
                }

                // Only do full verification (signatures, key state) for non-divergent prefix
                // Post-divergence, we can't verify signatures without tracking per-branch key state
                if divergence_info.is_none() {
                    // Check if KEL is decommissioned
                    if is_decommissioned {
                        return Err(KelsError::InvalidKel(
                            "KEL is decommissioned - no further events allowed".to_string(),
                        ));
                    }

                    // Handle establishment events
                    if event.is_establishment() {
                        let qb64 = event.public_key.as_ref().ok_or_else(|| {
                            KelsError::InvalidKel(
                                "Establishment event missing public key".to_string(),
                            )
                        })?;
                        let public_key = PublicKey::from_qb64(qb64)?;

                        // Verify pre-rotation commitment (except inception)
                        if *version > 0
                            && let Some(expected_hash) = last_rotation_hash
                        {
                            let computed = compute_rotation_hash(&public_key);
                            if computed != expected_hash {
                                return Err(KelsError::InvalidKel(
                                    "Public key does not match previous rotation hash".to_string(),
                                ));
                            }
                        }

                        // Verify recovery key for rec/ror/cnt/dec
                        if event.reveals_recovery_key() {
                            self.verify_recovery_key_revelation(
                                event,
                                *version,
                                last_recovery_hash,
                            )?;
                            last_recovery_hash = event.recovery_hash.as_deref();
                        }

                        current_public_key = Some(public_key);
                        last_rotation_hash = event.rotation_hash.as_deref();

                        // Initial recovery hash from inception
                        if event.is_inception() || event.is_delegated_inception() {
                            last_recovery_hash = event.recovery_hash.as_deref();
                        }

                        if event.decommissions() {
                            is_decommissioned = true;
                        }
                    }

                    // Verify signature(s)
                    self.verify_signatures(signed_event, *version, current_public_key.as_ref())?;
                }

                next_tails.insert(&event.said);
            }

            valid_tails = next_tails;
        }

        Ok(divergence_info)
    }

    /// Verify recovery key revelation for rec/ror/cnt/dec events.
    fn verify_recovery_key_revelation(
        &self,
        event: &KeyEvent,
        version: u64,
        last_recovery_hash: Option<&str>,
    ) -> Result<(), KelsError> {
        if event.recovery_key.is_none() || (event.recovery_hash.is_none() && !event.decommissions())
        {
            return Err(KelsError::InvalidKel(format!(
                "Recovery event at version {} missing recovery_key or recovery_hash",
                version
            )));
        }

        if let Some(expected_hash) = last_recovery_hash {
            let recovery_key_qb64 = event.recovery_key.as_ref().ok_or_else(|| {
                KelsError::InvalidKel("Recovery event missing recovery_key".to_string())
            })?;
            let recovery_key = PublicKey::from_qb64(recovery_key_qb64)?;
            let computed = compute_rotation_hash(&recovery_key);
            if computed != expected_hash {
                return Err(KelsError::InvalidKel(
                    "Recovery key does not match previous recovery hash".to_string(),
                ));
            }
        } else {
            return Err(KelsError::InvalidKel(
                "Recovery event without prior recovery hash".to_string(),
            ));
        }

        Ok(())
    }

    /// Verify signatures on an event.
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

impl From<Vec<SignedKeyEvent>> for Kel {
    fn from(events: Vec<SignedKeyEvent>) -> Self {
        Self(events)
    }
}

impl IntoIterator for Kel {
    type Item = SignedKeyEvent;
    type IntoIter = std::vec::IntoIter<SignedKeyEvent>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a Kel {
    type Item = &'a SignedKeyEvent;
    type IntoIter = std::slice::Iter<'a, SignedKeyEvent>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

/// Trait for pluggable KEL storage backends.
///
/// Implement this trait to provide custom storage for KELs (e.g., file-based,
/// keychain, database). This allows the same registrant logic to work across
/// different platforms with different storage mechanisms.
///
/// # Example
///
/// ```ignore
/// struct FileKelStore {
///     base_path: PathBuf,
/// }
///
/// #[async_trait]
/// impl KelStore for FileKelStore {
///     async fn load(&self, prefix: &str) -> Result<Option<Kel>, KelsError> {
///         let path = self.base_path.join(format!("{}.kel.json", prefix));
///         if !path.exists() {
///             return Ok(None);
///         }
///         let data = tokio::fs::read_to_string(&path).await?;
///         let events: Vec<SignedKeyEvent> = serde_json::from_str(&data)?;
///         Ok(Some(Kel::from_events(events, true)?))
///     }
///
///     async fn save(&self, kel: &Kel) -> Result<(), KelsError> {
///         let prefix = kel.prefix().ok_or(KelsError::NotIncepted)?;
///         let path = self.base_path.join(format!("{}.kel.json", prefix));
///         let data = serde_json::to_string_pretty(kel.events())?;
///         tokio::fs::write(&path, data).await?;
///         Ok(())
///     }
///
///     async fn delete(&self, prefix: &str) -> Result<(), KelsError> {
///         let path = self.base_path.join(format!("{}.kel.json", prefix));
///         if path.exists() {
///             tokio::fs::remove_file(&path).await?;
///         }
///         Ok(())
///     }
/// }
/// ```
#[async_trait]
pub trait KelStore: Send + Sync {
    /// The owner's prefix, if set.
    ///
    /// When set, the `cache()` method will skip saving KELs with this prefix
    /// to protect the owner's authoritative state from being overwritten by
    /// server fetches.
    fn owner_prefix(&self) -> Option<String> {
        None
    }

    /// Set or clear the owner prefix.
    ///
    /// Called after enrollment when the prefix becomes known, or on reset to clear it.
    /// Default implementation is a no-op for stores that don't support owner prefix.
    fn set_owner_prefix(&self, _prefix: Option<&str>) {}

    /// Load a KEL by its prefix.
    ///
    /// Returns `Ok(None)` if no KEL exists for the given prefix.
    /// The implementation should skip verification (pass `skip_verify: true` to
    /// `Kel::from_events`) since KELs are verified on save.
    async fn load(&self, prefix: &str) -> Result<Option<Kel>, KelsError>;

    /// Save/persist a KEL.
    ///
    /// The KEL's prefix is used as the storage key.
    /// This should overwrite any existing KEL with the same prefix.
    async fn save(&self, kel: &Kel) -> Result<(), KelsError>;

    /// Delete a KEL by its prefix.
    ///
    /// Does nothing if the KEL doesn't exist.
    async fn delete(&self, prefix: &str) -> Result<(), KelsError>;

    /// Cache a KEL fetched from a server.
    ///
    /// If the KEL's prefix matches the owner prefix, this is a no-op to protect
    /// the owner's authoritative local state from being overwritten by server data.
    /// For other prefixes, this behaves like `save()`.
    async fn cache(&self, kel: &Kel) -> Result<(), KelsError> {
        if let Some(owner) = self.owner_prefix()
            && kel.prefix() == Some(owner.as_str())
        {
            return Ok(());
        }
        self.save(kel).await
    }
}

/// File-based KEL store for CLI and desktop apps
pub struct FileKelStore {
    kel_dir: std::path::PathBuf,
    owner_prefix: std::sync::RwLock<Option<String>>,
}

impl FileKelStore {
    pub fn new(kel_dir: impl Into<std::path::PathBuf>) -> Result<Self, KelsError> {
        let kel_dir = kel_dir.into();
        std::fs::create_dir_all(&kel_dir).map_err(|e| KelsError::StorageError(e.to_string()))?;
        Ok(Self {
            kel_dir,
            owner_prefix: std::sync::RwLock::new(None),
        })
    }

    /// Create a FileKelStore with an owner prefix.
    ///
    /// The owner prefix protects your authoritative KEL from being overwritten
    /// when caching KELs fetched from a server.
    pub fn with_owner(
        kel_dir: impl Into<std::path::PathBuf>,
        owner_prefix: String,
    ) -> Result<Self, KelsError> {
        let kel_dir = kel_dir.into();
        std::fs::create_dir_all(&kel_dir).map_err(|e| KelsError::StorageError(e.to_string()))?;
        Ok(Self {
            kel_dir,
            owner_prefix: std::sync::RwLock::new(Some(owner_prefix)),
        })
    }

    fn kel_path(&self, prefix: &str) -> std::path::PathBuf {
        self.kel_dir.join(format!("{}.kel.json", prefix))
    }
}

#[async_trait]
impl KelStore for FileKelStore {
    fn owner_prefix(&self) -> Option<String> {
        self.owner_prefix.read().ok().and_then(|g| g.clone())
    }

    fn set_owner_prefix(&self, prefix: Option<&str>) {
        if let Ok(mut guard) = self.owner_prefix.write() {
            *guard = prefix.map(|s| s.to_string());
        }
    }

    async fn load(&self, prefix: &str) -> Result<Option<Kel>, KelsError> {
        let path = self.kel_path(prefix);
        if !path.exists() {
            return Ok(None);
        }

        let contents =
            std::fs::read_to_string(&path).map_err(|e| KelsError::StorageError(e.to_string()))?;
        let events: Vec<SignedKeyEvent> = serde_json::from_str(&contents)?;
        let kel = Kel::from_events(events, true)?;
        Ok(Some(kel))
    }

    async fn save(&self, kel: &Kel) -> Result<(), KelsError> {
        use std::io::Write;

        let prefix = kel
            .prefix()
            .ok_or_else(|| KelsError::InvalidKel("KEL has no prefix".to_string()))?;
        let path = self.kel_path(prefix);
        let contents = serde_json::to_string_pretty(kel.events())?;

        // Write and sync to ensure data is flushed to disk
        let mut file =
            std::fs::File::create(&path).map_err(|e| KelsError::StorageError(e.to_string()))?;
        file.write_all(contents.as_bytes())
            .map_err(|e| KelsError::StorageError(e.to_string()))?;
        file.sync_all()
            .map_err(|e| KelsError::StorageError(e.to_string()))?;

        Ok(())
    }

    async fn delete(&self, prefix: &str) -> Result<(), KelsError> {
        let path = self.kel_path(prefix);
        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| KelsError::StorageError(e.to_string()))?;
        }
        Ok(())
    }
}

// ==================== Signed Event Repository ====================

/// Repository trait for storing signed key events with their signatures.
///
/// This trait is implemented by repositories generated with `#[stored(signed_events = true)]`.
/// It provides the methods needed for database-backed KEL storage.
///
/// Use `RepositoryKelStore` to wrap a `SignedEventRepository` as a `KelStore`.
#[async_trait]
pub trait SignedEventRepository: Send + Sync {
    /// Get the full KEL for a prefix as a Kel struct.
    async fn get_kel(&self, prefix: &str) -> Result<Kel, KelsError>;

    /// Check if a signature exists for an event SAID.
    async fn get_signature_by_said(
        &self,
        said: &str,
    ) -> Result<Option<crate::EventSignature>, KelsError>;

    /// Store an event with its signatures.
    async fn create_with_signatures(
        &self,
        event: crate::KeyEvent,
        signatures: Vec<crate::EventSignature>,
    ) -> Result<crate::KeyEvent, KelsError>;
}

/// KelStore implementation backed by a SignedEventRepository.
///
/// Wraps any repository implementing `SignedEventRepository` to provide
/// `KelStore` functionality for use with `KeyEventBuilder`.
///
/// # Example
///
/// ```text
/// let repo = KeyEventRepository::new(pool);
/// let store = RepositoryKelStore::new(Arc::new(repo));
/// let builder = KeyEventBuilder::with_dependencies(key_provider, kels_client, Some(store), None);
/// ```
pub struct RepositoryKelStore<R: SignedEventRepository> {
    repo: std::sync::Arc<R>,
}

impl<R: SignedEventRepository> RepositoryKelStore<R> {
    pub fn new(repo: std::sync::Arc<R>) -> Self {
        Self { repo }
    }
}

#[async_trait]
impl<R: SignedEventRepository + 'static> KelStore for RepositoryKelStore<R> {
    async fn load(&self, prefix: &str) -> Result<Option<Kel>, KelsError> {
        let kel = self.repo.get_kel(prefix).await?;
        if kel.is_empty() {
            Ok(None)
        } else {
            Ok(Some(kel))
        }
    }

    async fn save(&self, kel: &Kel) -> Result<(), KelsError> {
        // Save each event that isn't already in the database
        for signed_event in kel.events() {
            // Check if event already exists
            let existing = self
                .repo
                .get_signature_by_said(&signed_event.event.said)
                .await?;
            if existing.is_none() {
                if signed_event.signatures.is_empty() {
                    return Err(KelsError::NoCurrentKey);
                }
                self.repo
                    .create_with_signatures(
                        signed_event.event.clone(),
                        signed_event.event_signatures(),
                    )
                    .await?;
            }
        }
        Ok(())
    }

    async fn delete(&self, _prefix: &str) -> Result<(), KelsError> {
        // No-op: KELs stored in repositories should not be deleted via KelStore
        // Use the repository's delete methods directly if needed
        Ok(())
    }
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
            .map(|e| e.decommissions())
            .unwrap_or(false)
    }

    /// Create an inception event with new keys.
    /// Only available on native/mobile platforms (requires OsRng for key generation).
    ///
    /// Generates three keys: current (signing), next (pre-committed), and recovery.
    pub async fn incept(&mut self) -> Result<(KeyEvent, Signature), KelsError> {
        let current_key = self.key_provider.generate_keypair().await?;
        let next_key = self.key_provider.generate_keypair().await?;
        let recovery_key = self.key_provider.generate_recovery_key().await?;
        let rotation_hash = compute_rotation_hash(&next_key);
        let recovery_hash = compute_rotation_hash(&recovery_key);

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
        let rotation_hash = compute_rotation_hash(&next_key);
        let recovery_hash = compute_rotation_hash(&recovery_key);

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
        let rotation_hash = compute_rotation_hash(&new_next);

        let event = KeyEvent::create_rotation(last_event, new_current.qb64(), Some(rotation_hash))?;
        let signature = self
            .key_provider
            .sign_with_pending(event.said.as_bytes())
            .await?;

        // Add event to local state
        let signed_event = SignedKeyEvent::new(event.clone(), new_current.qb64(), signature.qb64());
        self.events.push(signed_event);
        self.state.update_establishment(&event);

        // PHASE 2: Submit to KELS
        let flush_result = if self.kels_client.is_some() {
            self.flush().await
        } else {
            // Offline mode - mark as confirmed immediately
            self.state.confirm(self.events.len());
            Ok(())
        };

        // PHASE 3: Handle result
        match &flush_result {
            Ok(()) => {
                // Commit rotation on success
                self.key_provider.commit_rotation().await;
            }
            Err(KelsError::DivergenceDetected(_)) => {
                // Rollback key rotation on divergence - we need old keys for recovery
                // But keep the event (it's stored on server as part of divergent KEL)
                self.key_provider.rollback_rotation().await;
            }
            Err(_) => {
                // Rollback on other errors and remove event
                self.key_provider.rollback_rotation().await;
                self.events.pop();
                self.state = KelBuilderState::from_events(&self.events);
            }
        }

        // Save to local store - do this even on divergence since event IS stored on server
        if let Some(ref store) = self.kel_store {
            store.save(&self.kel()).await?;
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
                    store.save(&self.kel()).await?;
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
        let rotation_hash = compute_rotation_hash(&new_next);

        // Prepare recovery key rotation
        let (current_recovery_pub, new_recovery_pub) =
            self.key_provider.prepare_recovery_rotation().await?;
        let new_recovery_hash = compute_rotation_hash(&new_recovery_pub);

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
                    store.save(&self.kel()).await?;
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

        let kels_events = kels_kel.events();

        // Check if KEL is divergent - if so, recovery is definitely needed
        let divergence_info = kels_kel.find_divergence();

        // Check if our pending events were actually accepted (by SAID match)
        // But only skip recovery if no divergence - divergent KEL always needs recovery
        let pending = self.pending_events();
        if !pending.is_empty() && divergence_info.is_none() {
            let kels_saids: std::collections::HashSet<_> =
                kels_events.iter().map(|e| &e.event.said).collect();
            let all_accepted = pending.iter().all(|e| kels_saids.contains(&e.event.said));
            if all_accepted {
                // Our events were accepted and no divergence - sync local state and return
                self.set_events(kels_events.to_vec());
                return Err(KelsError::NoRecoveryNeeded(
                    "Pending events were accepted, state synced".into(),
                ));
            }
        }

        // Find divergence point from the fetched KEL
        let divergence_version = divergence_info
            .ok_or_else(|| KelsError::NoRecoveryNeeded("No divergence detected in KEL".into()))?
            .diverged_at_version;

        // Get the last agreed establishment event (before divergence)
        let valid_establishment = kels_events
            .iter()
            .rfind(|e| e.event.version < divergence_version && e.event.is_establishment())
            .ok_or_else(|| {
                KelsError::InvalidKel("No establishment event before divergence".into())
            })?;

        // Analyze adversary events in divergent range
        let divergent_events: Vec<_> = kels_events
            .iter()
            .filter(|e| e.event.version >= divergence_version)
            .collect();

        // Check if adversary revealed recovery key - this means true compromise
        let adversary_has_recovery = divergent_events
            .iter()
            .any(|e| e.event.reveals_recovery_key());

        // Check if adversary rotated (rot without rec) - recoverable but need immediate rotation
        let adversary_rotated = divergent_events.iter().any(|e| e.event.is_rotation());

        // Rebuild state from agreed-upon prefix
        let agreed_events: Vec<_> = kels_events
            .iter()
            .filter(|e| e.event.version < divergence_version)
            .cloned()
            .collect();

        self.set_events(agreed_events);

        // Get the last agreed event to chain from
        let last_agreed_event = self
            .state
            .last_trusted_event
            .as_ref()
            .ok_or_else(|| KelsError::InvalidKel("No agreed events".into()))?;

        // Determine which case we're in based on key matching
        let valid_pub_key = valid_establishment
            .event
            .public_key
            .as_ref()
            .ok_or_else(|| KelsError::InvalidKel("No public key in establishment".into()))?;

        let valid_rotation_hash = valid_establishment.event.rotation_hash.as_ref();

        let current_key = self.key_provider.current_public_key().await?;

        // Case A: current matches valid_establishment.public_key (no local rotation happened)
        // Case B: current matches valid_establishment.rotation_hash (local rotation was rejected)
        let current_key_hash = compute_rotation_hash(&current_key);
        let is_case_b = if current_key.qb64() == *valid_pub_key {
            false // Case A
        } else if valid_rotation_hash.is_some_and(|h| *h == current_key_hash) {
            true // Case B - current key matches what was committed in rotation_hash
        } else {
            return Err(KelsError::KeyMismatch(
                "Current key matches neither establishment public_key nor rotation_hash".into(),
            ));
        };

        // For Case A, we need to rotate internally first
        if !is_case_b {
            // Case A: rotate internally (next → current, generate new next)
            self.key_provider.rotate().await?;
        }

        // Now current is the "next" key (for Case A) or already the post-rotation key (Case B)
        let new_current_key = self.key_provider.current_public_key().await?;
        let new_next_key = self.key_provider.next_public_key().await?;

        // Prepare recovery key rotation - get current and new recovery keys
        let (current_recovery_pub, new_recovery_pub) =
            self.key_provider.prepare_recovery_rotation().await?;

        // Create recovery event based on adversary compromise level
        let rec_event = if adversary_has_recovery {
            // Adversary revealed recovery key - create contest event (KEL frozen)
            KeyEvent::create_contest(
                last_agreed_event,
                new_current_key.qb64(),
                current_recovery_pub.qb64(),
            )?
        } else {
            // Normal recovery: continue with new hashes
            KeyEvent::create_recovery(
                last_agreed_event,
                new_current_key.qb64(),
                compute_rotation_hash(&new_next_key),
                current_recovery_pub.qb64(),
                compute_rotation_hash(&new_recovery_pub),
            )?
        };

        // Primary signature: sign with new current key (matches event.public_key)
        let rec_primary_signature = self.key_provider.sign(rec_event.said.as_bytes()).await?;

        // Secondary signature: sign with recovery key (proves ownership)
        let rec_secondary_signature = self
            .key_provider
            .sign_with_recovery(rec_event.said.as_bytes())
            .await?;

        // Create signed rec event with dual signatures
        let signed_rec_event = SignedKeyEvent::new_recovery(
            rec_event.clone(),
            new_current_key.qb64(),
            rec_primary_signature.qb64(),
            current_recovery_pub.qb64(),
            rec_secondary_signature.qb64(),
        );

        // If adversary rotated, they know our current signing key - need immediate rotation
        let events_to_submit: Vec<SignedKeyEvent>;
        let final_event: KeyEvent;
        let final_signature: Signature;

        if adversary_has_recovery {
            events_to_submit = vec![signed_rec_event];
            final_event = rec_event.clone();
            final_signature = rec_primary_signature;
        } else if adversary_rotated {
            // Rotate signing key to escape compromised key
            let post_rec_current = self.key_provider.rotate().await?;
            let post_rec_next = self.key_provider.next_public_key().await?;

            // Create rot event chained from rec event
            let rot_event = KeyEvent::create_rotation(
                &rec_event,
                post_rec_current.qb64(),
                Some(compute_rotation_hash(&post_rec_next)),
            )?;

            let rot_signature = self.key_provider.sign(rot_event.said.as_bytes()).await?;
            let signed_rot_event = SignedKeyEvent::new(
                rot_event.clone(),
                post_rec_current.qb64(),
                rot_signature.qb64(),
            );

            events_to_submit = vec![signed_rec_event, signed_rot_event];
            final_event = rot_event;
            final_signature = rot_signature;
        } else {
            events_to_submit = vec![signed_rec_event];
            final_event = rec_event.clone();
            final_signature = rec_primary_signature;
        }

        // Submit to KELS (batch if adversary rotated)
        let response = client.submit_events(&events_to_submit).await?;

        if response.accepted {
            // Commit the recovery key rotation now that the events were accepted
            self.key_provider.commit_recovery_rotation().await;

            // Update local state with all submitted events
            for signed_event in &events_to_submit {
                self.events.push(signed_event.clone());
            }
            self.state.update_establishment(&final_event);

            // Save to local store if configured
            if let Some(ref store) = self.kel_store {
                store.save(&self.kel()).await?;
            }

            let outcome = if adversary_has_recovery {
                RecoveryOutcome::Contested
            } else {
                RecoveryOutcome::Recovered
            };

            Ok((outcome, final_event, final_signature))
        } else {
            Err(KelsError::SubmissionFailed(
                "Recovery events rejected by KELS".into(),
            ))
        }
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
        self.state.last_trusted_event.as_ref().map(|e| e.prefix.as_str())
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
        self.state.last_trusted_event.as_ref().map(|e| e.said.as_str())
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
    pub fn kel(&self) -> Kel {
        Kel(self.events.clone())
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

            Err(KelsError::DivergenceDetected(diverged_at))
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

        // Save to local store if configured
        // Do this even on divergence since the event WAS stored on server
        if let Some(ref store) = self.kel_store {
            store.save(&self.kel()).await?;
        }

        flush_result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyProvider;
    use verifiable_storage::SelfAddressed;

    #[tokio::test]
    async fn test_incept() {
        let mut builder = KeyEventBuilder::new(KeyProvider::software(), None);

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
        let mut builder = KeyEventBuilder::new(KeyProvider::software(), None);

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
        let mut builder = KeyEventBuilder::new(KeyProvider::software(), None);

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
        let expected_hash = compute_rotation_hash(&new_public_key);
        assert_eq!(rotation_hash, expected_hash);

        assert!(
            new_public_key
                .verify(rot_event.said.as_bytes(), &signature)
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_interact_before_incept_fails() {
        let mut builder = KeyEventBuilder::new(KeyProvider::software(), None);

        let result = builder.interact("some_anchor").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_rotate_before_incept_fails() {
        let mut builder = KeyEventBuilder::new(KeyProvider::software(), None);

        let result = builder.rotate().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_said_verification() {
        let mut builder = KeyEventBuilder::new(KeyProvider::software(), None);

        let (event, _) = builder.incept().await.unwrap();
        assert!(event.verify_prefix().is_ok());

        let (ixn_event, _) = builder.interact("anchor").await.unwrap();
        assert!(ixn_event.verify_said().is_ok());
    }

    #[tokio::test]
    async fn test_with_kel() {
        let mut builder1 = KeyEventBuilder::new(KeyProvider::software(), None);
        let (icp_event, icp_sig) = builder1.incept().await.unwrap();
        let public_key = icp_event.public_key.clone().unwrap();

        let software = builder1.key_provider().as_software().unwrap();
        let current_key = software.current_private_key().unwrap().clone();
        let next_key = software.next_private_key().unwrap().clone();

        let mut kel = Kel::new();
        kel.push(SignedKeyEvent::new(
            icp_event.clone(),
            public_key,
            icp_sig.qb64(),
        ));
        let mut builder2 = KeyEventBuilder::with_kel(
            KeyProvider::with_software_keys(current_key, next_key),
            None,
            &kel,
        );

        let (ixn_event, _) = builder2.interact("anchor").await.unwrap();
        assert_eq!(ixn_event.prefix, icp_event.prefix);
        assert_eq!(ixn_event.previous, Some(icp_event.said));
        assert_eq!(ixn_event.version, 1);
    }

    #[tokio::test]
    async fn test_rotation_after_interactions() {
        let mut builder = KeyEventBuilder::new(KeyProvider::software(), None);
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

        let software = builder.key_provider().as_software().unwrap();
        let current_key = software.current_private_key().unwrap().clone();
        let next_key = software.next_private_key().unwrap().clone();
        let mut builder2 = KeyEventBuilder::with_kel(
            KeyProvider::with_software_keys(current_key, next_key),
            None,
            &kel,
        );

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
        let mut builder = KeyEventBuilder::new(KeyProvider::software(), None);

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
        let mut builder = KeyEventBuilder::new(KeyProvider::software(), None);
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
        let mut builder = KeyEventBuilder::new(KeyProvider::software(), None);
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
        let mut builder1 = KeyEventBuilder::new(KeyProvider::software(), None);
        let (icp_event, icp_sig) = builder1.incept().await.unwrap();
        let (ixn1, ixn1_sig) = builder1.interact("anchor1").await.unwrap();

        // Create a second builder from the same icp to make a divergent event
        let software = builder1.key_provider().as_software().unwrap();
        let current_key = software.current_private_key().unwrap().clone();
        let next_key = software.next_private_key().unwrap().clone();

        let icp_public_key = icp_event.public_key.clone().unwrap();
        let mut kel_for_builder2 = Kel::new();
        kel_for_builder2.push(SignedKeyEvent::new(
            icp_event.clone(),
            icp_public_key.clone(),
            icp_sig.qb64(),
        ));

        let mut builder2 = KeyEventBuilder::with_kel(
            KeyProvider::with_software_keys(current_key, next_key),
            None,
            &kel_for_builder2,
        );
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
        let mut builder1 = KeyEventBuilder::new(KeyProvider::software(), None);
        let (icp_event, icp_sig) = builder1.incept().await.unwrap();
        let (ixn1, ixn1_sig) = builder1.interact("anchor1").await.unwrap();

        let software = builder1.key_provider().as_software().unwrap();
        let current_key = software.current_private_key().unwrap().clone();
        let next_key = software.next_private_key().unwrap().clone();

        let icp_public_key = icp_event.public_key.clone().unwrap();
        let mut kel_for_builder2 = Kel::new();
        kel_for_builder2.push(SignedKeyEvent::new(
            icp_event.clone(),
            icp_public_key.clone(),
            icp_sig.qb64(),
        ));

        // Create second divergent event
        let mut builder2 = KeyEventBuilder::with_kel(
            KeyProvider::with_software_keys(current_key.clone(), next_key.clone()),
            None,
            &kel_for_builder2,
        );
        let (ixn2, ixn2_sig) = builder2.interact("anchor2").await.unwrap();

        // Create third divergent event
        let mut builder3 = KeyEventBuilder::with_kel(
            KeyProvider::with_software_keys(current_key, next_key),
            None,
            &kel_for_builder2,
        );
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
        let mut builder1 = KeyEventBuilder::new(KeyProvider::software(), None);
        let (icp_event, icp_sig) = builder1.incept().await.unwrap();
        let (ixn1, ixn1_sig) = builder1.interact("anchor1").await.unwrap();

        let software = builder1.key_provider().as_software().unwrap();
        let current_key = software.current_private_key().unwrap().clone();
        let next_key = software.next_private_key().unwrap().clone();

        let icp_public_key = icp_event.public_key.clone().unwrap();
        let mut kel_for_builder2 = Kel::new();
        kel_for_builder2.push(SignedKeyEvent::new(
            icp_event.clone(),
            icp_public_key.clone(),
            icp_sig.qb64(),
        ));

        let mut builder2 = KeyEventBuilder::with_kel(
            KeyProvider::with_software_keys(current_key.clone(), next_key.clone()),
            None,
            &kel_for_builder2,
        );
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
            KeyProvider::with_software_keys(current_key, next_key),
            None,
            &divergent_kel,
        );

        // last_event should be the icp (last event BEFORE divergence at v1)
        assert_eq!(builder3.last_event().unwrap().said, icp_event.said);

        // confirmed_cursor should point to position 1 (first divergent event)
        assert_eq!(builder3.confirmed_count(), 1);

        // pending_events should be the two divergent events
        assert_eq!(builder3.pending_events().len(), 2);
    }

    #[tokio::test]
    async fn test_with_kel_three_way_divergent() {
        // Test that 3-way divergence is handled correctly by with_kel
        let mut builder1 = KeyEventBuilder::new(KeyProvider::software(), None);
        let (icp_event, icp_sig) = builder1.incept().await.unwrap();
        let (ixn1, ixn1_sig) = builder1.interact("anchor1").await.unwrap();

        let software = builder1.key_provider().as_software().unwrap();
        let current_key = software.current_private_key().unwrap().clone();
        let next_key = software.next_private_key().unwrap().clone();

        let icp_public_key = icp_event.public_key.clone().unwrap();
        let mut kel_for_others = Kel::new();
        kel_for_others.push(SignedKeyEvent::new(
            icp_event.clone(),
            icp_public_key.clone(),
            icp_sig.qb64(),
        ));

        let mut builder2 = KeyEventBuilder::with_kel(
            KeyProvider::with_software_keys(current_key.clone(), next_key.clone()),
            None,
            &kel_for_others,
        );
        let (ixn2, ixn2_sig) = builder2.interact("anchor2").await.unwrap();

        let mut builder3 = KeyEventBuilder::with_kel(
            KeyProvider::with_software_keys(current_key.clone(), next_key.clone()),
            None,
            &kel_for_others,
        );
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
            KeyProvider::with_software_keys(current_key, next_key),
            None,
            &divergent_kel,
        );

        // last_event should be icp (before divergence)
        assert_eq!(loaded_builder.last_event().unwrap().said, icp_event.said);

        // confirmed_cursor should be 1, pending should have 3 events
        assert_eq!(loaded_builder.confirmed_count(), 1);
        assert_eq!(loaded_builder.pending_events().len(), 3);
    }
}
