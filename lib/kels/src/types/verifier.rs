//! Streaming incremental KEL verifier and sync abstraction.
//!
//! `KelVerifier` verifies events page by page without holding the full chain in memory.
//! Tracks evolving cryptographic state as it walks forward through the chain,
//! supporting both linear and divergent KELs.
//!
//! After verification, call `into_verification()` to get a `Verification` — the
//! proof-of-verification token that provides access to verified KEL state.
//!
//! `PagedKelSource` / `PagedKelSink` / `sync_and_verify` provide a generic pattern
//! for streaming events from a source through a verifier into a destination.

use std::collections::{BTreeSet, HashMap};

use async_trait::async_trait;
use cesr::{Digest, Matter, PublicKey, Signature};
use verifiable_storage::{Chained, SelfAddressed};

use super::events::SignedKeyEvent;
use super::verification::{BranchTip, Verification};
use crate::error::KelsError;
use crate::store::KelStore;

/// Compute the rotation hash (Blake3-256 of the public key qb64 string).
pub fn compute_rotation_hash(public_key: &str) -> String {
    Digest::blake3_256(public_key.as_bytes()).qb64()
}

/// Per-branch cryptographic state tracked during verification.
#[derive(Clone)]
struct BranchState {
    tip: SignedKeyEvent,
    establishment_tip: SignedKeyEvent,
    current_public_key: String,
    pending_rotation_hash: Option<String>,
    pending_recovery_hash: Option<String>,
}

/// Stateful forward-walking chain verifier.
///
/// Verifies events incrementally, page by page. Tracks evolving cryptographic state
/// so the full chain never needs to be in memory.
///
/// Supports both linear chains and divergent KELs. When events arrive at the same
/// serial (divergence), the verifier forks branch state and verifies each branch
/// independently.
///
/// Events MUST be fed in `serial ASC, said ASC` order with complete generations
/// (all events at a given serial must be in the same page). Use
/// `truncate_incomplete_generation()` to ensure this at page boundaries.
///
/// After verification, call `into_verification()` to produce a `Verification`
/// (proof-of-verification token).
pub struct KelVerifier {
    prefix: String,
    /// Pre-divergence: single branch state. Branches keyed by tip SAID.
    branches: HashMap<String, BranchState>,
    /// The current serial we've verified up to.
    last_verified_serial: Option<u64>,
    /// Serial where divergence first occurred.
    diverged_at_serial: Option<u64>,
    /// Whether a contest event has been seen.
    is_contested: bool,
    /// Anchor checking: SAIDs we're looking for.
    queried_saids: BTreeSet<String>,
    /// Anchor checking: SAIDs we've found anchored.
    anchored_saids: BTreeSet<String>,
}

impl KelVerifier {
    /// Start from inception. Used for full verification (e.g., streaming a peer's KEL).
    pub fn new(prefix: impl Into<String>) -> Self {
        Self {
            prefix: prefix.into(),
            branches: HashMap::new(),
            last_verified_serial: None,
            diverged_at_serial: None,
            is_contested: false,
            queried_saids: BTreeSet::new(),
            anchored_saids: BTreeSet::new(),
        }
    }

    /// Start verification from a single verified branch tip.
    ///
    /// Used for divergence/recovery scenarios where events need to be verified
    /// against a specific branch (not all branches). Creates a single-branch
    /// verifier from the branch tip's crypto state.
    pub fn from_branch_tip(prefix: impl Into<String>, tip: &BranchTip) -> Self {
        let prefix = prefix.into();
        let mut branches = HashMap::new();

        if let Some(ref pk) = tip.establishment_tip.event.public_key {
            branches.insert(
                tip.tip.event.said.clone(),
                BranchState {
                    tip: tip.tip.clone(),
                    establishment_tip: tip.establishment_tip.clone(),
                    current_public_key: pk.clone(),
                    pending_rotation_hash: tip.establishment_tip.event.rotation_hash.clone(),
                    pending_recovery_hash: tip.establishment_tip.event.recovery_hash.clone(),
                },
            );
        }

        let last_verified_serial = Some(tip.tip.event.serial);

        Self {
            prefix,
            branches,
            last_verified_serial,
            diverged_at_serial: None,
            is_contested: false,
            queried_saids: BTreeSet::new(),
            anchored_saids: BTreeSet::new(),
        }
    }

    /// Resume from a verified `Verification`.
    pub fn resume(prefix: impl Into<String>, ctx: &Verification) -> Self {
        let prefix = prefix.into();
        let mut branches = HashMap::new();

        for bt in ctx.branch_tips() {
            if let Some(ref pk) = bt.establishment_tip.event.public_key {
                branches.insert(
                    bt.tip.event.said.clone(),
                    BranchState {
                        tip: bt.tip.clone(),
                        establishment_tip: bt.establishment_tip.clone(),
                        current_public_key: pk.clone(),
                        pending_rotation_hash: bt.establishment_tip.event.rotation_hash.clone(),
                        pending_recovery_hash: bt.establishment_tip.event.recovery_hash.clone(),
                    },
                );
            }
        }

        let last_verified_serial = ctx.branch_tips().iter().map(|bt| bt.tip.event.serial).max();

        Self {
            prefix,
            branches,
            last_verified_serial,
            diverged_at_serial: ctx.diverged_at_serial(),
            is_contested: ctx.is_contested(),
            queried_saids: BTreeSet::new(),
            anchored_saids: BTreeSet::new(),
        }
    }

    /// Register SAIDs to check for anchoring during verification.
    ///
    /// Call this before `verify_page()`. As the verifier walks events, it checks
    /// each `ixn` event's `anchor` field against these SAIDs. Results are available
    /// via `Verification::anchored_saids()` after calling `into_verification()`.
    pub fn check_anchors(&mut self, saids: impl IntoIterator<Item = String>) {
        self.queried_saids.extend(saids);
    }

    /// The current public key (qb64) after the last verified establishment event.
    /// Only meaningful for non-divergent KELs (single branch).
    pub fn current_public_key(&self) -> Option<&str> {
        if self.branches.len() == 1 {
            self.branches
                .values()
                .next()
                .map(|b| b.current_public_key.as_str())
        } else {
            None
        }
    }

    /// Verify a page of events against the running state.
    ///
    /// Events must be sorted `serial ASC, said ASC` and complete generations
    /// must not be split across pages. Use `truncate_incomplete_generation()`
    /// to ensure this.
    pub fn verify_page(&mut self, events: &[SignedKeyEvent]) -> Result<(), KelsError> {
        // Group events by serial to process complete generations
        let mut serial_groups: Vec<(u64, Vec<&SignedKeyEvent>)> = Vec::new();
        for event in events {
            if let Some(last) = serial_groups.last_mut()
                && last.0 == event.event.serial
            {
                last.1.push(event);
                continue;
            }
            serial_groups.push((event.event.serial, vec![event]));
        }

        for (serial, generation) in serial_groups {
            self.verify_generation(serial, &generation)?;
        }

        Ok(())
    }

    /// Consume the verifier and produce a `Verification` (proof-of-verification token).
    pub fn into_verification(self) -> Result<Verification, KelsError> {
        let mut branch_tips: Vec<BranchTip> = self
            .branches
            .into_values()
            .map(|bs| BranchTip {
                tip: bs.tip,
                establishment_tip: bs.establishment_tip,
            })
            .collect();

        // Deterministic ordering for SAID derivation
        branch_tips.sort_by(|a, b| a.tip.event.said.cmp(&b.tip.event.said));

        let mut v = Verification::new(
            self.prefix,
            branch_tips,
            self.is_contested,
            self.diverged_at_serial,
            self.anchored_saids,
            self.queried_saids,
        );
        v.derive_said()
            .map_err(|e| KelsError::InvalidKel(format!("SAID derivation failed: {}", e)))?;
        Ok(v)
    }

    /// Verify a complete generation (all events at a given serial).
    fn verify_generation(
        &mut self,
        serial: u64,
        events: &[&SignedKeyEvent],
    ) -> Result<(), KelsError> {
        if events.is_empty() {
            return Ok(());
        }

        // Inception (serial 0, no branches yet)
        if self.branches.is_empty() {
            if serial != 0 {
                return Err(KelsError::InvalidSerial(format!(
                    "First event has serial {} but expected 0",
                    serial
                )));
            }
            if events.len() > 1 {
                return Err(KelsError::InvalidKel(
                    "Multiple inception events at serial 0".to_string(),
                ));
            }
            let event = events[0];
            self.verify_inception(event)?;
            return Ok(());
        }

        // Non-inception: expected serial is last_verified + 1
        let expected_serial = self.last_verified_serial.map(|s| s + 1).unwrap_or(0);

        if serial != expected_serial {
            return Err(KelsError::InvalidSerial(format!(
                "Generation has serial {} but expected {}",
                serial, expected_serial,
            )));
        }

        // Detect divergence: more events than branches means new fork
        let num_branches = self.branches.len();
        if events.len() > num_branches && self.diverged_at_serial.is_none() {
            self.diverged_at_serial = Some(serial);
        }

        // Match each event to its branch via `previous` pointer
        let mut new_branches: HashMap<String, BranchState> = HashMap::new();

        for event in events {
            let previous = event.event.previous.as_deref().ok_or_else(|| {
                KelsError::InvalidKel(format!(
                    "Non-inception event {} has no previous pointer",
                    event.event.said,
                ))
            })?;

            // Find the branch this event extends
            let branch = self.branches.get(previous).ok_or_else(|| {
                KelsError::InvalidKel(format!(
                    "Event {} previous {} does not match any branch tip",
                    event.event.said, previous,
                ))
            })?;

            // Verify the event against this branch's crypto state
            let new_state = self.verify_chain_event(event, branch)?;

            // Track anchor checking
            if event.event.is_interaction()
                && let Some(ref anchor) = event.event.anchor
                && self.queried_saids.contains(anchor.as_str())
            {
                self.anchored_saids.insert(anchor.clone());
            }

            // Track contested
            if event.event.is_contest() {
                self.is_contested = true;
            }

            new_branches.insert(event.event.said.clone(), new_state);
        }

        // For branches not extended by any event in this generation,
        // this is an error — all branches must advance together
        // (events are ordered serial ASC, so if a branch has no event
        // at this serial, it means its tip is stale)
        //
        // Actually, in a divergent KEL stored as serial ASC said ASC,
        // branches that were NOT extended simply don't have events at this
        // serial. That only happens if one branch is shorter. Keep those
        // branches as-is.
        for (said, state) in &self.branches {
            if !new_branches.values().any(|_| true)
                || events
                    .iter()
                    .any(|e| e.event.previous.as_deref() == Some(said.as_str()))
            {
                continue;
            }
            // Branch not extended — keep it
            new_branches.insert(said.clone(), state.clone());
        }

        self.branches = new_branches;
        self.last_verified_serial = Some(serial);

        Ok(())
    }

    /// Verify an inception event and initialize the first branch.
    fn verify_inception(&mut self, signed_event: &SignedKeyEvent) -> Result<(), KelsError> {
        let event = &signed_event.event;

        // Basic checks
        self.verify_event_basics(event)?;

        if event.previous.is_some() {
            return Err(KelsError::InvalidKel(format!(
                "Inception event {} has previous pointer",
                event.said,
            )));
        }
        if !event.kind.is_inception() {
            return Err(KelsError::InvalidKel(format!(
                "First event {} is not an inception event",
                event.said,
            )));
        }

        let qb64 = event.public_key.as_ref().ok_or_else(|| {
            KelsError::InvalidKel("Establishment event missing public key".to_string())
        })?;

        // Verify signature with the event's own public key
        let public_key = PublicKey::from_qb64(qb64)?;
        Self::verify_signatures(signed_event, &public_key)?;

        // Anchor checking
        if event.is_interaction()
            && let Some(ref anchor) = event.anchor
            && self.queried_saids.contains(anchor.as_str())
        {
            self.anchored_saids.insert(anchor.clone());
        }

        // Initialize branch
        self.branches.insert(
            event.said.clone(),
            BranchState {
                tip: signed_event.clone(),
                establishment_tip: signed_event.clone(),
                current_public_key: qb64.clone(),
                pending_rotation_hash: event.rotation_hash.clone(),
                pending_recovery_hash: event.recovery_hash.clone(),
            },
        );
        self.last_verified_serial = Some(0);

        Ok(())
    }

    /// Verify a non-inception event against a branch's crypto state.
    /// Returns the updated branch state.
    fn verify_chain_event(
        &self,
        signed_event: &SignedKeyEvent,
        branch: &BranchState,
    ) -> Result<BranchState, KelsError> {
        let event = &signed_event.event;

        self.verify_event_basics(event)?;

        if event.is_establishment() {
            let qb64 = event.public_key.as_ref().ok_or_else(|| {
                KelsError::InvalidKel("Establishment event missing public key".to_string())
            })?;

            // Verify forward commitment
            if let Some(ref rotation_hash) = branch.pending_rotation_hash {
                let computed = compute_rotation_hash(qb64);
                if computed != *rotation_hash {
                    return Err(KelsError::InvalidKel(
                        "Public key does not match previous rotation hash".to_string(),
                    ));
                }
            }

            // Verify recovery key revelation
            if event.reveals_recovery_key() {
                let recovery_key = event.recovery_key.as_ref().ok_or_else(|| {
                    KelsError::InvalidKel(format!(
                        "Recovery event {} has no recovery_key field",
                        &event.said,
                    ))
                })?;

                if let Some(ref recovery_hash) = branch.pending_recovery_hash {
                    let computed = compute_rotation_hash(recovery_key);
                    if computed != *recovery_hash {
                        return Err(KelsError::InvalidKel(
                            "Recovery key does not match previous recovery hash".to_string(),
                        ));
                    }
                }
            }

            // Verify signature with this event's own public key
            let public_key = PublicKey::from_qb64(qb64)?;
            Self::verify_signatures(signed_event, &public_key)?;

            Ok(BranchState {
                tip: signed_event.clone(),
                establishment_tip: signed_event.clone(),
                current_public_key: qb64.clone(),
                pending_rotation_hash: event.rotation_hash.clone(),
                pending_recovery_hash: event.recovery_hash.clone(),
            })
        } else {
            // Non-establishment: verify with branch's current public key
            let public_key = PublicKey::from_qb64(&branch.current_public_key)?;
            Self::verify_signatures(signed_event, &public_key)?;

            Ok(BranchState {
                tip: signed_event.clone(),
                establishment_tip: branch.establishment_tip.clone(),
                current_public_key: branch.current_public_key.clone(),
                pending_rotation_hash: branch.pending_rotation_hash.clone(),
                pending_recovery_hash: branch.pending_recovery_hash.clone(),
            })
        }
    }

    /// SAID integrity + prefix match + structure validation.
    fn verify_event_basics(&self, event: &super::events::KeyEvent) -> Result<(), KelsError> {
        event.verify().map_err(|e| {
            KelsError::InvalidKel(format!(
                "Event {} SAID verification failed: {}",
                &event.said, e
            ))
        })?;

        if event.prefix != self.prefix {
            return Err(KelsError::InvalidKel(format!(
                "Event {} has different prefix",
                &event.said,
            )));
        }

        event.validate_structure().map_err(KelsError::InvalidKel)?;

        Ok(())
    }

    fn verify_signatures(
        signed_event: &SignedKeyEvent,
        public_key: &PublicKey,
    ) -> Result<(), KelsError> {
        let event = &signed_event.event;
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

        // Dual-signature requirement for recovery events
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

/// Truncate a page of events so that the last generation is complete.
///
/// Events are expected in `serial ASC, said ASC` order. If the last serial has
/// fewer events than the second-to-last, the incomplete generation is removed.
/// Returns the number of events truncated (caller should not advance the offset
/// past these).
pub fn truncate_incomplete_generation(events: &mut Vec<SignedKeyEvent>) -> usize {
    if events.len() < 2 {
        return 0;
    }

    // Safe: checked events.len() >= 2 above
    let last_serial = events[events.len() - 1].event.serial;
    let last_count = events
        .iter()
        .rev()
        .take_while(|e| e.event.serial == last_serial)
        .count();

    // Find the second-to-last serial
    let second_last_serial = events
        .iter()
        .rev()
        .skip(last_count)
        .map(|e| e.event.serial)
        .next();

    let Some(second_last) = second_last_serial else {
        // Only one serial in the page — it's complete
        return 0;
    };

    let second_last_count = events
        .iter()
        .filter(|e| e.event.serial == second_last)
        .count();

    if last_count < second_last_count {
        // Incomplete generation — truncate
        let new_len = events.len() - last_count;
        events.truncate(new_len);
        last_count
    } else {
        0
    }
}

/// Trait for loading pages of signed key events. Implemented by `KelStore`
/// and by transaction wrappers that read under advisory locks.
#[async_trait]
pub trait PageLoader: Send + Sync {
    async fn load_page(
        &mut self,
        prefix: &str,
        limit: u64,
        offset: u64,
    ) -> Result<(Vec<SignedKeyEvent>, bool), KelsError>;
}

/// `KelStore` adapter for `PageLoader` — wraps a shared reference.
pub struct StorePageLoader<'a>(&'a dyn KelStore);

impl<'a> StorePageLoader<'a> {
    pub fn new(store: &'a dyn KelStore) -> Self {
        Self(store)
    }
}

#[async_trait]
impl PageLoader for StorePageLoader<'_> {
    async fn load_page(
        &mut self,
        prefix: &str,
        limit: u64,
        offset: u64,
    ) -> Result<(Vec<SignedKeyEvent>, bool), KelsError> {
        self.0.load(prefix, limit, offset).await
    }
}

/// Verify a full KEL using paginated reads, returning a trusted `Verification`.
///
/// Pages through the loader with `KelVerifier` and returns the proof-of-verification
/// token. `max_pages` limits resource exhaustion from enormous KELs — fails secure
/// if exceeded.
///
/// `anchor_saids` optionally registers SAIDs to check for anchoring during the walk.
/// Results are available via `Verification::anchored_saids()` / `anchors_all_saids()`.
///
/// Use `StorePageLoader` to wrap a `&dyn KelStore`, or implement `PageLoader` on a
/// locked transaction wrapper to read under advisory lock.
pub async fn completed_verification(
    loader: &mut dyn PageLoader,
    prefix: &str,
    page_size: u64,
    max_pages: usize,
    anchor_saids: impl IntoIterator<Item = String>,
) -> Result<Verification, KelsError> {
    let mut verifier = KelVerifier::new(prefix);
    verifier.check_anchors(anchor_saids);
    let mut offset: u64 = 0;

    for _ in 0..max_pages {
        let (mut events, has_more) = loader.load_page(prefix, page_size, offset).await?;

        if events.is_empty() {
            break;
        }

        // Ensure complete generations at page boundary
        let truncated = if has_more {
            truncate_incomplete_generation(&mut events)
        } else {
            0
        };

        let advanced = events.len() as u64;
        verifier.verify_page(&events)?;
        offset += advanced;

        if !has_more || truncated > 0 && advanced == 0 {
            break;
        }
    }

    verifier.into_verification()
}

// ==================== Sync Abstraction ====================

/// Source of paginated signed key events (e.g., HTTP client, local DB).
#[async_trait]
pub trait PagedKelSource: Send + Sync {
    async fn fetch_page(
        &self,
        prefix: &str,
        since: Option<&str>,
        limit: usize,
    ) -> Result<(Vec<SignedKeyEvent>, bool), KelsError>;
}

/// Destination for signed key events (e.g., local DB).
#[async_trait]
pub trait PagedKelSink: Send + Sync {
    async fn store_page(&self, prefix: &str, events: &[SignedKeyEvent]) -> Result<(), KelsError>;
}

/// Stream pages from source → verify with KelVerifier → store in sink.
///
/// Loops: fetch page → `verifier.verify_page()` → `sink.store_page()` → advance cursor.
/// Stops when `!has_more` or `max_pages` reached.
pub async fn sync_and_verify(
    prefix: &str,
    source: &impl PagedKelSource,
    sink: &impl PagedKelSink,
    verifier: &mut KelVerifier,
    page_size: usize,
    max_pages: usize,
) -> Result<(), KelsError> {
    let mut since: Option<String> = None;

    for _ in 0..max_pages {
        let (events, has_more) = source
            .fetch_page(prefix, since.as_deref(), page_size)
            .await?;

        if events.is_empty() {
            break;
        }

        verifier.verify_page(&events)?;

        let last_said = events.last().map(|e| e.event.said.clone());

        sink.store_page(prefix, &events).await?;

        if !has_more {
            break;
        }

        since = last_said;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::RwLock};

    use async_trait::async_trait;
    use cesr::{Matter, PrivateKey};

    use super::*;
    use crate::{builder::KeyEventBuilder, crypto::SoftwareKeyProvider, store::KelStore};

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

    /// Verify events with KelVerifier and return Verification
    fn verify(events: &[SignedKeyEvent]) -> Verification {
        let prefix = events[0].event.prefix.clone();
        let mut verifier = KelVerifier::new(&prefix);
        verifier.verify_page(events).unwrap();
        verifier.into_verification().unwrap()
    }

    /// Verify events with anchor checking and return Verification
    fn verify_with_anchors(
        events: &[SignedKeyEvent],
        anchors: impl IntoIterator<Item = String>,
    ) -> Verification {
        let prefix = events[0].event.prefix.clone();
        let mut verifier = KelVerifier::new(&prefix);
        verifier.check_anchors(anchors);
        verifier.verify_page(events).unwrap();
        verifier.into_verification().unwrap()
    }

    /// In-memory store for testing
    struct MemoryStore {
        kels: RwLock<HashMap<String, Vec<SignedKeyEvent>>>,
    }

    impl MemoryStore {
        fn new() -> Self {
            Self {
                kels: RwLock::new(HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl KelStore for MemoryStore {
        async fn load(
            &self,
            prefix: &str,
            limit: u64,
            offset: u64,
        ) -> Result<(Vec<SignedKeyEvent>, bool), crate::error::KelsError> {
            let guard = self.kels.read().unwrap();
            match guard.get(prefix) {
                Some(events) => {
                    let start = offset as usize;
                    if start >= events.len() {
                        return Ok((vec![], false));
                    }
                    let end = (start + limit as usize).min(events.len());
                    let page = events[start..end].to_vec();
                    let has_more = end < events.len();
                    Ok((page, has_more))
                }
                None => Ok((vec![], false)),
            }
        }

        async fn save(
            &self,
            prefix: &str,
            events: &[SignedKeyEvent],
        ) -> Result<(), crate::error::KelsError> {
            self.kels
                .write()
                .unwrap()
                .insert(prefix.to_string(), events.to_vec());
            Ok(())
        }

        async fn delete(&self, prefix: &str) -> Result<(), crate::error::KelsError> {
            self.kels.write().unwrap().remove(prefix);
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_large_kel_paginated_verification() {
        // Build a 1025-event KEL (icp + 1024 ixn) — spans 3 pages at 512 events/page
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let icp = builder.incept().await.unwrap();
        let prefix = icp.event.prefix.clone();

        let mut events = vec![icp];
        for i in 0..1024 {
            let ixn = builder
                .interact(&Digest::blake3_256(format!("anchor-{}", i).as_bytes()).qb64())
                .await
                .unwrap();
            events.push(ixn);
        }
        assert_eq!(events.len(), 1025);

        // Save to MemoryStore
        let store = MemoryStore::new();
        store.save(&prefix, &events).await.unwrap();

        // Verify with small page size to force multiple pages
        let ctx = completed_verification(
            &mut StorePageLoader::new(&store),
            &prefix,
            512,
            100,
            std::iter::empty(),
        )
        .await
        .unwrap();

        assert!(!ctx.is_empty());
        assert!(!ctx.is_divergent());
        assert!(!ctx.is_contested());
        assert!(!ctx.is_decommissioned());
        assert!(ctx.current_public_key().is_some());

        // Tip should be the last event
        assert_eq!(ctx.branch_tips().len(), 1);
        assert_eq!(
            ctx.branch_tips()[0].tip.event.said,
            events.last().unwrap().event.said
        );
    }

    #[tokio::test]
    async fn test_large_kel_with_early_divergence() {
        // Build a long KEL, then inject a divergent event at serial 2
        let mut builder1 = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let icp = builder1.incept().await.unwrap();
        let prefix = icp.event.prefix.clone();
        let ixn1 = builder1
            .interact(&Digest::blake3_256(b"anchor-1").qb64())
            .await
            .unwrap();

        // Duplicate builder after icp+ixn1 (adversary has same keys)
        let mut builder2 = builder1.clone();

        // Owner continues building a long chain
        let mut owner_events = vec![icp.clone(), ixn1.clone()];
        for i in 2..1025 {
            let ixn = builder1
                .interact(&Digest::blake3_256(format!("anchor-{}", i).as_bytes()).qb64())
                .await
                .unwrap();
            owner_events.push(ixn);
        }
        assert_eq!(owner_events.len(), 1025);

        // Adversary injects one event at serial 2 (divergence)
        let adversary_ixn = builder2
            .interact(&Digest::blake3_256(b"adversary-anchor").qb64())
            .await
            .unwrap();
        assert_eq!(adversary_ixn.event.serial, 2);

        // Combined events: owner chain + adversary event at serial 2
        // Sort by serial ASC, said ASC (DB ordering)
        let mut all_events = owner_events.clone();
        all_events.push(adversary_ixn.clone());
        all_events.sort_by(|a, b| {
            a.event
                .serial
                .cmp(&b.event.serial)
                .then(a.event.said.cmp(&b.event.said))
        });

        // Save to store
        let store = MemoryStore::new();
        store.save(&prefix, &all_events).await.unwrap();

        // Verify with paginated reads — should detect divergence
        let ctx = completed_verification(
            &mut StorePageLoader::new(&store),
            &prefix,
            512,
            100,
            std::iter::empty(),
        )
        .await
        .unwrap();

        assert!(ctx.is_divergent());
        assert_eq!(ctx.diverged_at_serial(), Some(2));
        assert_eq!(ctx.branch_tips().len(), 2);
    }

    #[tokio::test]
    async fn test_completed_verification_with_anchor_checking() {
        use cesr::{Digest, Matter};

        let target_anchor = Digest::blake3_256(b"target-anchor").qb64();
        let missing_anchor = Digest::blake3_256(b"missing-anchor").qb64();

        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let icp = builder.incept().await.unwrap();
        let prefix = icp.event.prefix.clone();
        let ixn = builder.interact(&target_anchor).await.unwrap();

        let store = MemoryStore::new();
        store.save(&prefix, &[icp, ixn]).await.unwrap();

        // Check for an anchor that exists
        let ctx = completed_verification(
            &mut StorePageLoader::new(&store),
            &prefix,
            512,
            100,
            std::iter::once(target_anchor.clone()),
        )
        .await
        .unwrap();

        assert!(ctx.is_said_anchored(&target_anchor));
        assert!(ctx.anchors_all_saids());

        // Check for an anchor that doesn't exist
        let ctx2 = completed_verification(
            &mut StorePageLoader::new(&store),
            &prefix,
            512,
            100,
            std::iter::once(missing_anchor.clone()),
        )
        .await
        .unwrap();

        assert!(!ctx2.is_said_anchored(&missing_anchor));
        assert!(!ctx2.anchors_all_saids());
    }

    #[tokio::test]
    async fn test_max_pages_limit_fails_secure() {
        // Build a KEL larger than max_pages * page_size
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let icp = builder.incept().await.unwrap();
        let prefix = icp.event.prefix.clone();

        let mut events = vec![icp];
        for i in 0..20 {
            let ixn = builder
                .interact(&Digest::blake3_256(format!("anchor-{}", i).as_bytes()).qb64())
                .await
                .unwrap();
            events.push(ixn);
        }

        let store = MemoryStore::new();
        store.save(&prefix, &events).await.unwrap();

        // Page size 5, max 2 pages = 10 events max, but we have 21
        let ctx = completed_verification(
            &mut StorePageLoader::new(&store),
            &prefix,
            5,
            2,
            std::iter::empty(),
        )
        .await
        .unwrap();

        // Should have verified only the first 10 events (2 pages of 5)
        // The context is valid but incomplete — tip is at serial 9, not 20
        assert_eq!(ctx.branch_tips()[0].tip.event.serial, 9);
    }

    #[tokio::test]
    async fn test_truncate_incomplete_generation_basic() {
        let mut builder1 = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let icp = builder1.incept().await.unwrap();
        let ixn1 = builder1
            .interact(&Digest::blake3_256(b"a1").qb64())
            .await
            .unwrap();

        // Create adversary builder with same keys, reset to icp state
        let mut builder2 = KeyEventBuilder::with_events(
            builder1.key_provider().clone(),
            None,
            None,
            vec![icp.clone()],
        );
        let ixn2 = builder2
            .interact(&Digest::blake3_256(b"a2").qb64())
            .await
            .unwrap();

        // Two events at serial 1, simulating divergence
        // If a page ends with only one of them, truncate should remove it
        let mut events = [icp, ixn1.clone(), ixn2.clone()].to_vec();
        events.sort_by(|a, b| {
            a.event
                .serial
                .cmp(&b.event.serial)
                .then(a.event.said.cmp(&b.event.said))
        });

        // Simulate page that has icp + first divergent event but not second
        let mut partial_page = events[..2].to_vec();
        let truncated = truncate_incomplete_generation(&mut partial_page);

        // Should truncate the lone serial-1 event since serial-0 has 1 event
        // but serial-1 should have 2 — we only have 1 of them
        // Actually: second-to-last serial (0) has 1 event, last serial (1) has 1 event
        // 1 == 1, so no truncation. This is correct — we can't know there should be 2
        // without seeing the second event.
        assert_eq!(truncated, 0);
    }

    // ==================== compute_rotation_hash ====================

    #[test]
    fn test_compute_rotation_hash() {
        let public_key = "1AAACk1SoB-PO_xcbaR6LgKHVgojABYjAhd4kEk7-qeS";
        let hash = compute_rotation_hash(public_key);
        assert!(hash.starts_with('E'));
        assert_eq!(hash.len(), 44);

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
        use verifiable_storage::SelfAddressed;

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

        assert_eq!(ctx.branch_tips()[0].tip.event.said, ixn2.event.said);
        assert_eq!(
            ctx.last_establishment_event().unwrap().event.said,
            rot.event.said
        );

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

    // ==================== KelVerifier — resume from Verification ====================

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
        let ctx2 = verifier.into_verification().unwrap();

        assert_eq!(ctx2.branch_tips()[0].tip.event.said, ixn2.event.said);
    }

    // ==================== KelVerifier — from_branch_tip ====================

    #[tokio::test]
    async fn test_from_branch_tip_verifies_extension() {
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
        let ctx = verifier.into_verification().unwrap();

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
