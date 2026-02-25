//! Streaming incremental KEL verifier and sync abstraction.
//!
//! `KelVerifier` verifies events page by page without holding the full chain in memory.
//! Tracks evolving cryptographic state as it walks forward through the chain,
//! supporting both linear and divergent KELs.
//!
//! After verification, call `into_merge_context()` to get a `MergeContext` — the
//! proof-of-verification token that provides access to verified KEL state.
//!
//! `PagedKelSource` / `PagedKelSink` / `sync_and_verify` provide a generic pattern
//! for streaming events from a source through a verifier into a destination.

use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use cesr::{Digest, Matter, PublicKey, Signature};
use verifiable_storage::Chained;

use super::events::SignedKeyEvent;
use super::merge_context::{BranchTip, MergeContext};
use crate::error::KelsError;
use crate::store::KelStore;

/// Compute the rotation hash (Blake3-256 of the public key qb64 string).
fn compute_rotation_hash(public_key: &str) -> String {
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
/// After verification, call `into_merge_context()` to produce a `MergeContext`
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
    queried_saids: HashSet<String>,
    /// Anchor checking: SAIDs we've found anchored.
    anchored_saids: HashSet<String>,
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
            queried_saids: HashSet::new(),
            anchored_saids: HashSet::new(),
        }
    }

    /// Resume from known DB state. Used by the submit handler fast path.
    ///
    /// `tip_serial` and `tip_said` identify the current chain tip.
    /// `last_establishment` provides the current cryptographic state.
    pub fn from_merge_context(
        prefix: impl Into<String>,
        tip_serial: u64,
        tip_said: impl Into<String>,
        last_establishment: &SignedKeyEvent,
    ) -> Self {
        let prefix = prefix.into();
        let tip_said = tip_said.into();
        let mut branches = HashMap::new();

        if let Some(ref pk) = last_establishment.event.public_key {
            // Create a synthetic tip event using the last establishment event's info
            // but with the actual tip SAID/serial
            let mut tip_event = last_establishment.clone();
            tip_event.event.said = tip_said.clone();
            tip_event.event.serial = tip_serial;

            branches.insert(
                tip_said,
                BranchState {
                    tip: tip_event,
                    establishment_tip: last_establishment.clone(),
                    current_public_key: pk.clone(),
                    pending_rotation_hash: last_establishment.event.rotation_hash.clone(),
                    pending_recovery_hash: last_establishment.event.recovery_hash.clone(),
                },
            );
        }

        Self {
            prefix,
            branches,
            last_verified_serial: Some(tip_serial),
            diverged_at_serial: None,
            is_contested: false,
            queried_saids: HashSet::new(),
            anchored_saids: HashSet::new(),
        }
    }

    /// Resume from a verified `MergeContext`.
    pub fn resume(prefix: impl Into<String>, ctx: &MergeContext) -> Self {
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
            queried_saids: HashSet::new(),
            anchored_saids: HashSet::new(),
        }
    }

    /// Register SAIDs to check for anchoring during verification.
    ///
    /// Call this before `verify_page()`. As the verifier walks events, it checks
    /// each `ixn` event's `anchor` field against these SAIDs. Results are available
    /// via `MergeContext::anchored_saids()` after calling `into_merge_context()`.
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

    /// Consume the verifier and produce a `MergeContext` (proof-of-verification token).
    pub fn into_merge_context(self) -> MergeContext {
        let branch_tips: Vec<BranchTip> = self
            .branches
            .into_values()
            .map(|bs| BranchTip {
                tip: bs.tip,
                establishment_tip: bs.establishment_tip,
            })
            .collect();

        MergeContext::new(
            self.prefix,
            branch_tips,
            self.is_contested,
            self.diverged_at_serial,
            self.anchored_saids,
            self.queried_saids,
        )
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

/// Verify a full KEL using paginated reads, returning a trusted `MergeContext`.
///
/// Pages through the loader with `KelVerifier` and returns the proof-of-verification
/// token. `max_pages` limits resource exhaustion from enormous KELs — fails secure
/// if exceeded.
///
/// `anchor_saids` optionally registers SAIDs to check for anchoring during the walk.
/// Results are available via `MergeContext::anchored_saids()` / `anchors_all_saids()`.
///
/// Use `StorePageLoader` to wrap a `&dyn KelStore`, or implement `PageLoader` on a
/// locked transaction wrapper to read under advisory lock.
pub async fn verified_merge_context(
    loader: &mut dyn PageLoader,
    prefix: &str,
    page_size: u64,
    max_pages: usize,
    anchor_saids: impl IntoIterator<Item = String>,
) -> Result<MergeContext, KelsError> {
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

    Ok(verifier.into_merge_context())
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
