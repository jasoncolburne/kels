//! Verification — proof-of-verification token for KEL state.
//!
//! `KelVerification` is the ONLY way to access verified KEL state. It cannot be
//! constructed directly — it must be obtained through `KelVerifier::into_verification()`.
//! Having a `KelVerification` proves the KEL was verified.

use std::{
    collections::{BTreeSet, HashMap},
    sync::Arc,
};

use cesr::{Digest, Matter, VerificationKey};
use serde::{Deserialize, Serialize};
use verifiable_storage::{Chained, SelfAddressed};

use super::event::SignedKeyEvent;
use crate::error::KelsError;

/// A verified branch endpoint: the chain head and its last establishment event.
///
/// For a non-divergent KEL, there is one `BranchTip`. For divergent KELs, there
/// is one per branch. The `establishment_tip` provides the crypto state (public key,
/// rotation hash, recovery hash) for that branch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchTip {
    /// The chain head — the latest event on this branch.
    pub tip: SignedKeyEvent,
    /// The last establishment event on this branch (provides signing key).
    pub establishment_tip: SignedKeyEvent,
}

/// Proof-of-verification token for KEL state.
///
/// Cannot be constructed directly — only via `KelVerifier::into_verification()`.
/// Having a `KelVerification` proves the KEL was fully verified. The SAID is a
/// content-addressable digest of the verified state — two `KelVerification`s with
/// the same SAID represent the same KEL state.
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[crate_new]
pub struct KelVerification {
    #[said]
    said: cesr::Digest,
    prefix: cesr::Digest,
    delegating_prefix: Option<cesr::Digest>,
    branch_tips: Vec<BranchTip>,
    is_contested: bool,
    diverged_at_serial: Option<u64>,
    event_count: usize,
    rotation_count: usize,
    anchored_saids: BTreeSet<cesr::Digest>,
    queried_saids: BTreeSet<cesr::Digest>,
    /// Whether the KEL maintains proactive recovery rotation compliance:
    /// no more than `MAX_NON_REVEALING_EVENTS` non-revealing events between
    /// consecutive recovery-revealing events. Required to ensure all server
    /// operations (archival, contest, recovery) are bounded to a single page.
    proactive_ror_compliant: bool,
    /// Non-revealing events since the last recovery-revealing event.
    /// Preserved across resume so incremental verification continues tracking.
    events_since_last_revealing: usize,
}

impl KelVerification {
    /// The SAID (content-addressable digest) of this verification state.
    pub fn said(&self) -> &cesr::Digest {
        &self.said
    }

    /// The prefix this context is for.
    pub fn prefix(&self) -> &cesr::Digest {
        &self.prefix
    }

    /// The delegating prefix from the inception event, if it was a `dip`.
    pub fn delegating_prefix(&self) -> Option<&cesr::Digest> {
        self.delegating_prefix.as_ref()
    }

    /// All verified branch endpoints.
    pub fn branch_tips(&self) -> &[BranchTip] {
        &self.branch_tips
    }

    /// Current public key from the last verified establishment event.
    /// Only meaningful for non-divergent KELs (single branch).
    pub fn current_public_key(&self) -> Option<&cesr::VerificationKey> {
        if self.branch_tips.len() == 1 {
            self.branch_tips[0]
                .establishment_tip
                .event
                .public_key
                .as_ref()
        } else {
            None
        }
    }

    /// The last verified establishment event.
    /// Only meaningful for non-divergent KELs (single branch).
    pub fn last_establishment_event(&self) -> Option<&SignedKeyEvent> {
        if self.branch_tips.len() == 1 {
            Some(&self.branch_tips[0].establishment_tip)
        } else {
            None
        }
    }

    /// Whether the KEL is divergent (multiple branches).
    pub fn is_divergent(&self) -> bool {
        self.branch_tips.len() > 1
    }

    /// Whether the KEL has been contested (permanently frozen).
    pub fn is_contested(&self) -> bool {
        self.is_contested
    }

    /// The lowest serial where divergence occurs (if divergent).
    pub fn diverged_at_serial(&self) -> Option<u64> {
        self.diverged_at_serial
    }

    /// The total number of verified events in the KEL.
    pub fn event_count(&self) -> usize {
        self.event_count
    }

    /// The number of rotation (rot/ror) events in the verified KEL.
    pub fn rotation_count(&self) -> usize {
        self.rotation_count
    }

    /// Whether the KEL has been decommissioned.
    /// True if contested, or if the single branch tip is a decommission event.
    pub fn is_decommissioned(&self) -> bool {
        self.is_contested
            || (self.branch_tips.len() == 1 && self.branch_tips[0].tip.event.decommissions())
    }

    /// Compute the effective tail SAID from verified tips.
    ///
    /// - Single branch: tip event SAID
    /// - Contested: `hash("contested:{prefix}")` — deterministic across all nodes
    /// - Divergent: `hash("divergent:{prefix}")` — deterministic regardless of which
    ///   fork events each node has, avoiding wasted anti-entropy sync attempts
    pub fn effective_tail_said(&self) -> Option<cesr::Digest> {
        if self.branch_tips.is_empty() {
            return None;
        }
        if self.branch_tips.len() == 1 {
            return Some(self.branch_tips[0].tip.event.said.clone());
        }
        if self.is_contested {
            let input = format!("contested:{}", self.prefix);
            return Some(crate::hash_effective_said(&input));
        }
        let input = format!("divergent:{}", self.prefix);
        Some(crate::hash_effective_said(&input))
    }

    /// Check if a specific SAID was found anchored in the verified KEL.
    pub fn is_said_anchored(&self, said: &cesr::Digest) -> bool {
        self.anchored_saids.contains(said)
    }

    /// The full set of verified anchored SAIDs.
    pub fn anchored_saids(&self) -> &BTreeSet<cesr::Digest> {
        &self.anchored_saids
    }

    /// Whether all queried SAIDs were found anchored.
    pub fn anchors_all_saids(&self) -> bool {
        self.queried_saids.is_subset(&self.anchored_saids)
    }

    /// Whether the KEL maintains proactive recovery rotation compliance.
    pub fn is_proactive_ror_compliant(&self) -> bool {
        self.proactive_ror_compliant
    }

    /// Non-revealing events since the last recovery-revealing event.
    pub fn events_since_last_revealing(&self) -> usize {
        self.events_since_last_revealing
    }

    /// Whether the KEL is empty (no events).
    pub fn is_empty(&self) -> bool {
        self.branch_tips.is_empty()
    }
}
/// Compute the rotation hash (Blake3-256 of the public key qb64 string).
pub fn compute_rotation_hash(public_key: &VerificationKey) -> cesr::Digest {
    Digest::blake3_256(public_key.qb64().as_bytes())
}

/// Per-branch cryptographic state tracked during verification.
#[derive(Clone)]
struct BranchState {
    tip: Arc<SignedKeyEvent>,
    establishment_tip: Arc<SignedKeyEvent>,
    current_public_key: VerificationKey,
    pending_rotation_hash: Option<cesr::Digest>,
    pending_recovery_hash: Option<cesr::Digest>,
    /// Non-revealing events since the last recovery-revealing event on this branch.
    events_since_last_revealing: usize,
}

fn branch_state_from_tip(
    tip: &BranchTip,
    events_since_last_revealing: usize,
) -> Result<(cesr::Digest, BranchState), KelsError> {
    let pk = tip
        .establishment_tip
        .event
        .public_key
        .as_ref()
        .ok_or_else(|| {
            KelsError::InvalidKel("Branch tip establishment event has no public key".into())
        })?;

    Ok((
        tip.tip.event.said.clone(),
        BranchState {
            tip: Arc::new(tip.tip.clone()),
            establishment_tip: Arc::new(tip.establishment_tip.clone()),
            current_public_key: pk.clone(),
            pending_rotation_hash: tip.establishment_tip.event.rotation_hash.clone(),
            pending_recovery_hash: tip.establishment_tip.event.recovery_hash.clone(),
            events_since_last_revealing,
        },
    ))
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
/// Events MUST be fed in `serial ASC, kind sort_priority ASC, said ASC` order with complete generations
/// (all events at a given serial must be in the same page). Use
/// `truncate_incomplete_generation()` to ensure this at page boundaries.
///
/// After verification, call `into_verification()` to produce a `KelVerification`
/// (proof-of-verification token).
pub struct KelVerifier {
    prefix: cesr::Digest,
    /// Delegating prefix from the inception event, if it was a `dip`.
    delegating_prefix: Option<cesr::Digest>,
    /// Pre-divergence: single branch state. Branches keyed by tip SAID.
    branches: HashMap<cesr::Digest, BranchState>,
    /// The current serial we've verified up to.
    last_verified_serial: Option<u64>,
    /// Serial where divergence first occurred.
    diverged_at_serial: Option<u64>,
    /// Whether a contest event has been seen.
    is_contested: bool,
    /// Total number of verified events.
    event_count: usize,
    /// Number of rotation (rot/ror) events seen.
    rotation_count: usize,
    /// Anchor checking: SAIDs we're looking for.
    queried_saids: BTreeSet<cesr::Digest>,
    /// Anchor checking: SAIDs we've found anchored.
    anchored_saids: BTreeSet<cesr::Digest>,
    /// Non-revealing events since the last recovery-revealing event.
    events_since_last_revealing: usize,
    /// Whether the proactive ror interval has been violated.
    proactive_ror_compliant: bool,
    /// Optional: collect establishment keys at specific serials during verification.
    requested_establishment_serials: BTreeSet<u64>,
    /// Collected establishment keys (serial → parsed VerificationKey).
    collected_establishment_keys: HashMap<u64, VerificationKey>,
}

impl KelVerifier {
    /// Start from inception. Used for full verification (e.g., streaming a peer's KEL).
    pub fn new(prefix: &cesr::Digest) -> Self {
        Self {
            prefix: prefix.clone(),
            delegating_prefix: None,
            branches: HashMap::new(),
            last_verified_serial: None,
            diverged_at_serial: None,
            is_contested: false,
            event_count: 0,
            rotation_count: 0,
            queried_saids: BTreeSet::new(),
            anchored_saids: BTreeSet::new(),
            events_since_last_revealing: 0,
            proactive_ror_compliant: true,
            requested_establishment_serials: BTreeSet::new(),
            collected_establishment_keys: HashMap::new(),
        }
    }

    /// Request that establishment keys at the given serials be collected during
    /// verification. The keys are available after verification via
    /// `KelVerification::establishment_key_at()`.
    ///
    /// Bounded: rejects if more than `max` serials are requested.
    pub fn with_establishment_key_collection(
        mut self,
        serials: BTreeSet<u64>,
        max: usize,
    ) -> Result<Self, KelsError> {
        if serials.len() > max {
            return Err(KelsError::InvalidKel(format!(
                "Too many establishment serials requested: {} (max {})",
                serials.len(),
                max
            )));
        }
        self.requested_establishment_serials = serials;
        Ok(self)
    }

    /// Start verification from a single verified branch tip.
    ///
    /// Used for divergence/recovery scenarios where events need to be verified
    /// against a specific branch (not all branches). Creates a single-branch
    /// verifier from the branch tip's crypto state.
    /// `delegating_prefix` is not needed here — this is only used by the
    /// merge path for verifying new events against an existing branch, which
    /// does not produce verifications consumed for delegation checks.
    /// Delegation-aware verification always starts from inception via `new()`.
    pub fn from_branch_tip(
        prefix: &cesr::Digest,
        tip: &BranchTip,
        events_since_last_revealing: usize,
    ) -> Result<Self, KelsError> {
        let mut branches = HashMap::new();

        let (said, state) = branch_state_from_tip(tip, events_since_last_revealing)?;
        branches.insert(said, state);

        let last_verified_serial = Some(tip.tip.event.serial);

        Ok(Self {
            prefix: prefix.clone(),
            delegating_prefix: None,
            branches,
            last_verified_serial,
            diverged_at_serial: None,
            is_contested: false,
            event_count: 0,
            rotation_count: 0,
            queried_saids: BTreeSet::new(),
            anchored_saids: BTreeSet::new(),
            events_since_last_revealing,
            proactive_ror_compliant: true,
            requested_establishment_serials: BTreeSet::new(),
            collected_establishment_keys: HashMap::new(),
        })
    }

    /// Resume from a verified `KelVerification`.
    pub fn resume(
        prefix: &cesr::Digest,
        kel_verification: &KelVerification,
    ) -> Result<Self, KelsError> {
        let mut branches = HashMap::new();

        let since_revealing_count = kel_verification.events_since_last_revealing();
        for bt in kel_verification.branch_tips() {
            let (said, state) = branch_state_from_tip(bt, since_revealing_count)?;
            branches.insert(said, state);
        }

        let last_verified_serial = kel_verification
            .branch_tips()
            .iter()
            .map(|bt| bt.tip.event.serial)
            .max();

        Ok(Self {
            prefix: prefix.clone(),
            delegating_prefix: kel_verification.delegating_prefix().cloned(),
            branches,
            last_verified_serial,
            diverged_at_serial: kel_verification.diverged_at_serial(),
            is_contested: kel_verification.is_contested(),
            event_count: kel_verification.event_count(),
            rotation_count: kel_verification.rotation_count(),
            queried_saids: BTreeSet::new(),
            anchored_saids: BTreeSet::new(),
            events_since_last_revealing: kel_verification.events_since_last_revealing(),
            proactive_ror_compliant: kel_verification.is_proactive_ror_compliant(),
            requested_establishment_serials: BTreeSet::new(),
            collected_establishment_keys: HashMap::new(),
        })
    }

    /// Register SAIDs to check for anchoring during verification.
    ///
    /// Call this before `verify_page()`. As the verifier walks events, it checks
    /// each `ixn` event's `anchor` field against these SAIDs. Results are available
    /// via `KelVerification::anchored_saids()` after calling `into_verification()`.
    pub fn check_anchors(&mut self, saids: impl IntoIterator<Item = cesr::Digest>) {
        self.queried_saids.extend(saids);
    }

    /// Whether the KEL maintains proactive recovery rotation compliance.
    pub fn is_proactive_ror_compliant(&self) -> bool {
        self.proactive_ror_compliant
    }

    /// The current public key after the last verified establishment event.
    /// Only meaningful for non-divergent KELs (single branch).
    pub fn current_public_key(&self) -> Option<&VerificationKey> {
        if self.branches.len() == 1 {
            self.branches.values().next().map(|b| &b.current_public_key)
        } else {
            None
        }
    }

    /// Verify a page of events against the running state.
    ///
    /// Events must be sorted `serial ASC, kind sort_priority ASC, said ASC` and complete generations
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

        self.event_count += events.len();

        Ok(())
    }

    /// Consume the verifier and produce a `KelVerification` plus any collected
    /// establishment keys (serial → public_key qb64). Keys are only populated if
    /// `with_establishment_key_collection` was called before verification.
    pub fn into_verification_with_keys(
        self,
    ) -> Result<(KelVerification, HashMap<u64, VerificationKey>), KelsError> {
        let keys = self.collected_establishment_keys.clone();
        let verification = self.into_verification()?;
        Ok((verification, keys))
    }

    /// Consume the verifier and produce a `KelVerification` (proof-of-verification token).
    pub fn into_verification(self) -> Result<KelVerification, KelsError> {
        // Derive global events_since_last_revealing from the max across branches.
        // This is the most conservative value — the branch closest to the limit.
        let events_since_last_revealing = self
            .branches
            .values()
            .map(|bs| bs.events_since_last_revealing)
            .max()
            .unwrap_or(self.events_since_last_revealing);

        let mut branch_tips: Vec<BranchTip> = self
            .branches
            .into_values()
            .map(|bs| BranchTip {
                tip: Arc::unwrap_or_clone(bs.tip),
                establishment_tip: Arc::unwrap_or_clone(bs.establishment_tip),
            })
            .collect();

        // Deterministic ordering for SAID derivation
        branch_tips.sort_by(|a, b| a.tip.event.said.cmp(&b.tip.event.said));

        let mut kel_verification = KelVerification::new(
            self.prefix,
            self.delegating_prefix,
            branch_tips,
            self.is_contested,
            self.diverged_at_serial,
            self.event_count,
            self.rotation_count,
            self.anchored_saids,
            self.queried_saids,
            self.proactive_ror_compliant,
            events_since_last_revealing,
        );
        kel_verification
            .derive_said()
            .map_err(|e| KelsError::InvalidKel(format!("SAID derivation failed: {}", e)))?;
        Ok(kel_verification)
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
            // Collect establishment key at serial 0 if requested
            if self.requested_establishment_serials.contains(&0)
                && let Some(ref pk) = event.event.public_key
            {
                self.collected_establishment_keys.insert(0, pk.clone());
            }
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

        // Invariant: max 2 events per generation. The DB submission logic
        // (handle_overlap_submission) only inserts one divergent event, so the DB
        // can never have more than 2 events at the same serial. Reject anything
        // else as invalid — the DB cannot be trusted.
        if events.len() > 2 {
            return Err(KelsError::InvalidKel(format!(
                "Generation at serial {} has {} events, max 2 allowed",
                serial,
                events.len()
            )));
        }

        // Invariant: after divergence, only 1 event per generation. Once divergent,
        // handle_divergent_submission only accepts rec/cnt. Recovery archives/deletes
        // adversary events. The shorter branch never extends beyond the divergence
        // point — it is always exactly 1 event.
        if let Some(div_serial) = self.diverged_at_serial
            && serial > div_serial
            && events.len() > 1
        {
            return Err(KelsError::InvalidKel(format!(
                "Generation at serial {} has {} events after divergence at serial {}",
                serial,
                events.len(),
                div_serial
            )));
        }

        // Detect divergence: more events than branches means new fork
        let num_branches = self.branches.len();
        if events.len() > num_branches && self.diverged_at_serial.is_none() {
            self.diverged_at_serial = Some(serial);
        }

        // Match each event to its branch via `previous` pointer
        let mut new_branches: HashMap<cesr::Digest, BranchState> = HashMap::new();

        for event in events {
            let previous = event.event.previous.as_ref().ok_or_else(|| {
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

            // Collect establishment key at this serial if requested
            if event.event.is_establishment()
                && self.requested_establishment_serials.contains(&serial)
                && let Some(ref pk) = event.event.public_key
            {
                self.collected_establishment_keys.insert(serial, pk.clone());
            }

            // Track anchor checking — exclude events in the divergent region.
            // Divergent events are untrusted (adversary may have forged anchors),
            // so only pre-divergence anchors are recorded.
            if self.diverged_at_serial.is_none_or(|ds| serial < ds)
                && event.event.is_interaction()
                && let Some(ref anchor) = event.event.anchor
                && self.queried_saids.contains(anchor)
            {
                self.anchored_saids.insert(anchor.clone());
            }

            // Track contested
            if event.event.is_contest() {
                self.is_contested = true;
            }

            // Track rotation count
            if event.event.reveals_rotation_key() {
                self.rotation_count += 1;
            }

            // Track proactive ror compliance (per-branch)
            if new_state.events_since_last_revealing > crate::MAX_NON_REVEALING_EVENTS {
                self.proactive_ror_compliant = false;
            }

            new_branches.insert(event.event.said.clone(), new_state);
        }

        // In a divergent KEL, one branch may be shorter than the other.
        // Keep un-extended branches as-is (they have no event at this serial).
        for (said, state) in &self.branches {
            if events
                .iter()
                .any(|e| e.event.previous.as_ref() == Some(said))
            {
                continue;
            }
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

        let public_key = event.public_key.as_ref().ok_or_else(|| {
            KelsError::InvalidKel("Establishment event missing public key".to_string())
        })?;

        // Verify signature with the event's own public key
        Self::verify_signatures(signed_event, public_key)?;

        // Capture delegating prefix from dip events
        self.delegating_prefix = event.delegating_prefix.clone();

        // Initialize branch
        let arc_event = Arc::new(signed_event.clone());
        self.branches.insert(
            event.said.clone(),
            BranchState {
                tip: Arc::clone(&arc_event),
                establishment_tip: arc_event,
                current_public_key: public_key.clone(),
                pending_rotation_hash: event.rotation_hash.clone(),
                pending_recovery_hash: event.recovery_hash.clone(),
                events_since_last_revealing: 0,
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
            let public_key = event.public_key.as_ref().ok_or_else(|| {
                KelsError::InvalidKel("Establishment event missing public key".to_string())
            })?;

            // Verify forward commitment
            if let Some(ref rotation_hash) = branch.pending_rotation_hash {
                let computed = compute_rotation_hash(public_key);
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
            Self::verify_signatures(signed_event, public_key)?;

            let events_since_last_revealing = if event.reveals_recovery_key() {
                0
            } else {
                branch.events_since_last_revealing + 1
            };

            let arc_event = Arc::new(signed_event.clone());
            Ok(BranchState {
                tip: Arc::clone(&arc_event),
                establishment_tip: arc_event,
                current_public_key: public_key.clone(),
                pending_rotation_hash: event.rotation_hash.clone(),
                pending_recovery_hash: event.recovery_hash.clone(),
                events_since_last_revealing,
            })
        } else {
            // Non-establishment: verify with branch's current public key
            Self::verify_signatures(signed_event, &branch.current_public_key)?;

            Ok(BranchState {
                tip: Arc::new(signed_event.clone()),
                establishment_tip: Arc::clone(&branch.establishment_tip),
                current_public_key: branch.current_public_key.clone(),
                pending_rotation_hash: branch.pending_rotation_hash.clone(),
                pending_recovery_hash: branch.pending_recovery_hash.clone(),
                events_since_last_revealing: branch.events_since_last_revealing + 1,
            })
        }
    }

    /// SAID integrity + prefix match + structure validation.
    fn verify_event_basics(&self, event: &super::event::KeyEvent) -> Result<(), KelsError> {
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
        public_key: &VerificationKey,
    ) -> Result<(), KelsError> {
        let event = &signed_event.event;

        let sig = signed_event.signature("signing").ok_or_else(|| {
            KelsError::InvalidKel(format!("Event {} has no signing signature", &event.said,))
        })?;

        public_key
            .verify(event.said.qb64().as_bytes(), &sig.signature)
            .map_err(|_| {
                KelsError::InvalidKel(format!(
                    "Event {} signature verification failed",
                    &event.said,
                ))
            })?;

        // Dual-signature requirement for recovery events
        if event.reveals_recovery_key() {
            let recovery_key = event.recovery_key.as_ref().ok_or_else(|| {
                KelsError::InvalidKel(format!(
                    "Recovery event {} has no recovery_key field",
                    &event.said,
                ))
            })?;

            let recovery_sig = signed_event.signature("recovery").ok_or_else(|| {
                KelsError::InvalidKel(format!(
                    "Recovery event {} has no recovery signature",
                    &event.said,
                ))
            })?;

            recovery_key
                .verify(event.said.qb64().as_bytes(), &recovery_sig.signature)
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
/// Events are expected in `serial ASC, kind sort_priority ASC, said ASC` order. If the last serial has
/// fewer events than the second-to-last, the incomplete generation is removed.
/// Returns the number of events truncated (caller should not advance the offset
/// past these).
///
/// **Limitation:** Cannot detect an incomplete generation at the linear-to-divergent
/// transition — a divergent pair (count 2) whose first page only includes one event
/// looks identical to a normal linear event (count 1). `transfer_key_events` handles
/// this via the held-back event strategy instead of relying on this function.
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
