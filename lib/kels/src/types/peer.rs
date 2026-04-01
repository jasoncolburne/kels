//! Peer allowlist & federation

#![allow(clippy::too_many_arguments)]

use std::collections::HashSet;

use cesr::{Matter, Signature, VerificationKey};
use serde::{Deserialize, Serialize};
use verifiable_storage::{Chained, SelfAddressed, StorageDatetime};

use super::KelVerification;
use crate::KelsError;

/// Validate that a timestamp is within the acceptable window.
///
/// Uses asymmetric bounds: allows up to 5 seconds of clock skew into the future,
/// but the full `max_age_secs` into the past. This prevents attackers from
/// pre-signing requests with far-future timestamps for delayed replay.
pub fn validate_timestamp(timestamp: i64, max_age_secs: i64) -> bool {
    let now = chrono::Utc::now().timestamp();
    let max_future_skew = 5;
    timestamp <= now + max_future_skew && timestamp >= now - max_age_secs
}

/// Minimum number of rejection votes required to kill a proposal.
///
/// Two rejections prevents a lone actor from blocking proposals, while keeping
/// the coordination bar low enough to stop collusion quickly once detected.
/// See `docs/rejection-threshold.md` for full rationale.
pub const REJECTION_THRESHOLD: usize = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedRequest<T> {
    pub payload: T,
    pub peer_prefix: String,
    pub signature: String,
}

impl<T: Serialize> SignedRequest<T> {
    /// Verify the request signature against a verified KEL context.
    ///
    /// Uses the current public key from the `KelVerification` (proof-of-verification token).
    /// Fails secure if the KEL is divergent (no unambiguous key).
    pub fn verify_signature(&self, kel_verification: &KelVerification) -> Result<(), KelsError> {
        if kel_verification.is_divergent() {
            return Err(KelsError::Divergent);
        }

        let public_key_qb64 = kel_verification
            .current_public_key()
            .ok_or_else(|| KelsError::VerificationFailed("No public key in verified KEL".into()))?;

        let public_key = VerificationKey::from_qb64(public_key_qb64)
            .map_err(|e| KelsError::VerificationFailed(format!("Invalid public key: {}", e)))?;

        let signature = Signature::from_qb64(&self.signature)
            .map_err(|e| KelsError::VerificationFailed(format!("Invalid signature: {}", e)))?;

        let payload_json = serde_json::to_vec(&self.payload)?;

        public_key
            .verify(&payload_json, &signature)
            .map_err(|_| KelsError::SignatureVerificationFailed)?;

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
#[storable(table = "peer")]
#[serde(rename_all = "camelCase")]
pub struct Peer {
    #[said]
    pub said: String,
    #[prefix]
    pub prefix: String,
    #[previous]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous: Option<String>,
    #[version]
    pub version: u64,
    #[created_at]
    pub created_at: StorageDatetime,
    pub peer_prefix: String,
    pub node_id: String,
    pub authorizing_kel: String,
    pub active: bool,
    /// Base domain for service discovery (e.g., "kels-node-a.kels").
    /// Derive service URLs: http://kels.{base_domain}, http://kels-sadstore.{base_domain}
    pub base_domain: String,
    /// Gossip address (host:port)
    pub gossip_addr: String,
}

impl Peer {
    pub fn deactivate(&self) -> Result<Self, verifiable_storage::StorageError> {
        let mut peer = self.clone();
        peer.active = false;
        peer.increment()?;
        Ok(peer)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerHistory {
    pub prefix: String,
    pub records: Vec<Peer>,
}

impl PeerHistory {
    /// Verify peer records against verified KEL contexts.
    pub fn verify_with_contexts(
        &self,
        trusted_prefixes: &HashSet<&'static str>,
        kel_verifications: &[&KelVerification],
    ) -> Result<(), KelsError> {
        for kel_verification in kel_verifications {
            if !trusted_prefixes.contains(kel_verification.prefix()) {
                return Err(KelsError::RegistryFailure(format!(
                    "Could not verify KEL {} as trusted",
                    kel_verification.prefix()
                )));
            }
        }

        self.verify_records()
    }

    fn verify_records(&self) -> Result<(), KelsError> {
        let mut last_said: Option<String> = None;
        for (i, peer_record) in self.records.iter().enumerate() {
            peer_record.verify()?;

            if let Some(said) = last_said {
                if let Some(previous) = peer_record.previous.clone() {
                    if previous != said {
                        return Err(KelsError::RegistryFailure(format!(
                            "Peer record {} previous doesn't match {}",
                            peer_record.said, said
                        )));
                    }
                } else {
                    return Err(KelsError::RegistryFailure(format!(
                        "Peer record {} is unchained from {}",
                        peer_record.said, said
                    )));
                }
            }

            if i as u64 != peer_record.version {
                return Err(KelsError::RegistryFailure(format!(
                    "Peer record {} has incorrect version {}",
                    peer_record.said, peer_record.version
                )));
            }

            last_said = Some(peer_record.said.clone());
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeersResponse {
    pub peers: Vec<PeerHistory>,
}

/// Status of a peer proposal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProposalStatus {
    /// Proposal is waiting for votes.
    Pending,
    /// Threshold met, peer was added/removed.
    Approved,
    /// Proposal was rejected (majority rejected or expired).
    Rejected,
    /// Proposal was withdrawn by proposer.
    Withdrawn,
}

impl std::fmt::Display for ProposalStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProposalStatus::Pending => write!(f, "Pending"),
            ProposalStatus::Approved => write!(f, "Approved"),
            ProposalStatus::Rejected => write!(f, "Rejected"),
            ProposalStatus::Withdrawn => write!(f, "Withdrawn"),
        }
    }
}

/// A vote on a proposal with a tamper-evident SAID.
///
/// Votes are simple self-addressed structs (not chained). Each vote is immutable
/// after creation. The `proposal` field binds this vote to a specific proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, SelfAddressed)]
pub struct Vote {
    /// Self-Addressing IDentifier - content hash for tamper evidence.
    #[said]
    pub said: String,
    /// The proposal prefix this vote is for (must match proposal.prefix).
    pub proposal: String,
    /// The voter's registry prefix.
    pub voter: String,
    /// Whether the voter approves (true) or rejects (false).
    pub approve: bool,
    /// When the vote was cast.
    #[created_at]
    pub voted_at: StorageDatetime,
}

/// Shared interface for proposal record types (addition and removal).
///
/// Provides default implementations for `proposal_id()`, `is_expired()`, and
/// `is_withdrawn()` based on accessor methods that each concrete type implements.
pub trait Proposal: Chained {
    fn proposal_said(&self) -> &str;
    fn proposal_prefix(&self) -> &str;
    fn proposal_previous(&self) -> Option<&str>;
    fn proposal_version(&self) -> u64;
    fn proposer(&self) -> &str;
    fn proposal_created_at(&self) -> &StorageDatetime;
    fn expires_at(&self) -> &StorageDatetime;
    fn withdrawn_at(&self) -> Option<&StorageDatetime>;

    fn proposal_id(&self) -> &str {
        self.proposal_prefix()
    }
    fn is_expired(&self) -> bool {
        StorageDatetime::now() > *self.expires_at()
    }
    fn is_withdrawn(&self) -> bool {
        self.withdrawn_at().is_some()
    }
}

/// Shared interface for proposal history types (chains of 1-2 records).
///
/// Provides a default `verify()` that checks structural integrity (SAID, prefix,
/// chain linkage, version monotonicity, proposer consistency, timestamps, withdrawal
/// validity). Also provides `is_withdrawn()`, `inception()`, and `latest()`.
pub trait ProposalHistory {
    type Record: Proposal;

    fn history_prefix(&self) -> &str;
    fn records(&self) -> &[Self::Record];
    /// Label for error messages, e.g. "Addition proposal" or "Removal proposal".
    fn label(&self) -> &str;

    fn verify(&self) -> Result<(), KelsError> {
        if self.records().is_empty() {
            return Err(KelsError::RegistryFailure(format!(
                "Empty {} chain",
                self.label().to_lowercase()
            )));
        }

        if self.records().len() > 2 {
            return Err(KelsError::RegistryFailure(format!(
                "{} chain has {} records, expected 1 or 2",
                self.label(),
                self.records().len()
            )));
        }

        let mut last_said: Option<String> = None;
        for (i, record) in self.records().iter().enumerate() {
            record.verify()?;

            if record.proposal_prefix() != self.history_prefix() {
                return Err(KelsError::RegistryFailure(format!(
                    "{} record {} prefix {} doesn't match chain prefix {}",
                    self.label(),
                    record.proposal_said(),
                    record.proposal_prefix(),
                    self.history_prefix()
                )));
            }

            if let Some(said) = &last_said {
                if record.proposal_previous() != Some(said.as_str()) {
                    return Err(KelsError::RegistryFailure(format!(
                        "{} record {} previous doesn't match {}",
                        self.label(),
                        record.proposal_said(),
                        said
                    )));
                }
            } else if record.proposal_previous().is_some() {
                return Err(KelsError::RegistryFailure(format!(
                    "First {} record {} has unexpected previous",
                    self.label().to_lowercase(),
                    record.proposal_said()
                )));
            }

            if i as u64 != record.proposal_version() {
                return Err(KelsError::RegistryFailure(format!(
                    "{} record {} has incorrect version {}",
                    self.label(),
                    record.proposal_said(),
                    record.proposal_version()
                )));
            }

            if record.proposer() != self.records()[0].proposer() {
                return Err(KelsError::RegistryFailure(format!(
                    "{} record {} proposer {} doesn't match inception proposer {}",
                    self.label(),
                    record.proposal_said(),
                    record.proposer(),
                    self.records()[0].proposer()
                )));
            }

            if i > 0
                && *record.proposal_created_at() <= *self.records()[i - 1].proposal_created_at()
            {
                return Err(KelsError::RegistryFailure(format!(
                    "{} record {} created_at is not after previous record",
                    self.label(),
                    record.proposal_said()
                )));
            }

            last_said = Some(record.proposal_said().to_string());
        }

        if self.records().len() == 2 && !self.records()[1].is_withdrawn() {
            return Err(KelsError::RegistryFailure(format!(
                "Second {} record must be a withdrawal",
                self.label().to_lowercase()
            )));
        }

        Ok(())
    }

    fn is_withdrawn(&self) -> bool {
        self.records().last().is_some_and(|r| r.is_withdrawn())
    }

    fn inception(&self) -> Option<&Self::Record> {
        self.records().first()
    }

    fn latest(&self) -> Option<&Self::Record> {
        self.records().last()
    }
}

/// Shared interface for proposal-with-votes types.
///
/// Provides default implementations for `verify()`, `status()`, vote counting,
/// and delegation to the underlying history.
pub trait ProposalWithVotesMethods {
    type History: ProposalHistory;

    fn history(&self) -> &Self::History;
    fn proposal_votes(&self) -> &[Vote];

    fn verify(&self) -> Result<(), KelsError> {
        self.history().verify()?;

        let proposal_prefix = self.history().history_prefix();

        let Some(inception) = self.history().inception() else {
            return Err(KelsError::RegistryFailure(format!(
                "Proposal {} has no inception record",
                proposal_prefix
            )));
        };
        let expires_at = inception.expires_at();

        for vote in self.proposal_votes() {
            vote.verify_said()?;

            if vote.proposal != *proposal_prefix {
                return Err(KelsError::RegistryFailure(format!(
                    "Vote {} references proposal {} but chain prefix is {}",
                    vote.said, vote.proposal, proposal_prefix
                )));
            }

            if vote.voted_at > *expires_at {
                return Err(KelsError::RegistryFailure(format!(
                    "Vote {} cast after proposal {} expired",
                    vote.said, proposal_prefix
                )));
            }
        }

        if self.history().is_withdrawn() && !self.proposal_votes().is_empty() {
            return Err(KelsError::RegistryFailure(format!(
                "Withdrawn {} {} has {} votes — tampered data",
                self.history().label().to_lowercase(),
                proposal_prefix,
                self.proposal_votes().len()
            )));
        }

        Ok(())
    }

    // Must call verify before using this, or results are not guaranteed
    fn status(&self, threshold: usize) -> ProposalStatus {
        if self.history().is_withdrawn() {
            return ProposalStatus::Withdrawn;
        }
        if self.rejection_count() >= REJECTION_THRESHOLD {
            return ProposalStatus::Rejected;
        }
        if self.approval_count() >= threshold {
            return ProposalStatus::Approved;
        }
        if self.is_expired() {
            return ProposalStatus::Rejected;
        }
        ProposalStatus::Pending
    }

    fn approval_count(&self) -> usize {
        self.proposal_votes().iter().filter(|v| v.approve).count()
    }

    fn rejection_count(&self) -> usize {
        self.proposal_votes().iter().filter(|v| !v.approve).count()
    }

    fn is_expired(&self) -> bool {
        self.history().inception().is_some_and(|p| p.is_expired())
    }

    fn proposal_id(&self) -> &str {
        self.history().history_prefix()
    }

    fn proposer(&self) -> Option<&str> {
        self.history().inception().map(|p| p.proposer())
    }

    fn voters(&self) -> Vec<&str> {
        self.proposal_votes()
            .iter()
            .map(|v| v.voter.as_str())
            .collect()
    }
}

/// A proposal to add a peer, requiring multi-party approval.
///
/// Uses chaining for tamper-evident audit trail:
/// - `prefix`: Stable proposal identifier (derived from inception) - use as proposal_id
/// - `said`: Changes with each update
/// - `previous`: Links to previous version for full history
///
/// Proposals are immutable after creation, except for withdrawal by the proposer.
/// Proposal chain: v0 (creation) → optionally v1 (withdrawal). No intermediate versions.
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
pub struct PeerAdditionProposal {
    /// Self-Addressing IDentifier - changes with each update.
    #[said]
    pub said: String,
    /// Stable proposal identifier (derived from inception SAID).
    #[prefix]
    pub prefix: String,
    /// SAID of previous version (None for inception).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[previous]
    pub previous: Option<String>,
    #[version]
    pub version: u64,
    /// The KELS prefix of the peer being proposed.
    pub peer_prefix: String,
    /// The node_id being proposed.
    pub node_id: String,
    pub base_domain: String,
    pub gossip_addr: String,
    pub proposer: String,
    /// Approval threshold at time of proposal creation.
    pub threshold: usize,
    /// When the proposal was created/updated.
    #[created_at]
    pub created_at: StorageDatetime,
    /// When the proposal expires.
    pub expires_at: StorageDatetime,
    /// If set, this proposal has been withdrawn by the proposer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub withdrawn_at: Option<StorageDatetime>,
}

impl PeerAdditionProposal {
    /// Create a new empty proposal (v0, no votes yet).
    ///
    /// The prefix (proposal ID) is derived from content - no UUID needed.
    /// The proposer must submit their vote separately via VotePeer.
    pub fn empty(
        peer_prefix: &str,
        node_id: &str,
        base_domain: &str,
        gossip_addr: &str,
        proposer: &str,
        threshold: usize,
        expires_at: &StorageDatetime,
    ) -> Result<Self, verifiable_storage::StorageError> {
        Self::create(
            peer_prefix.to_string(),
            node_id.to_string(),
            base_domain.to_string(),
            gossip_addr.to_string(),
            proposer.to_string(),
            threshold,
            expires_at.clone(),
            None,
        )
    }
}

impl Proposal for PeerAdditionProposal {
    fn proposal_said(&self) -> &str {
        &self.said
    }
    fn proposal_prefix(&self) -> &str {
        &self.prefix
    }
    fn proposal_previous(&self) -> Option<&str> {
        self.previous.as_deref()
    }
    fn proposal_version(&self) -> u64 {
        self.version
    }
    fn proposer(&self) -> &str {
        &self.proposer
    }
    fn proposal_created_at(&self) -> &StorageDatetime {
        &self.created_at
    }
    fn expires_at(&self) -> &StorageDatetime {
        &self.expires_at
    }
    fn withdrawn_at(&self) -> Option<&StorageDatetime> {
        self.withdrawn_at.as_ref()
    }
}

/// A proposal chain (1-2 records: v0 creation, optionally v1 withdrawal).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdditionHistory {
    pub prefix: String,
    pub records: Vec<PeerAdditionProposal>,
}

impl ProposalHistory for AdditionHistory {
    type Record = PeerAdditionProposal;

    fn history_prefix(&self) -> &str {
        &self.prefix
    }
    fn records(&self) -> &[PeerAdditionProposal] {
        &self.records
    }
    fn label(&self) -> &str {
        "Proposal"
    }
}

/// A completed addition proposal bundled with its votes (the full DAG).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdditionWithVotes {
    pub history: AdditionHistory,
    pub votes: Vec<Vote>,
}

impl ProposalWithVotesMethods for AdditionWithVotes {
    type History = AdditionHistory;

    fn history(&self) -> &AdditionHistory {
        &self.history
    }
    fn proposal_votes(&self) -> &[Vote] {
        &self.votes
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ProposalWithVotes {
    Addition(AdditionWithVotes),
    Removal(RemovalWithVotes),
}

/// A proposal to remove a peer, requiring multi-party approval.
#[derive(Debug, Clone, Serialize, Deserialize, SelfAddressed)]
pub struct PeerRemovalProposal {
    #[said]
    pub said: String,
    #[prefix]
    pub prefix: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[previous]
    pub previous: Option<String>,
    #[version]
    pub version: u64,
    pub peer_prefix: String,
    pub proposer: String,
    pub threshold: usize,
    #[created_at]
    pub created_at: StorageDatetime,
    pub expires_at: StorageDatetime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub withdrawn_at: Option<StorageDatetime>,
}

impl PeerRemovalProposal {
    pub fn empty(
        peer_prefix: &str,
        proposer: &str,
        threshold: usize,
        expires_at: &StorageDatetime,
    ) -> Result<Self, verifiable_storage::StorageError> {
        Self::create(
            peer_prefix.to_string(),
            proposer.to_string(),
            threshold,
            expires_at.clone(),
            None,
        )
    }
}

impl Proposal for PeerRemovalProposal {
    fn proposal_said(&self) -> &str {
        &self.said
    }
    fn proposal_prefix(&self) -> &str {
        &self.prefix
    }
    fn proposal_previous(&self) -> Option<&str> {
        self.previous.as_deref()
    }
    fn proposal_version(&self) -> u64 {
        self.version
    }
    fn proposer(&self) -> &str {
        &self.proposer
    }
    fn proposal_created_at(&self) -> &StorageDatetime {
        &self.created_at
    }
    fn expires_at(&self) -> &StorageDatetime {
        &self.expires_at
    }
    fn withdrawn_at(&self) -> Option<&StorageDatetime> {
        self.withdrawn_at.as_ref()
    }
}

/// A removal proposal chain (1-2 records: v0 creation, optionally v1 withdrawal).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemovalHistory {
    pub prefix: String,
    pub records: Vec<PeerRemovalProposal>,
}

impl ProposalHistory for RemovalHistory {
    type Record = PeerRemovalProposal;

    fn history_prefix(&self) -> &str {
        &self.prefix
    }
    fn records(&self) -> &[PeerRemovalProposal] {
        &self.records
    }
    fn label(&self) -> &str {
        "Removal proposal"
    }
}

/// A completed removal proposal bundled with its votes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemovalWithVotes {
    pub history: RemovalHistory,
    pub votes: Vec<Vote>,
}

impl ProposalWithVotesMethods for RemovalWithVotes {
    type History = RemovalHistory;

    fn history(&self) -> &RemovalHistory {
        &self.history
    }
    fn proposal_votes(&self) -> &[Vote] {
        &self.votes
    }
}

/// Response from the completed proposals endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompletedProposalsResponse {
    pub additions: Vec<AdditionWithVotes>,
    pub removals: Vec<RemovalWithVotes>,
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use verifiable_storage::{Chained, SelfAddressed};

    // ==================== validate_timestamp Tests ====================

    #[test]
    fn test_timestamp_current_is_valid() {
        let now = chrono::Utc::now().timestamp();
        assert!(validate_timestamp(now, 60));
    }

    #[test]
    fn test_timestamp_past_within_window() {
        let now = chrono::Utc::now().timestamp();
        assert!(validate_timestamp(now - 30, 60));
    }

    #[test]
    fn test_timestamp_past_outside_window() {
        let now = chrono::Utc::now().timestamp();
        assert!(!validate_timestamp(now - 61, 60));
    }

    #[test]
    fn test_timestamp_future_within_skew() {
        let now = chrono::Utc::now().timestamp();
        assert!(validate_timestamp(now + 3, 60));
    }

    #[test]
    fn test_timestamp_future_at_skew_boundary() {
        let now = chrono::Utc::now().timestamp();
        assert!(validate_timestamp(now + 5, 60));
    }

    #[test]
    fn test_timestamp_future_beyond_skew() {
        let now = chrono::Utc::now().timestamp();
        assert!(!validate_timestamp(now + 6, 60));
    }

    #[test]
    fn test_timestamp_far_future_rejected() {
        let now = chrono::Utc::now().timestamp();
        assert!(!validate_timestamp(now + 60, 60));
    }

    #[test]
    fn test_timestamp_past_at_boundary() {
        let now = chrono::Utc::now().timestamp();
        assert!(validate_timestamp(now - 60, 60));
    }

    fn test_expires_at() -> StorageDatetime {
        (chrono::Utc::now() + chrono::Duration::days(7)).into()
    }

    // ==================== AdditionHistory created_at monotonicity ====================

    #[test]
    fn test_addition_history_valid_timestamps() {
        let v0 = PeerAdditionProposal::empty(
            "peer-1",
            "node-1",
            "http://node-1:8080",
            "127.0.0.1:4001",
            "KRegistryA",
            2,
            &test_expires_at(),
        )
        .unwrap();

        let mut v1 = v0.clone();
        v1.withdrawn_at = Some(StorageDatetime::now());
        v1.increment().unwrap();

        let history = AdditionHistory {
            prefix: v0.prefix.clone(),
            records: vec![v0, v1],
        };
        assert!(history.verify().is_ok());
    }

    #[test]
    fn test_addition_history_non_monotonic_timestamp_fails() {
        let v0 = PeerAdditionProposal::empty(
            "peer-1",
            "node-1",
            "http://node-1:8080",
            "127.0.0.1:4001",
            "KRegistryA",
            2,
            &test_expires_at(),
        )
        .unwrap();

        let mut v1 = v0.clone();
        v1.withdrawn_at = Some(StorageDatetime::now());
        v1.increment().unwrap();
        // Set created_at to before v0 AFTER increment, then re-derive SAID
        v1.created_at = (chrono::Utc::now() - chrono::Duration::hours(1)).into();
        v1.derive_said().unwrap();

        let history = AdditionHistory {
            prefix: v0.prefix.clone(),
            records: vec![v0, v1],
        };
        let err = history.verify().unwrap_err();
        assert!(
            err.to_string().contains("created_at is not after"),
            "Expected created_at monotonicity error, got: {}",
            err
        );
    }

    // ==================== RemovalHistory created_at monotonicity ====================

    #[test]
    fn test_removal_history_valid_timestamps() {
        let v0 = PeerRemovalProposal::empty("peer-1", "KRegistryA", 2, &test_expires_at()).unwrap();

        let mut v1 = v0.clone();
        v1.withdrawn_at = Some(StorageDatetime::now());
        v1.increment().unwrap();

        let history = RemovalHistory {
            prefix: v0.prefix.clone(),
            records: vec![v0, v1],
        };
        assert!(history.verify().is_ok());
    }

    #[tokio::test]
    async fn test_verify_signature_rejects_divergent_kel() {
        use crate::{KelVerifier, KeyEventBuilder, SoftwareKeyProvider};
        use cesr::{Digest, Matter, VerificationKeyCode};

        let mut builder1 = KeyEventBuilder::new(
            SoftwareKeyProvider::new(
                VerificationKeyCode::Secp256r1,
                VerificationKeyCode::Secp256r1,
            ),
            None,
        );
        let icp = builder1.incept().await.unwrap();
        let prefix = icp.event.prefix.clone();
        let mut builder2 = builder1.clone();
        let anchor1 = Digest::blake3_256(b"anchor1").qb64();
        let anchor2 = Digest::blake3_256(b"anchor2").qb64();
        let ixn1 = builder1.interact(&anchor1).await.unwrap();
        let ixn2 = builder2.interact(&anchor2).await.unwrap();

        // Sort events the way the DB would: serial ASC, kind sort_priority ASC, said ASC
        let mut events = vec![icp, ixn1, ixn2];
        events.sort_by(|a, b| {
            a.event
                .serial
                .cmp(&b.event.serial)
                .then(
                    a.event
                        .kind
                        .sort_priority()
                        .cmp(&b.event.kind.sort_priority()),
                )
                .then(a.event.said.cmp(&b.event.said))
        });

        let mut verifier = KelVerifier::new(&prefix);
        verifier.verify_page(&events).unwrap();
        let kel_verification = verifier.into_verification().unwrap();
        assert!(kel_verification.is_divergent());

        let signed = SignedRequest {
            payload: "test".to_string(),
            peer_prefix: "test_prefix".to_string(),
            signature: "test_sig".to_string(),
        };

        let result = signed.verify_signature(&kel_verification);
        assert!(
            matches!(result, Err(crate::KelsError::Divergent)),
            "Expected Divergent error, got: {:?}",
            result
        );
    }

    #[test]
    fn test_removal_history_non_monotonic_timestamp_fails() {
        let v0 = PeerRemovalProposal::empty("peer-1", "KRegistryA", 2, &test_expires_at()).unwrap();

        let mut v1 = v0.clone();
        v1.withdrawn_at = Some(StorageDatetime::now());
        v1.increment().unwrap();
        // Set created_at to before v0 AFTER increment, then re-derive SAID
        v1.created_at = (chrono::Utc::now() - chrono::Duration::hours(1)).into();
        v1.derive_said().unwrap();

        let history = RemovalHistory {
            prefix: v0.prefix.clone(),
            records: vec![v0, v1],
        };
        let err = history.verify().unwrap_err();
        assert!(
            err.to_string().contains("created_at is not after"),
            "Expected created_at monotonicity error, got: {}",
            err
        );
    }
}
