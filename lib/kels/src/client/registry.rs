//! Registry API client for node registration and discovery.
//!
//! Shared client used by gossip nodes, CLI, and other clients to interact
//! with the registry service.

use std::{cmp::Ordering, collections::HashSet, future::Future, iter, time::Duration};
use tracing::{debug, info, warn};

use futures::future::join_all;
use rand::seq::SliceRandom;
use verifiable_storage::StorageDatetime;

use crate::{
    client::NodeStatus,
    error::KelsError,
    types::{
        CompletedProposalsResponse, ErrorResponse, FederationStatus, KelVerification, Peer,
        PeersResponse, Proposal, ProposalHistory, ProposalStatus, ProposalWithVotesMethods,
        SignedRequest, Vote,
    },
};

#[cfg(feature = "federation")]
const TRUSTED_REGISTRY_PREFIXES: &str = env!("TRUSTED_REGISTRY_PREFIXES");

#[cfg(feature = "federation")]
fn parse_trusted_prefixes() -> HashSet<&'static str> {
    TRUSTED_REGISTRY_PREFIXES
        .split(',')
        .filter(|s| !s.is_empty())
        .collect()
}

/// Get the compiled-in trusted registry prefixes.
#[cfg(feature = "federation")]
pub fn trusted_prefixes() -> HashSet<&'static str> {
    parse_trusted_prefixes()
}

/// Get the compiled-in trusted registry prefixes.
/// Panics: requires the `federation` feature.
#[cfg(not(feature = "federation"))]
pub fn trusted_prefixes() -> HashSet<&'static str> {
    unimplemented!("trusted_prefixes() requires the 'federation' feature")
}

/// Result of a signing operation, containing all data needed for a SignedRequest.
#[derive(Debug, Clone)]
pub struct SignResult {
    /// CESR qb64 encoded signature
    pub signature: String,
    /// The signer's peer identity (KELS prefix)
    pub peer_prefix: String,
}

/// Trait for signing requests.
///
/// Implementors sign data and return the signature along with the signer's
/// peer identity (KELS prefix). The public key is not included — verifiers
/// look it up from the peer's cached KEL.
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait PeerSigner: Send + Sync {
    /// Sign the given data and return the signature and peer identity.
    async fn sign(&self, data: &[u8]) -> Result<SignResult, KelsError>;
}

/// Create a signed request wrapper for the given payload using the provided signer.
pub async fn sign_request<T>(
    signer: &dyn PeerSigner,
    payload: &T,
) -> Result<SignedRequest<T>, KelsError>
where
    T: serde::Serialize + Clone,
{
    // Serialize payload to JSON for signing
    let payload_json = serde_json::to_vec(payload)?;

    // Sign the payload (returns signature and peer prefix)
    let sign_result = signer.sign(&payload_json).await?;

    Ok(SignedRequest {
        payload: payload.clone(),
        peer_prefix: sign_result.peer_prefix,
        signature: sign_result.signature,
    })
}

/// Client for interacting with the registry service.
#[derive(Clone)]
pub struct KelsRegistryClient {
    client: reqwest::Client,
    base_url: String,
}

impl KelsRegistryClient {
    /// Create a new registry client with default timeout (no signing capability).
    pub fn new(registry_url: &str) -> Result<Self, KelsError> {
        Self::with_timeout(registry_url, Duration::from_secs(10))
    }

    /// Create a new registry client with custom timeout (no signing capability).
    pub fn with_timeout(registry_url: &str, timeout: Duration) -> Result<Self, KelsError> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(timeout)
            .build()?;

        Ok(Self {
            client,
            base_url: registry_url.trim_end_matches('/').to_string(),
        })
    }

    /// List all active peers from the registry.
    pub async fn list_active_peers(&self) -> Result<Vec<Peer>, KelsError> {
        let peers_response = self.fetch_peers().await?;
        Ok(peers_response
            .peers
            .into_iter()
            .filter_map(|history| {
                history
                    .records
                    .into_iter()
                    .last()
                    .filter(|peer| peer.active)
            })
            .collect())
    }

    /// Check if the registry is healthy.
    pub async fn health_check(&self) -> Result<bool, KelsError> {
        let response = self
            .client
            .get(format!("{}/health", self.base_url))
            .send()
            .await?;

        Ok(response.status().is_success())
    }

    /// Fetch all peers from the registry.
    ///
    /// Returns peer histories containing all versions of each peer record.
    /// This is an unauthenticated endpoint - nodes can check the peer list
    /// before they are authorized.
    pub async fn fetch_peers(&self) -> Result<PeersResponse, KelsError> {
        let response = self
            .client
            .get(format!("{}/api/v1/peers", self.base_url))
            .send()
            .await?;

        if response.status().is_success() {
            Ok(response.json().await?)
        } else {
            let err: ErrorResponse = response.json().await?;
            Err(KelsError::ServerError(err.error, err.code))
        }
    }

    pub async fn is_peer_authorized(
        &self,
        peer_prefix: &str,
        trusted_prefixes: &HashSet<&'static str>,
        kel_verifications: &[&KelVerification],
    ) -> Result<bool, KelsError> {
        let peers_response = self.fetch_peers().await?;
        if !peers_response.peers.iter().any(|history| {
            history
                .records
                .last()
                .map(|peer| peer.peer_prefix == peer_prefix)
                .unwrap_or(false)
        }) {
            return Err(KelsError::RegistryFailure(format!(
                "Peer {} not found in peers list",
                peer_prefix
            )));
        }

        Ok(peers_response.peers.iter().any(|history| {
            history
                .verify_with_contexts(trusted_prefixes, kel_verifications)
                .is_ok()
        }))
    }

    pub async fn has_ready_peers(&self, exclude_node_id: Option<&str>) -> Result<bool, KelsError> {
        let peers_response = self.fetch_peers().await?;

        for history in peers_response.peers {
            let Some(record) = history.records.last() else {
                continue;
            };
            if !record.active {
                continue;
            }
            if let Some(node_id) = exclude_node_id
                && node_id == record.node_id
            {
                continue;
            }

            let kels_url = format!("http://kels.{}", record.base_domain);
            if let Ok(client) = crate::KelsClient::with_timeout(&kels_url, Duration::from_secs(2))
                && client.check_ready_status().await == NodeStatus::Ready
            {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Fetch the registry's own prefix from federation status.
    pub async fn fetch_registry_prefix(&self) -> Result<String, KelsError> {
        let url = format!("{}/api/v1/federation/status", self.base_url);
        let response = self.client.get(&url).send().await?;

        if response.status().is_success() {
            let status: FederationStatus = response.json().await?;
            Ok(status.self_prefix)
        } else {
            let err: ErrorResponse = response.json().await?;
            Err(KelsError::ServerError(err.error, err.code))
        }
    }

    /// Fetch a specific federation member's KEL by prefix with optional pagination.
    pub async fn fetch_member_key_events(
        &self,
        prefix: &str,
        since: Option<&str>,
        limit: usize,
    ) -> Result<crate::SignedKeyEventPage, KelsError> {
        let mut url = format!(
            "{}/api/v1/member-kels/kel/{}?limit={}",
            self.base_url, prefix, limit
        );
        if let Some(since) = since {
            url.push_str(&format!("&since={}", since));
        }
        let response = self.client.get(&url).send().await?;

        if response.status().is_success() {
            Ok(response.json().await?)
        } else {
            let err: ErrorResponse = response.json().await?;
            Err(KelsError::ServerError(err.error, err.code))
        }
    }

    /// Fetch completed proposals from this registry.
    pub async fn fetch_completed_proposals(&self) -> Result<CompletedProposalsResponse, KelsError> {
        let response = self
            .client
            .get(format!("{}/api/v1/federation/proposals", self.base_url))
            .send()
            .await?;

        if response.status().is_success() {
            Ok(response.json().await?)
        } else {
            let err: ErrorResponse = response.json().await?;
            Err(KelsError::ServerError(err.error, err.code))
        }
    }

    /// Fetch completed proposals with full audit trail (includes all historical proposals).
    pub async fn fetch_completed_proposals_audit(
        &self,
    ) -> Result<CompletedProposalsResponse, KelsError> {
        let response = self
            .client
            .get(format!(
                "{}/api/v1/federation/proposals?audit=true",
                self.base_url
            ))
            .send()
            .await?;

        if response.status().is_success() {
            Ok(response.json().await?)
        } else {
            let err: ErrorResponse = response.json().await?;
            Err(KelsError::ServerError(err.error, err.code))
        }
    }

    /// Fetch federation status.
    pub async fn fetch_federation_status(&self) -> Result<crate::FederationStatus, KelsError> {
        let response = self
            .client
            .get(format!("{}/api/v1/federation/status", self.base_url))
            .send()
            .await?;

        if response.status().is_success() {
            Ok(response.json().await?)
        } else {
            let err: ErrorResponse = response.json().await?;
            Err(KelsError::ServerError(err.error, err.code))
        }
    }

    /// Fetch all peers (including inactive) from the registry.
    pub async fn fetch_all_peers(&self) -> Result<crate::PeersResponse, KelsError> {
        let response = self
            .client
            .get(format!("{}/api/v1/peers?all=true", self.base_url))
            .send()
            .await?;

        if response.status().is_success() {
            Ok(response.json().await?)
        } else {
            let err: ErrorResponse = response.json().await?;
            Err(KelsError::ServerError(err.error, err.code))
        }
    }

    /// Submit a peer addition proposal.
    pub async fn submit_addition_proposal(
        &self,
        proposal: &crate::PeerAdditionProposal,
    ) -> Result<crate::ProposalResponse, KelsError> {
        let response = self
            .client
            .post(format!("{}/api/v1/admin/addition-proposals", self.base_url))
            .json(proposal)
            .send()
            .await?;

        if response.status().is_success() {
            Ok(response.json().await?)
        } else {
            let err: ErrorResponse = response.json().await?;
            Err(KelsError::ServerError(err.error, err.code))
        }
    }

    /// Submit a peer removal proposal.
    pub async fn submit_removal_proposal(
        &self,
        proposal: &crate::PeerRemovalProposal,
    ) -> Result<crate::ProposalResponse, KelsError> {
        let response = self
            .client
            .post(format!("{}/api/v1/admin/removal-proposals", self.base_url))
            .json(proposal)
            .send()
            .await?;

        if response.status().is_success() {
            Ok(response.json().await?)
        } else {
            let err: ErrorResponse = response.json().await?;
            Err(KelsError::ServerError(err.error, err.code))
        }
    }

    /// Submit a vote on a proposal.
    pub async fn submit_vote(
        &self,
        proposal_id: &str,
        vote: &crate::Vote,
    ) -> Result<crate::ProposalResponse, KelsError> {
        let response = self
            .client
            .post(format!(
                "{}/api/v1/admin/proposals/{}/vote",
                self.base_url, proposal_id
            ))
            .json(vote)
            .send()
            .await?;

        if response.status().is_success() {
            Ok(response.json().await?)
        } else {
            let err: ErrorResponse = response.json().await?;
            Err(KelsError::ServerError(err.error, err.code))
        }
    }

    /// Fetch a specific proposal by ID.
    pub async fn fetch_proposal(
        &self,
        proposal_id: &str,
    ) -> Result<crate::ProposalWithVotes, KelsError> {
        let response = self
            .client
            .get(format!(
                "{}/api/v1/federation/proposals/{}",
                self.base_url, proposal_id
            ))
            .send()
            .await?;

        if response.status().is_success() {
            Ok(response.json().await?)
        } else {
            let err: ErrorResponse = response.json().await?;
            Err(KelsError::ServerError(err.error, err.code))
        }
    }
}

/// Try each registry URL in shuffled order until one succeeds.
///
/// All calls use an explicit timeout. URLs are shuffled to distribute load.
pub async fn with_failover<T, F, Fut>(
    urls: &[String],
    timeout: Duration,
    f: F,
) -> Result<T, KelsError>
where
    F: Fn(KelsRegistryClient) -> Fut,
    Fut: Future<Output = Result<T, KelsError>>,
{
    let mut shuffled: Vec<_> = urls.to_vec();
    shuffled.shuffle(&mut rand::rng());

    let mut last_err = None;
    for url in &shuffled {
        let client = KelsRegistryClient::with_timeout(url, timeout)?;
        match f(client).await {
            Ok(result) => return Ok(result),
            Err(e) => {
                warn!(url = %url, error = %e, "with_failover: attempt failed, trying next");
                last_err = Some(e);
            }
        }
    }

    Err(last_err
        .unwrap_or_else(|| KelsError::RegistryFailure("No registry URLs provided".to_string())))
}

/// Sync a registry member KEL to a local store, trying each registry URL until one succeeds.
pub async fn sync_member_kel(
    prefix: &str,
    registry_urls: &[String],
    sink: &(dyn crate::PagedKelSink + Sync),
) {
    for url in registry_urls {
        let source = match crate::HttpKelSource::new(url, "/api/v1/member-kels/kel/{prefix}") {
            Ok(s) => s,
            Err(e) => {
                warn!(url = %url, error = %e, "Failed to build HTTP client for member KEL sync");
                continue;
            }
        };
        if crate::forward_key_events(
            prefix,
            &source,
            sink,
            crate::page_size(),
            crate::max_pages(),
            None,
        )
        .await
        .is_ok()
        {
            return;
        }
    }
    warn!(prefix = %prefix, "Failed to sync member KEL from any registry URL");
}

/// Verify that a peer record is anchored in its authorizing registry's KEL.
///
/// Checks anchoring from the local store first. If not found, re-syncs the
/// registry KEL from HTTP and retries.
pub async fn verify_peer_anchoring(
    store: &(dyn crate::KelStore + Sync),
    peer: &Peer,
    registry_urls: &[String],
) -> Result<bool, KelsError> {
    let saids = || iter::once(peer.said.clone());

    // First try from local store
    let mut loader = crate::StorePageLoader::new(store);
    let kel_verification = crate::completed_verification(
        &mut loader,
        &peer.authorizing_kel,
        crate::page_size(),
        crate::max_pages(),
        saids(),
    )
    .await;

    if let Ok(ref v) = kel_verification
        && v.anchors_all_saids()
    {
        return Ok(true);
    }

    // Retry: re-sync from registry HTTP, then re-verify from store
    let sink = crate::KelStoreSink(store);
    sync_member_kel(&peer.authorizing_kel, registry_urls, &sink).await;

    let mut loader = crate::StorePageLoader::new(store);
    let kel_verification = crate::completed_verification(
        &mut loader,
        &peer.authorizing_kel,
        crate::page_size(),
        crate::max_pages(),
        saids(),
    )
    .await?;

    Ok(kel_verification.anchors_all_saids())
}

enum ProposalCandidateRef<'a> {
    Addition(&'a crate::AdditionWithVotes),
    Removal(&'a crate::RemovalWithVotes),
}

/// Verify that a peer has an approved proposal backed by sufficient anchored votes.
///
/// Uses a `KelStore` for anchor verification, with HTTP re-sync on cache miss.
pub async fn verify_peer_votes(
    store: &(dyn crate::KelStore + Sync),
    peer_prefix: &str,
    proposals_response: &Option<CompletedProposalsResponse>,
    trusted_prefixes: &HashSet<&str>,
    registry_urls: &[String],
) -> bool {
    let Some(response) = proposals_response else {
        warn!(peer_prefix = %peer_prefix, "No proposals available for peer vote verification");
        return false;
    };

    let mut candidates: Vec<(bool, &StorageDatetime, ProposalCandidateRef<'_>)> = Vec::new();

    for awv in &response.additions {
        let Some(last) = awv.history.records.last() else {
            continue;
        };
        if last.is_withdrawn()
            || awv
                .history
                .inception()
                .is_none_or(|p| p.peer_prefix != peer_prefix)
            || awv.status(last.threshold) != ProposalStatus::Approved
        {
            continue;
        }
        candidates.push((true, &last.created_at, ProposalCandidateRef::Addition(awv)));
    }

    for rwv in &response.removals {
        let Some(last) = rwv.history.records.last() else {
            continue;
        };
        if last.is_withdrawn()
            || rwv
                .history
                .inception()
                .is_none_or(|p| p.peer_prefix != peer_prefix)
            || rwv.status(last.threshold) != ProposalStatus::Approved
        {
            continue;
        }
        candidates.push((false, &last.created_at, ProposalCandidateRef::Removal(rwv)));
    }

    if candidates.is_empty() {
        info!(peer_prefix = %peer_prefix, "No approved proposal found for peer");
        return false;
    }

    candidates.sort_by(|a, b| b.1.cmp(a.1));

    let member_prefixes = trusted_prefixes.clone();

    for (is_addition, _, candidate) in &candidates {
        let (kind, verify_result, proposer, record_saids, votes, threshold) = match candidate {
            ProposalCandidateRef::Addition(awv) => (
                "addition",
                awv.verify(),
                awv.proposer(),
                awv.history
                    .records
                    .iter()
                    .map(|r| &r.said)
                    .collect::<Vec<_>>(),
                &awv.votes,
                awv.history
                    .inception()
                    .map(|p| p.threshold)
                    .unwrap_or(usize::MAX),
            ),
            ProposalCandidateRef::Removal(rwv) => (
                "removal",
                rwv.verify(),
                rwv.proposer(),
                rwv.history
                    .records
                    .iter()
                    .map(|r| &r.said)
                    .collect::<Vec<_>>(),
                &rwv.votes,
                rwv.history
                    .inception()
                    .map(|p| p.threshold)
                    .unwrap_or(usize::MAX),
            ),
        };

        if verify_proposal_dag_standalone(
            store,
            peer_prefix,
            kind,
            verify_result,
            proposer,
            record_saids.into_iter(),
            votes,
            threshold,
            &member_prefixes,
            registry_urls,
        )
        .await
        {
            if *is_addition {
                return true;
            } else {
                info!(peer_prefix = %peer_prefix, "Verified removal — peer excluded");
                return false;
            }
        }

        warn!(peer_prefix = %peer_prefix, kind = kind, "Proposal failed verification, trying next");
    }

    warn!(peer_prefix = %peer_prefix, "No proposal passed verification for peer");
    false
}

/// Verify anchoring from a local store, retrying with HTTP re-sync if needed.
async fn verify_anchors_from_store(
    store: &(dyn crate::KelStore + Sync),
    prefix: &str,
    saids: impl IntoIterator<Item = String> + Clone,
    registry_urls: &[String],
) -> Result<Option<KelVerification>, KelsError> {
    // First try from local store
    let mut loader = crate::StorePageLoader::new(store);
    let kel_verification = crate::completed_verification(
        &mut loader,
        prefix,
        crate::page_size(),
        crate::max_pages(),
        saids.clone(),
    )
    .await;

    if let Ok(ref v) = kel_verification
        && v.anchors_all_saids()
    {
        return Ok(Some(v.clone()));
    }

    // Retry: re-sync from registry HTTP
    let sink = crate::KelStoreSink(store);
    sync_member_kel(prefix, registry_urls, &sink).await;

    let mut loader = crate::StorePageLoader::new(store);
    let kel_verification = crate::completed_verification(
        &mut loader,
        prefix,
        crate::page_size(),
        crate::max_pages(),
        saids,
    )
    .await?;

    if kel_verification.anchors_all_saids() {
        Ok(Some(kel_verification))
    } else {
        Ok(None)
    }
}

/// Verify a proposal's structural integrity, record anchoring, and vote anchoring.
#[allow(clippy::too_many_arguments)]
async fn verify_proposal_dag_standalone<'a>(
    store: &(dyn crate::KelStore + Sync),
    peer_prefix: &str,
    kind: &str,
    structural_result: Result<(), KelsError>,
    proposer: Option<&str>,
    record_saids: impl Iterator<Item = &'a String>,
    votes: &[Vote],
    threshold: usize,
    member_prefixes: &HashSet<&str>,
    registry_urls: &[String],
) -> bool {
    if let Err(e) = structural_result {
        warn!(peer_prefix = %peer_prefix, error = %e, "{} proposal DAG verification failed", kind);
        return false;
    }

    let proposer = match proposer {
        Some(p) => p.to_string(),
        None => {
            warn!(peer_prefix = %peer_prefix, "{} proposal has no proposer", kind);
            return false;
        }
    };

    if !member_prefixes.contains(proposer.as_str()) {
        warn!(peer_prefix = %peer_prefix, proposer = %proposer, "{} proposer is not a federation member", kind);
        return false;
    }

    let mut proposer_saids: Vec<String> = record_saids.cloned().collect();

    let eligible_votes: Vec<&Vote> = votes
        .iter()
        .filter(|v| v.approve && member_prefixes.contains(v.voter.as_str()))
        .collect();

    let mut proposer_voted = false;
    for vote in &eligible_votes {
        if vote.voter == proposer {
            proposer_saids.push(vote.said.clone());
            proposer_voted = true;
        }
    }

    debug!(
        peer_prefix = %peer_prefix,
        proposer = %proposer,
        saids = proposer_saids.len(),
        "verify_proposal_dag: checking proposer anchoring (records + vote)"
    );

    match verify_anchors_from_store(store, &proposer, proposer_saids, registry_urls).await {
        Ok(Some(_)) => {
            debug!(proposer = %proposer, "verify_proposal_dag: proposer anchoring OK");
        }
        Ok(None) => {
            warn!(
                peer_prefix = %peer_prefix,
                proposer = %proposer,
                "{} proposal/vote SAIDs not all anchored in proposer's KEL", kind
            );
            return false;
        }
        Err(e) => {
            warn!(
                peer_prefix = %peer_prefix,
                error = %e,
                "Failed to fetch proposer's KEL for {} anchoring", kind
            );
            return false;
        }
    }

    let mut verified_voters: HashSet<String> = HashSet::new();
    if proposer_voted {
        verified_voters.insert(proposer.clone());
    }

    for vote in &eligible_votes {
        if vote.voter == proposer {
            continue;
        }

        debug!(
            peer_prefix = %peer_prefix,
            vote_said = %vote.said,
            voter = %vote.voter,
            "verify_proposal_dag: checking vote anchoring"
        );

        match verify_anchors_from_store(store, &vote.voter, vec![vote.said.clone()], registry_urls)
            .await
        {
            Ok(Some(_)) => {
                debug!(voter = %vote.voter, "verify_proposal_dag: vote anchor OK");
                verified_voters.insert(vote.voter.clone());
            }
            Ok(None) => {
                warn!(
                    vote_said = %vote.said,
                    voter = %vote.voter,
                    "{} vote SAID not anchored in voter's KEL", kind
                );
            }
            Err(e) => {
                warn!(
                    voter = %vote.voter,
                    error = %e,
                    "Failed to fetch voter's KEL for {} vote verification", kind
                );
            }
        }
    }

    if verified_voters.len() < threshold {
        warn!(
            peer_prefix = %peer_prefix,
            verified = verified_voters.len(),
            threshold = threshold,
            "Insufficient verified votes for {} of peer", kind
        );
        return false;
    }

    true
}

/// Discover verified, ready peers from registries, sorted by latency.
///
/// Used by CLI and FFI. Performs full verification: structural integrity,
/// peer anchoring, and vote verification against the local store.
/// Returns only active, verified, ready peers sorted by measured latency.
pub async fn nodes_sorted_by_latency(
    urls: &[String],
    timeout: Duration,
    store: &(dyn crate::KelStore + Sync),
) -> Result<Vec<Peer>, KelsError> {
    let trusted = trusted_prefixes();

    // Fetch and verify registry member KELs to the local store
    let sink = crate::KelStoreSink(store);
    for prefix in &trusted {
        sync_member_kel(prefix, urls, &sink).await;
    }

    // Verify each trusted prefix from store
    for prefix in &trusted {
        let mut loader = crate::StorePageLoader::new(store);
        let _ = crate::completed_verification(
            &mut loader,
            prefix,
            crate::page_size(),
            crate::max_pages(),
            iter::empty(),
        )
        .await;
    }

    // Fetch peers with failover
    let peers_response: PeersResponse =
        with_failover(urls, timeout, |c| async move { c.fetch_peers().await }).await?;

    // Fetch proposals with failover
    let proposals_response = with_failover(urls, timeout, |c| async move {
        c.fetch_completed_proposals().await
    })
    .await
    .ok();

    let mut verified_peers = Vec::new();
    for history in &peers_response.peers {
        let Some(peer) = history.records.last() else {
            continue;
        };

        if !peer.active {
            continue;
        }

        match verify_peer_anchoring(store, peer, urls).await {
            Ok(true) => {}
            Ok(false) => {
                warn!(peer_prefix = %peer.peer_prefix, "Peer SAID not anchored, skipping");
                continue;
            }
            Err(e) => {
                warn!(peer_prefix = %peer.peer_prefix, error = %e, "Failed to verify peer anchoring");
                continue;
            }
        }

        if !verify_peer_votes(
            store,
            &peer.peer_prefix,
            &proposals_response,
            &trusted,
            urls,
        )
        .await
        {
            warn!(peer_prefix = %peer.peer_prefix, "Peer votes not verified, skipping");
            continue;
        }

        // Check readiness and measure latency
        let kels_url = format!("http://kels.{}", peer.base_domain);
        let Ok(client) = crate::KelsClient::with_timeout(&kels_url, timeout) else {
            continue;
        };

        if client.check_ready_status().await != NodeStatus::Ready {
            continue;
        }

        verified_peers.push((peer.clone(), client));
    }

    // Measure latency to all ready peers in parallel
    let latency_futures: Vec<_> = verified_peers
        .iter()
        .enumerate()
        .map(|(i, (peer, client))| {
            let node_id = peer.node_id.clone();
            let client = client.clone();
            async move {
                let latency = client.test_latency().await.ok();
                if let Some(ref lat) = latency {
                    info!("Node {} latency: {}ms", node_id, lat.as_millis());
                } else {
                    warn!("Node {} latency test failed/timed out", node_id);
                }
                (i, latency)
            }
        })
        .collect();

    let mut latencies: Vec<Option<Duration>> = vec![None; verified_peers.len()];
    for (i, latency) in join_all(latency_futures).await {
        latencies[i] = latency;
    }

    // Sort by latency (nodes with latency first, then those without)
    let mut indexed: Vec<(usize, &Peer)> = verified_peers
        .iter()
        .enumerate()
        .map(|(i, (p, _))| (i, p))
        .collect();
    indexed.sort_by(|a, b| match (&latencies[a.0], &latencies[b.0]) {
        (Some(a_lat), Some(b_lat)) => a_lat.cmp(b_lat),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    });

    Ok(indexed
        .into_iter()
        .map(|(i, _)| verified_peers[i].0.clone())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Peer, PeerHistory};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // ==================== Constructor Tests ====================

    #[test]
    fn test_url_trailing_slash_stripped() {
        let client = KelsRegistryClient::new("http://registry:8080/").unwrap();
        assert_eq!(client.base_url, "http://registry:8080");
    }

    #[tokio::test]
    async fn test_list_active_peers() {
        let mock_server = MockServer::start().await;

        let peer = Peer {
            said: "KTestPeerSaid_______________________________".to_string(),
            prefix: "KTestPeerPrefix_____________________________".to_string(),
            previous: None,
            version: 1,
            created_at: chrono::Utc::now().into(),
            peer_prefix: "EPeer1Prefix________________________________".to_string(),
            node_id: "node-1".to_string(),
            authorizing_kel: "EAuthorizingKel_____________________________".to_string(),
            active: true,
            base_domain: "node-1.kels".to_string(),
            gossip_addr: "10.0.0.1:9000".to_string(),
        };

        let response = PeersResponse {
            peers: vec![PeerHistory {
                prefix: peer.prefix.clone(),
                records: vec![peer],
            }],
        };

        Mock::given(method("GET"))
            .and(path("/api/v1/peers"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response))
            .mount(&mock_server)
            .await;

        let client = KelsRegistryClient::new(&mock_server.uri()).unwrap();
        let peers = client.list_active_peers().await.unwrap();

        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].node_id, "node-1");
        assert_eq!(peers[0].base_domain, "node-1.kels");
    }

    // ==================== Peers Tests ====================

    fn make_test_peer(peer_prefix: &str, node_id: &str, active: bool) -> Peer {
        Peer::create(
            peer_prefix.to_string(),
            node_id.to_string(),
            "EAuthorizingKel_____________________________".to_string(),
            active,
            format!("http://{}:8080", node_id),
            "127.0.0.1:4001".to_string(),
        )
        .expect("create peer")
    }

    #[tokio::test]
    async fn test_fetch_peers_success() {
        let mock_server = MockServer::start().await;

        let peer = make_test_peer(
            "EPeer1Prefix________________________________",
            "node-1",
            true,
        );
        let response = PeersResponse {
            peers: vec![PeerHistory {
                prefix: peer.prefix.clone(),
                records: vec![peer],
            }],
        };

        Mock::given(method("GET"))
            .and(path("/api/v1/peers"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response))
            .mount(&mock_server)
            .await;

        let client = KelsRegistryClient::new(&mock_server.uri()).unwrap();
        let result = client.fetch_peers().await;

        assert!(result.is_ok());
        let peers = result.unwrap();
        assert_eq!(peers.peers.len(), 1);
    }

    #[tokio::test]
    async fn test_fetch_peers_server_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v1/peers"))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "error": "Error",
                "code": "internal_error"
            })))
            .mount(&mock_server)
            .await;

        let client = KelsRegistryClient::new(&mock_server.uri()).unwrap();
        let result = client.fetch_peers().await;

        assert!(matches!(result, Err(KelsError::ServerError(..))));
    }
}
