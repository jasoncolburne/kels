//! Registry API client for node registration and discovery.
//!
//! Shared client used by gossip nodes, CLI, and other clients to interact
//! with the kels-registry service.

use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};
use tracing::{debug, info, warn};

use futures::future::join_all;
use verifiable_storage::StorageDatetime;

use crate::{
    client::KelsClient,
    error::KelsError,
    types::{
        CompletedProposalsResponse, DeregisterRequest, ErrorResponse, KelVerifier, NodeInfo,
        NodeRegistration, NodeStatus, Peer, PeersResponse, Proposal, ProposalHistory,
        ProposalStatus, ProposalWithVotesMethods, RegisterNodeRequest, SignedKeyEvent,
        SignedKeyEventPage, SignedRequest, StatusUpdateRequest, Verification, Vote,
    },
};

/// Trusted registry prefixes for verifying registry identity.
/// MUST be set at compile time via TRUSTED_REGISTRY_PREFIXES environment variable.
/// Format: "prefix1,prefix2,..." (comma-separated KELS prefixes)
const TRUSTED_REGISTRY_PREFIXES: &str = env!("TRUSTED_REGISTRY_PREFIXES");

fn parse_trusted_prefixes() -> HashSet<&'static str> {
    TRUSTED_REGISTRY_PREFIXES
        .split(',')
        .filter(|s| !s.is_empty())
        .collect()
}

/// Get the compiled-in trusted registry prefixes.
pub fn trusted_prefixes() -> HashSet<&'static str> {
    parse_trusted_prefixes()
}

/// Result of a signing operation, containing all data needed for a SignedRequest.
#[derive(Debug, Clone)]
pub struct SignResult {
    /// CESR qb64 encoded signature
    pub signature: String,
    /// The signer's peer identity (KELS prefix)
    pub peer_prefix: String,
}

/// Trait for signing registry requests.
///
/// Implementors sign data and return the signature along with the signer's
/// peer identity (KELS prefix). The public key is not included — verifiers
/// look it up from the peer's cached KEL.
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait RegistrySigner: Send + Sync {
    /// Sign the given data and return the signature and peer identity.
    async fn sign(&self, data: &[u8]) -> Result<SignResult, KelsError>;
}

/// Create a signed request wrapper for the given payload using the provided signer.
pub async fn sign_request<T>(
    signer: &dyn RegistrySigner,
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

/// Client for interacting with the kels-registry service.
#[derive(Clone)]
pub struct KelsRegistryClient {
    client: reqwest::Client,
    base_url: String,
    signer: Option<Arc<dyn RegistrySigner>>,
}

impl KelsRegistryClient {
    /// Create a new registry client with default timeout (no signing capability).
    pub fn new(registry_url: &str) -> Self {
        Self::with_timeout(registry_url, Duration::from_secs(10))
    }

    /// Create a new registry client with custom timeout (no signing capability).
    pub fn with_timeout(registry_url: &str, timeout: Duration) -> Self {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .unwrap_or_default();

        Self {
            client,
            base_url: registry_url.trim_end_matches('/').to_string(),
            signer: None,
        }
    }

    /// Create a new registry client with signing capability.
    pub fn with_signer(registry_url: &str, signer: Arc<dyn RegistrySigner>) -> Self {
        Self::with_signer_and_timeout(registry_url, signer, Duration::from_secs(10))
    }

    /// Create a new registry client with signing capability and custom timeout.
    pub fn with_signer_and_timeout(
        registry_url: &str,
        signer: Arc<dyn RegistrySigner>,
        timeout: Duration,
    ) -> Self {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .unwrap_or_default();

        Self {
            client,
            base_url: registry_url.trim_end_matches('/').to_string(),
            signer: Some(signer),
        }
    }

    /// Create a signed request wrapper for the given payload.
    async fn sign_request<T>(&self, payload: &T) -> Result<SignedRequest<T>, KelsError>
    where
        T: serde::Serialize + Clone,
    {
        let signer = self
            .signer
            .as_ref()
            .ok_or_else(|| KelsError::SigningFailed("No signer configured".to_string()))?;

        sign_request(signer.as_ref(), payload).await
    }

    /// Register a node with the registry.
    ///
    /// Requires a signer to be configured (use `with_signer` constructor).
    pub async fn register(
        &self,
        node_id: &str,
        kels_url: &str,
        gossip_addr: &str,
        status: NodeStatus,
    ) -> Result<NodeRegistration, KelsError> {
        let request = RegisterNodeRequest {
            node_id: node_id.to_string(),
            node_type: crate::NodeType::Kels,
            kels_url: kels_url.to_string(),
            gossip_addr: gossip_addr.to_string(),
            status,
        };

        // Sign the request
        let signed_request = self.sign_request(&request).await?;

        info!("${:?}", signed_request);

        let response = self
            .client
            .post(format!("{}/api/nodes/register", self.base_url))
            .json(&signed_request)
            .send()
            .await?;

        if response.status().is_success() {
            Ok(response.json().await?)
        } else {
            let err: ErrorResponse = response.json().await?;
            Err(KelsError::ServerError(err.error, err.code))
        }
    }

    /// Deregister a node from the registry.
    ///
    /// Requires a signer to be configured (use `with_signer` constructor).
    pub async fn deregister(&self, node_id: &str) -> Result<(), KelsError> {
        let request = DeregisterRequest {
            node_id: node_id.to_string(),
        };

        // Sign the request
        let signed_request = self.sign_request(&request).await?;

        let response = self
            .client
            .post(format!("{}/api/nodes/deregister", self.base_url))
            .json(&signed_request)
            .send()
            .await?;

        if response.status().is_success() || response.status() == reqwest::StatusCode::NOT_FOUND {
            Ok(())
        } else {
            let err: ErrorResponse = response.json().await?;
            Err(KelsError::ServerError(err.error, err.code))
        }
    }

    /// List all active peers as NodeInfo (for client discovery with latency testing).
    pub async fn list_nodes_info(&self) -> Result<Vec<NodeInfo>, KelsError> {
        let (peers_response, ready_map) = self.fetch_peers().await?;
        let nodes: Vec<NodeInfo> = peers_response
            .peers
            .into_iter()
            .filter_map(|history| {
                history.records.into_iter().last().and_then(|peer| {
                    let status = ready_map
                        .get(&peer.prefix)
                        .unwrap_or(&NodeStatus::Bootstrapping);

                    if peer.active {
                        Some(NodeInfo {
                            node_id: peer.node_id,
                            kels_url: peer.kels_url,
                            gossip_addr: peer.gossip_addr,
                            status: *status,
                            latency_ms: None,
                        })
                    } else {
                        None
                    }
                })
            })
            .collect();
        Ok(nodes)
    }

    /// Update node status.
    ///
    /// Requires a signer to be configured (use `with_signer` constructor).
    pub async fn update_status(
        &self,
        node_id: &str,
        status: NodeStatus,
    ) -> Result<NodeRegistration, KelsError> {
        let request = StatusUpdateRequest {
            node_id: node_id.to_string(),
            status,
        };

        // Sign the request
        let signed_request = self.sign_request(&request).await?;

        let response = self
            .client
            .post(format!("{}/api/nodes/status", self.base_url))
            .json(&signed_request)
            .send()
            .await?;

        if response.status().is_success() {
            Ok(response.json().await?)
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(KelsError::KeyNotFound(node_id.to_string()))
        } else {
            let err: ErrorResponse = response.json().await?;
            Err(KelsError::ServerError(err.error, err.code))
        }
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
    pub async fn fetch_peers(
        &self,
    ) -> Result<(PeersResponse, HashMap<String, NodeStatus>), KelsError> {
        let response = self
            .client
            .get(format!("{}/api/peers", self.base_url))
            .send()
            .await?;

        if response.status().is_success() {
            let result: PeersResponse = response.json().await?;

            let peer_slice: Vec<_> = result
                .peers
                .iter()
                .filter_map(|p| p.records.last())
                .by_ref()
                .collect();
            let ready_map = self.check_nodes_ready_status(&peer_slice).await?;

            Ok((result, ready_map))
        } else {
            let err: ErrorResponse = response.json().await?;
            Err(KelsError::ServerError(err.error, err.code))
        }
    }

    pub async fn is_peer_authorized(
        &self,
        peer_prefix: &str,
        trusted_prefixes: &HashSet<&'static str>,
        contexts: &[&Verification],
    ) -> Result<bool, KelsError> {
        let (peers_response, _) = self.fetch_peers().await?;
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
                .verify_with_contexts(trusted_prefixes, contexts)
                .is_ok()
        }))
    }

    pub async fn has_ready_peers(&self, exclude_node_id: Option<&str>) -> Result<bool, KelsError> {
        let (nodes, ready_map) = self.fetch_peers().await?;

        for history in nodes.peers {
            let last_record = history.records.last();
            if let Some(record) = last_record
                && record.active
            {
                if let Some(node_id) = exclude_node_id
                    && node_id == record.node_id
                {
                    continue;
                }

                if ready_map.get(&history.prefix) == Some(&NodeStatus::Ready) {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    async fn check_node_ready_status(&self, kels_url: &str) -> NodeStatus {
        let ready_url = format!("{}/ready", kels_url.trim_end_matches('/'));

        let quick_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap_or_else(|_| self.client.clone());

        match quick_client.get(&ready_url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    // Parse the JSON response to check if ready=true
                    if let Ok(body) = response.json::<serde_json::Value>().await
                        && body.get("ready") == Some(&serde_json::Value::Bool(true))
                    {
                        return NodeStatus::Ready;
                    }
                    NodeStatus::Bootstrapping
                } else if response.status().as_u16() == 503 {
                    // SERVICE_UNAVAILABLE means bootstrapping
                    NodeStatus::Bootstrapping
                } else {
                    NodeStatus::Unhealthy
                }
            }
            Err(_) => NodeStatus::Unhealthy,
        }
    }

    async fn check_nodes_ready_status(
        &self,
        peers: &[&Peer],
    ) -> Result<HashMap<String, NodeStatus>, KelsError> {
        let mut map: HashMap<String, NodeStatus> = HashMap::with_capacity(peers.len());

        let futures = peers
            .iter()
            .map(|peer| self.check_node_ready_status(&peer.kels_url));
        let statuses = join_all(futures).await;

        for (peer, status) in peers.iter().zip(statuses.into_iter()) {
            map.insert(peer.prefix.clone(), status);
        }

        Ok(map)
    }

    /// Fetch the registry's KEL for verification.
    ///
    /// Fetch registry key events (paginated).
    ///
    /// This is an unauthenticated endpoint - nodes use this to verify
    /// that peer records are anchored in the registry's KEL.
    pub async fn fetch_registry_key_events(
        &self,
        since: Option<&str>,
        limit: usize,
    ) -> Result<crate::SignedKeyEventPage, KelsError> {
        let mut url = format!("{}/api/registry-kel?limit={}", self.base_url, limit);
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

    /// Fetch a specific federation member's KEL by prefix with optional pagination.
    pub async fn fetch_member_key_events(
        &self,
        prefix: &str,
        since: Option<&str>,
        limit: usize,
    ) -> Result<crate::SignedKeyEventPage, KelsError> {
        let mut url = format!(
            "{}/api/member-kels/{}?limit={}",
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

    /// Batch fetch federation member KELs with optional delta sync.
    ///
    /// Accepts a map of prefix → optional since SAID. If empty, returns all trusted prefixes.
    /// Returns a map of prefix -> SignedKeyEventPage for each requested member.
    pub async fn fetch_all_member_key_events(
        &self,
        request: &crate::BatchKelsRequest,
    ) -> Result<HashMap<String, SignedKeyEventPage>, KelsError> {
        let response = self
            .client
            .post(format!("{}/api/member-kels", self.base_url))
            .json(request)
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

/// Client for interacting with multiple registry services with automatic failover.
#[derive(Clone)]
pub struct MultiRegistryClient {
    urls: Vec<String>,
    timeout: Duration,
    signer: Option<Arc<dyn RegistrySigner>>,
    url_map: HashMap<String, (String, Verification, Vec<SignedKeyEvent>)>,
    prefix_map: HashMap<String, (String, Verification, Vec<SignedKeyEvent>)>,
    trusted_prefixes: HashSet<&'static str>,
}

enum ProposalCandidate<'a> {
    Addition(&'a crate::AdditionWithVotes),
    Removal(&'a crate::RemovalWithVotes),
}

impl MultiRegistryClient {
    /// Create a new multi-registry client with default timeout (no signing capability).
    ///
    /// URLs are tried in order, with automatic failover to the next URL on failure.
    pub fn new(urls: Vec<String>) -> Self {
        Self::with_timeout(urls, Duration::from_secs(10))
    }

    /// Create a new multi-registry client with custom timeout (no signing capability).
    pub fn with_timeout(urls: Vec<String>, timeout: Duration) -> Self {
        Self {
            urls,
            timeout,
            signer: None,
            url_map: HashMap::new(),
            prefix_map: HashMap::new(),
            trusted_prefixes: parse_trusted_prefixes(),
        }
    }

    /// Create a new multi-registry client with signing capability.
    pub fn with_signer(urls: Vec<String>, signer: Arc<dyn RegistrySigner>) -> Self {
        Self::with_signer_and_timeout(urls, signer, Duration::from_secs(10))
    }

    /// Create a new multi-registry client with signing capability and custom timeout.
    pub fn with_signer_and_timeout(
        urls: Vec<String>,
        signer: Arc<dyn RegistrySigner>,
        timeout: Duration,
    ) -> Self {
        Self {
            urls,
            timeout,
            signer: Some(signer),
            url_map: HashMap::new(),
            prefix_map: HashMap::new(),
            trusted_prefixes: parse_trusted_prefixes(),
        }
    }

    /// Get the list of registry URLs.
    pub fn urls(&self) -> &[String] {
        &self.urls
    }

    /// Create a single-URL client for the given URL.
    fn create_client(&self, url: &str) -> KelsRegistryClient {
        match &self.signer {
            Some(signer) => {
                KelsRegistryClient::with_signer_and_timeout(url, signer.clone(), self.timeout)
            }
            None => KelsRegistryClient::with_timeout(url, self.timeout),
        }
    }

    fn create_kels_client(&self, url: &str) -> KelsClient {
        KelsClient::with_timeout(url, self.timeout)
    }

    fn url_for_prefix(&self, prefix: &str) -> Result<String, KelsError> {
        match self.prefix_map.get(prefix) {
            Some((url, ..)) => Ok(url.clone()),
            None => Err(KelsError::RegistryFailure(format!(
                "Could not find registry for prefix {}",
                prefix
            ))),
        }
    }

    pub async fn prefix_for_url(&self, url: &str) -> Result<String, KelsError> {
        match self.url_map.get(url) {
            Some((prefix, ..)) => Ok(prefix.clone()),
            None => {
                let client = self.create_client(url);
                let page = client
                    .fetch_registry_key_events(None, crate::MAX_EVENTS_PER_KEL_RESPONSE)
                    .await?;
                match page.events.first() {
                    Some(e) => Ok(e.event.prefix.clone()),
                    None => Err(KelsError::RegistryFailure(format!(
                        "Prefix not found for url {}",
                        url
                    ))),
                }
            }
        }
    }

    /// Get the cached events for all verified registry KELs.
    ///
    /// Returns an iterator over `(prefix, events)` pairs from the prefix map.
    /// Must be called after `fetch_verified_member_key_events`.
    pub fn cached_events(&self) -> impl Iterator<Item = (&str, &[SignedKeyEvent])> {
        self.prefix_map
            .iter()
            .map(|(prefix, (_, _, events))| (prefix.as_str(), events.as_slice()))
    }

    /// Load locally-stored registry KEL events into the cache.
    ///
    /// Verifies the events with `KelVerifier` and stores them in `prefix_map`.
    /// These entries survive `fetch_verified_member_key_events` — remote data overwrites
    /// local entries for the same prefix, but local entries for prefixes not returned
    /// by remote registries (e.g. removed registries) are preserved.
    pub fn load_local_events(
        &mut self,
        prefix: &str,
        events: Vec<SignedKeyEvent>,
    ) -> Result<(), KelsError> {
        if events.is_empty() || !self.trusted_prefixes.contains(prefix) {
            return Ok(());
        }

        let mut verifier = KelVerifier::new(prefix);
        verifier.verify_page(&events).map_err(|e| {
            KelsError::VerificationFailed(format!("Local KEL verify failed: {}", e))
        })?;
        let ctx = verifier.into_verification()?;

        self.prefix_map
            .insert(prefix.to_string(), (String::new(), ctx, events));
        Ok(())
    }

    /// List all registered nodes as NodeInfo (for client discovery with latency testing).
    ///
    /// Performs full verification: structural integrity, peer anchoring in registry KEL,
    /// and peer vote verification. Peers that fail any check are excluded.
    pub async fn list_verified_nodes_info(
        &mut self,
        prefix: &str,
    ) -> Result<Vec<NodeInfo>, KelsError> {
        self.fetch_verified_member_key_events(false).await?;

        let url = self.url_for_prefix(prefix)?;
        let client = self.create_client(&url);
        match client.fetch_peers().await {
            Ok((response, ready_map)) => {
                self.verify_peers_response(&response).await?;

                let proposals_response = self.fetch_completed_proposals().await.ok();

                let mut nodes = Vec::new();
                for history in response.peers {
                    let Some(peer) = history.records.last() else {
                        continue;
                    };

                    if !peer.active {
                        continue;
                    }

                    // Verify peer record anchoring in authorizing registry KEL
                    match self.verify_peer_anchoring(peer).await {
                        Ok(true) => {}
                        Ok(false) => {
                            warn!(
                                peer_prefix = %peer.peer_prefix,
                                "Peer SAID not anchored in registry KEL, skipping"
                            );
                            continue;
                        }
                        Err(e) => {
                            warn!(
                                peer_prefix = %peer.peer_prefix,
                                error = %e,
                                "Failed to verify peer anchoring, skipping"
                            );
                            continue;
                        }
                    }

                    // Verify proposal + votes
                    if !self
                        .verify_peer_votes(&peer.peer_prefix, &proposals_response)
                        .await
                    {
                        warn!(
                            peer_prefix = %peer.peer_prefix,
                            "Peer not backed by sufficient verified votes, skipping"
                        );
                        continue;
                    }

                    let status = ready_map
                        .get(&peer.prefix)
                        .unwrap_or(&NodeStatus::Bootstrapping);
                    nodes.push(NodeInfo {
                        node_id: peer.node_id.clone(),
                        kels_url: peer.kels_url.clone(),
                        gossip_addr: peer.gossip_addr.clone(),
                        status: *status,
                        latency_ms: None,
                    });
                }

                Ok(nodes)
            }
            Err(e) => Err(KelsError::RegistryFailure(format!(
                "Could not list nodes for registry {}: {}",
                prefix, e
            ))),
        }
    }

    /// Fetch verified peers from any available registry.
    ///
    /// Tries each registry in order, returning on first success.
    /// Since all registries are federated and replicate the same peer data,
    /// any single registry has the complete peer list.
    pub async fn fetch_all_verified_peers(&mut self) -> Result<PeersResponse, KelsError> {
        self.fetch_verified_member_key_events(false).await?;

        for url in &self.urls {
            let client = self.create_client(url);
            match client.fetch_peers().await {
                Ok((response, _ready_map)) => {
                    self.verify_peers_response(&response).await?;
                    return Ok(response);
                }
                Err(e) => {
                    warn!(url = %url, error = %e, "Failed to fetch peers, trying next registry");
                }
            }
        }

        Err(KelsError::RegistryFailure(
            "Could not fetch peers from any registry".to_string(),
        ))
    }

    async fn verify_peers_response(&mut self, response: &PeersResponse) -> Result<(), KelsError> {
        for history in &response.peers {
            let contexts_vec = self.fetch_verified_member_key_events(false).await?;
            let contexts: Vec<&Verification> = contexts_vec.iter().collect();
            history.verify_with_contexts(&self.trusted_prefixes, &contexts)?;
        }

        Ok(())
    }

    /// Verify that a peer record is anchored in its authorizing registry's KEL.
    ///
    /// Returns true if the peer's SAID is found as an anchor in the registry KEL.
    /// Retries once with a forced refetch if not found in the cached KEL.
    pub async fn verify_peer_anchoring(&mut self, peer: &Peer) -> Result<bool, KelsError> {
        let saids = || std::iter::once(peer.said.clone());
        let maybe_ctx = retry_once!(
            self.verify_anchors(&peer.authorizing_kel, saids(), false),
            |ctx: &Verification| ctx.anchors_all_saids(),
            self.verify_anchors(&peer.authorizing_kel, saids(), true),
        )?;

        if maybe_ctx.is_none() {
            debug!(
                peer_prefix = %peer.peer_prefix,
                said = %peer.said,
                authorizing_kel = %peer.authorizing_kel,
                "verify_peer_anchoring: anchor NOT found even after force refetch"
            );
        }

        Ok(maybe_ctx.is_some())
    }

    /// Verify that a peer has an approved proposal backed by sufficient anchored votes.
    ///
    /// Performs full DAG verification:
    /// 1. Structural: proposal chain integrity, vote SAIDs, vote references
    /// 2. Proposal anchoring: each proposal record's SAID anchored in proposer's KEL
    /// 3. Vote anchoring: each approval vote's SAID anchored in voter's KEL
    /// 4. Status: must be Approved with threshold verified votes
    pub async fn verify_peer_votes(
        &mut self,
        peer_prefix: &str,
        proposals_response: &Option<CompletedProposalsResponse>,
    ) -> bool {
        let Some(response) = proposals_response else {
            warn!(peer_prefix = %peer_prefix, "No proposals available for peer vote verification");
            return false;
        };

        // Collect all approved, non-withdrawn proposals for this peer (additions and removals).
        // Each candidate holds a reference to the proposal and whether it's an addition.
        let mut candidates: Vec<(bool, &StorageDatetime, ProposalCandidate<'_>)> = Vec::new();

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
            candidates.push((true, &last.created_at, ProposalCandidate::Addition(awv)));
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
            candidates.push((false, &last.created_at, ProposalCandidate::Removal(rwv)));
        }

        if candidates.is_empty() {
            info!(peer_prefix = %peer_prefix, "No approved proposal found for peer");
            return false;
        }

        // Sort most recent first, then iterate until we find one that verifies.
        candidates.sort_by(|a, b| b.1.cmp(a.1));

        let member_prefixes = trusted_prefixes();

        for (is_addition, _, candidate) in &candidates {
            let (kind, verify_result, proposer, record_saids, votes, threshold) = match candidate {
                ProposalCandidate::Addition(awv) => (
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
                ProposalCandidate::Removal(rwv) => (
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

            if self
                .verify_proposal_dag(
                    peer_prefix,
                    kind,
                    verify_result,
                    proposer,
                    record_saids.into_iter(),
                    votes,
                    threshold,
                    &member_prefixes,
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

    /// Verify a proposal's structural integrity, record anchoring, and vote anchoring.
    ///
    /// Shared verification logic for both addition and removal proposals.
    /// Returns true if the proposal passes all checks.
    #[allow(clippy::too_many_arguments)]
    async fn verify_proposal_dag<'a>(
        &mut self,
        peer_prefix: &str,
        kind: &str,
        structural_result: Result<(), KelsError>,
        proposer: Option<&str>,
        record_saids: impl Iterator<Item = &'a String>,
        votes: &[Vote],
        threshold: usize,
        member_prefixes: &HashSet<&str>,
    ) -> bool {
        // 1. Structural verification
        if let Err(e) = structural_result {
            warn!(peer_prefix = %peer_prefix, error = %e, "{} proposal DAG verification failed", kind);
            return false;
        }

        // 2. Verify proposal anchoring: each record's SAID anchored in proposer's KEL
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

        // 2+3. Batch anchor checks: proposer record SAIDs + proposer's vote SAID
        // in one walk, then each other voter individually.
        let mut proposer_saids: Vec<String> = record_saids.cloned().collect();

        // Collect eligible votes, separating the proposer's vote from others
        let eligible_votes: Vec<&Vote> = votes
            .iter()
            .filter(|v| v.approve && member_prefixes.contains(v.voter.as_str()))
            .collect();

        // If the proposer also voted, include that SAID in the proposer batch
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
        let maybe_ctx = retry_once!(
            self.verify_anchors(&proposer, proposer_saids.iter().cloned(), false),
            |ctx: &Verification| ctx.anchors_all_saids(),
            self.verify_anchors(&proposer, proposer_saids.iter().cloned(), true),
        );

        match maybe_ctx {
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

        // Verify remaining voters (non-proposer) individually
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
            let saids = || std::iter::once(vote.said.clone());
            let maybe_ctx = retry_once!(
                self.verify_anchors(&vote.voter, saids(), false),
                |ctx: &Verification| ctx.anchors_all_saids(),
                self.verify_anchors(&vote.voter, saids(), true),
            );

            match maybe_ctx {
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

    /// Check if a peer is authorized in the allowlist.
    ///
    /// Returns true if the peer_prefix is found in the allowlist with active=true.
    /// This is an unauthenticated check - nodes can verify their authorization
    /// before attempting to register.
    pub async fn is_peer_authorized(&mut self, peer_prefix: &str) -> Result<bool, KelsError> {
        let contexts_vec = self.fetch_verified_member_key_events(false).await?;
        let contexts: Vec<&Verification> = contexts_vec.iter().collect();
        for url in &self.urls {
            let client = self.create_client(url);
            match client
                .is_peer_authorized(peer_prefix, &self.trusted_prefixes, &contexts)
                .await
            {
                Ok(result) => return Ok(result),
                Err(e) => {
                    warn!(url = %url, error = %e, "Failed to check peer authorization, trying next");
                }
            }
        }
        Err(KelsError::RegistryFailure(
            "Could not check peer authorization from any registry".to_string(),
        ))
    }

    pub async fn nodes_sorted_by_latency(
        &mut self,
        registry_prefix: &str,
    ) -> Result<Vec<NodeInfo>, KelsError> {
        let mut nodes = self.list_verified_nodes_info(registry_prefix).await?;

        // Test latency to each Ready node concurrently (with short timeout)
        let latency_futures: Vec<_> = nodes
            .iter()
            .enumerate()
            .filter(|(_, n)| n.status == NodeStatus::Ready)
            .map(|(i, n)| {
                let url = n.kels_url.clone();
                let node_id = n.node_id.clone();
                let registry = self.clone();
                async move {
                    let client = registry.create_kels_client(&url);
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

        let results = futures::future::join_all(latency_futures).await;
        for (i, latency) in results {
            if let Some(lat) = latency {
                nodes[i].latency_ms = Some(lat.as_millis() as u64);
            }
        }

        // Sort: Ready nodes with latency first (by latency), then Ready without latency, then others
        nodes.sort_by(|a, b| match (&a.status, &b.status) {
            (NodeStatus::Ready, NodeStatus::Ready) => match (&a.latency_ms, &b.latency_ms) {
                (Some(a_lat), Some(b_lat)) => a_lat.cmp(b_lat),
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (None, None) => Ordering::Equal,
            },
            (NodeStatus::Ready, _) => Ordering::Less,
            (_, NodeStatus::Ready) => Ordering::Greater,
            _ => Ordering::Equal,
        });

        Ok(nodes)
    }

    /// Fetch the registry's KEL from all registries in parallel.
    ///
    /// This is an unauthenticated endpoint - nodes use this to verify
    /// that peer records are anchored in the registry's KEL.
    /// Unlike other methods, this fetches from ALL registries, not just until one succeeds.
    pub async fn fetch_verified_member_key_events(
        &mut self,
        force_fetch: bool,
    ) -> Result<Vec<Verification>, KelsError> {
        if !self.prefix_map.is_empty() && !force_fetch {
            debug!(
                "fetch_all_member_key_events: using cached KELs ({} entries)",
                self.prefix_map.len()
            );
            return Ok(self
                .prefix_map
                .values()
                .map(|(_, ctx, _)| ctx.clone())
                .collect());
        }

        debug!(
            "fetch_all_member_key_events: force_fetch={}, fetching from {} URLs",
            force_fetch,
            self.urls.len()
        );
        // Don't clear prefix_map — locally-loaded entries (from load_local_events)
        // survive remote fetch. Remote data overwrites per-prefix on success.
        self.url_map.clear();

        // Fetch all member KELs (including decommissioned) from any available registry
        // using the plural endpoint. Any active registry serves all member KELs from
        // Raft-replicated state.
        let batch_request = crate::BatchKelsRequest {
            prefixes: self
                .trusted_prefixes
                .iter()
                .map(|&p| (p.to_string(), None))
                .collect(),
        };

        for url in self.urls.clone() {
            let client = self.create_client(&url);
            match client.fetch_all_member_key_events(&batch_request).await {
                Ok(pages_map) if !pages_map.is_empty() => {
                    let mut contexts: Vec<Verification> = Vec::new();

                    for (prefix, page) in &pages_map {
                        if !self.trusted_prefixes.contains(prefix.as_str()) {
                            warn!(
                                prefix = %prefix,
                                "Ignoring untrusted prefix from member-kels response"
                            );
                            continue;
                        }

                        // Verify the KEL page with KelVerifier
                        let mut verifier = KelVerifier::new(prefix);
                        if let Err(e) = verifier.verify_page(&page.events) {
                            warn!(
                                prefix = %prefix,
                                error = %e,
                                "KEL verification failed, skipping"
                            );
                            continue;
                        }
                        let ctx = verifier.into_verification()?;

                        // Verify prefix is in trusted set
                        if !self.trusted_prefixes.contains(ctx.prefix()) {
                            warn!(
                                prefix = %prefix,
                                "KEL prefix not in trusted set, skipping"
                            );
                            continue;
                        }

                        debug!(
                            "fetch_all_member_key_events: prefix={}, events={}, anchors={}",
                            prefix,
                            page.events.len(),
                            page.events
                                .iter()
                                .filter(|e| e.event.is_interaction())
                                .count(),
                        );
                        self.prefix_map.insert(
                            prefix.clone(),
                            (url.clone(), ctx.clone(), page.events.clone()),
                        );
                        contexts.push(ctx);
                    }

                    if contexts.is_empty() {
                        warn!(url = %url, "No trusted prefixes in response, trying next");
                        continue;
                    }

                    return Ok(contexts);
                }
                Ok(_) => {
                    debug!(url = %url, "fetch_all_member_key_events: empty response, trying next");
                }
                Err(e) => {
                    warn!(url = %url, error = %e, "Failed to fetch registry KELs, trying next");
                }
            }
        }

        Err(KelsError::RegistryFailure(
            "Could not fetch registry KELs from any registry".to_string(),
        ))
    }

    /// Fetch and cache a single registry's verified events.
    ///
    /// Returns the cached `Verification` for the given prefix. If `force_fetch` is true,
    /// re-fetches from the registry.
    async fn fetch_registry_events(
        &mut self,
        prefix: &str,
        force_fetch: bool,
    ) -> Result<(), KelsError> {
        debug!(prefix = %prefix, force_fetch = force_fetch, "fetch_registry_events");
        self.fetch_verified_member_key_events(force_fetch).await?;
        if self.prefix_map.contains_key(prefix) {
            Ok(())
        } else {
            debug!(
                prefix = %prefix,
                available = ?self.prefix_map.keys().collect::<Vec<_>>(),
                "fetch_registry_events: NOT FOUND in prefix_map"
            );
            Err(KelsError::RegistryFailure(format!(
                "Could not find {} in available trusted registries",
                prefix
            )))
        }
    }

    /// Re-verify cached events for a prefix with anchor checking.
    ///
    /// Fetches (or uses cached) events, then runs `KelVerifier` with the given
    /// SAIDs registered for anchor checking. Returns the resulting `Verification`
    /// which can be queried via `anchors_all_saids()`.
    ///
    /// Re-verification is required because anchor SAIDs must be registered before
    /// the walk — the cached `Verification` in `prefix_map` was produced without
    /// these SAIDs and cannot answer anchor queries retroactively. Batch multiple
    /// SAIDs per prefix to avoid redundant walks.
    async fn verify_anchors(
        &mut self,
        prefix: &str,
        saids: impl IntoIterator<Item = String>,
        force_fetch: bool,
    ) -> Result<Verification, KelsError> {
        self.fetch_registry_events(prefix, force_fetch).await?;
        let (_, _, events) = self.prefix_map.get(prefix).ok_or_else(|| {
            KelsError::RegistryFailure(format!(
                "Could not find {} in available trusted registries",
                prefix
            ))
        })?;
        let events = events.clone();
        let mut verifier = KelVerifier::new(prefix);
        verifier.check_anchors(saids);
        verifier.verify_page(&events)?;
        verifier.into_verification()
    }

    /// Fetch completed proposals from any available registry.
    ///
    /// Returns the default filtered response: only approved, non-withdrawn
    /// addition proposals for currently active peers.
    pub async fn fetch_completed_proposals(
        &self,
    ) -> Result<crate::CompletedProposalsResponse, KelsError> {
        self.fetch_proposals_inner("/api/federation/proposals")
            .await
    }

    /// Fetch all completed proposals (unfiltered) from any available registry.
    ///
    /// Returns the full audit response including all additions, removals,
    /// withdrawn and rejected proposals.
    pub async fn fetch_completed_proposals_audit(
        &self,
    ) -> Result<crate::CompletedProposalsResponse, KelsError> {
        self.fetch_proposals_inner("/api/federation/proposals?audit=true")
            .await
    }

    async fn fetch_proposals_inner(
        &self,
        path: &str,
    ) -> Result<crate::CompletedProposalsResponse, KelsError> {
        for url in &self.urls {
            let client = self.create_client(url);
            let response = client
                .client
                .get(format!("{}{}", client.base_url, path))
                .send()
                .await;

            match response {
                Ok(resp) if resp.status().is_success() => {
                    return resp.json().await.map_err(KelsError::from);
                }
                Ok(resp) => {
                    warn!(
                        url = %url,
                        status = %resp.status(),
                        "Failed to fetch proposals"
                    );
                }
                Err(e) => {
                    warn!(url = %url, error = %e, "Failed to fetch proposals");
                }
            }
        }

        Err(KelsError::RegistryFailure(
            "Could not fetch proposals from any registry".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::KeyEventBuilder;
    use crate::crypto::SoftwareKeyProvider;
    use crate::types::{NodeRegistration, NodeType, Peer, PeerHistory};
    use std::time::Duration;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // Mock signer for testing
    struct MockSigner;

    #[async_trait::async_trait]
    impl RegistrySigner for MockSigner {
        async fn sign(&self, _data: &[u8]) -> Result<SignResult, KelsError> {
            Ok(SignResult {
                signature: "0BAAAA_mock_signature".to_string(),
                peer_prefix: "EMockPeerPrefix_____________________________".to_string(),
            })
        }
    }

    // ==================== Constructor Tests ====================

    #[test]
    fn test_new_client() {
        let client = KelsRegistryClient::new("http://registry:8080");
        assert!(client.signer.is_none());
    }

    #[test]
    fn test_with_timeout() {
        let client =
            KelsRegistryClient::with_timeout("http://registry:8080", Duration::from_secs(5));
        assert!(client.signer.is_none());
    }

    #[test]
    fn test_with_signer() {
        let signer = Arc::new(MockSigner);
        let client = KelsRegistryClient::with_signer("http://registry:8080", signer);
        assert!(client.signer.is_some());
    }

    #[test]
    fn test_with_signer_and_timeout() {
        let signer = Arc::new(MockSigner);
        let client = KelsRegistryClient::with_signer_and_timeout(
            "http://registry:8080",
            signer,
            Duration::from_secs(30),
        );
        assert!(client.signer.is_some());
    }

    #[test]
    fn test_url_trailing_slash_stripped() {
        let client = KelsRegistryClient::new("http://registry:8080/");
        assert_eq!(client.base_url, "http://registry:8080");
    }

    // ==================== Registration Tests ====================

    #[tokio::test]
    async fn test_register_success() {
        let mock_server = MockServer::start().await;

        let response = NodeRegistration {
            node_id: "node-1".to_string(),
            node_type: NodeType::Kels,
            kels_url: "http://node-1:8091".to_string(),
            gossip_addr: "10.0.0.1:9000".to_string(),
            registered_at: chrono::Utc::now(),
            last_heartbeat: chrono::Utc::now(),
            status: NodeStatus::Bootstrapping,
        };

        Mock::given(method("POST"))
            .and(path("/api/nodes/register"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response))
            .mount(&mock_server)
            .await;

        let signer = Arc::new(MockSigner);
        let client = KelsRegistryClient::with_signer(&mock_server.uri(), signer);
        let result = client
            .register(
                "node-1",
                "http://node-1:8091",
                "10.0.0.1:9000",
                NodeStatus::Bootstrapping,
            )
            .await;

        assert!(result.is_ok());
        let reg = result.unwrap();
        assert_eq!(reg.node_id, "node-1");
    }

    #[tokio::test]
    async fn test_register_without_signer_fails() {
        let client = KelsRegistryClient::new("http://registry:8080");
        let result = client
            .register(
                "node-1",
                "http://node-1:8091",
                "10.0.0.1:9000",
                NodeStatus::Bootstrapping,
            )
            .await;

        assert!(matches!(result, Err(KelsError::SigningFailed(_))));
    }

    #[tokio::test]
    async fn test_register_server_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/api/nodes/register"))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "error": "Internal error",
                "code": "internal_error"
            })))
            .mount(&mock_server)
            .await;

        let signer = Arc::new(MockSigner);
        let client = KelsRegistryClient::with_signer(&mock_server.uri(), signer);
        let result = client
            .register(
                "node-1",
                "http://node-1:8091",
                "10.0.0.1:9000",
                NodeStatus::Bootstrapping,
            )
            .await;

        assert!(matches!(result, Err(KelsError::ServerError(..))));
    }

    // ==================== Deregistration Tests ====================

    #[tokio::test]
    async fn test_deregister_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/api/nodes/deregister"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let signer = Arc::new(MockSigner);
        let client = KelsRegistryClient::with_signer(&mock_server.uri(), signer);
        let result = client.deregister("node-1").await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_deregister_not_found_ok() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/api/nodes/deregister"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock_server)
            .await;

        let signer = Arc::new(MockSigner);
        let client = KelsRegistryClient::with_signer(&mock_server.uri(), signer);
        let result = client.deregister("node-1").await;

        // 404 is OK for deregister (already deregistered)
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_deregister_without_signer_fails() {
        let client = KelsRegistryClient::new("http://registry:8080");
        let result = client.deregister("node-1").await;

        assert!(matches!(result, Err(KelsError::SigningFailed(_))));
    }

    #[tokio::test]
    async fn test_list_nodes_info() {
        let mock_server = MockServer::start().await;

        let peer = Peer {
            said: "ETestPeerSaid_______________________________".to_string(),
            prefix: "ETestPeerPrefix_____________________________".to_string(),
            previous: None,
            version: 1,
            created_at: chrono::Utc::now().into(),
            peer_prefix: "EPeer1Prefix________________________________".to_string(),
            node_id: "node-1".to_string(),
            authorizing_kel: "EAuthorizingKel_____________________________".to_string(),
            active: true,
            kels_url: "http://node-1:8091".to_string(),
            gossip_addr: "10.0.0.1:9000".to_string(),
        };

        let response = PeersResponse {
            peers: vec![PeerHistory {
                prefix: peer.prefix.clone(),
                records: vec![peer],
            }],
        };

        Mock::given(method("GET"))
            .and(path("/api/peers"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response))
            .mount(&mock_server)
            .await;

        let client = KelsRegistryClient::new(&mock_server.uri());
        let result = client.list_nodes_info().await;

        assert!(result.is_ok());
        let nodes = result.unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].node_id, "node-1");
        assert_eq!(nodes[0].kels_url, "http://node-1:8091");
    }

    // ==================== Update Status Tests ====================

    #[tokio::test]
    async fn test_update_status_success() {
        let mock_server = MockServer::start().await;

        let response = NodeRegistration {
            node_id: "node-1".to_string(),
            node_type: NodeType::Kels,
            kels_url: "http://node-1:8091".to_string(),
            gossip_addr: "10.0.0.1:9000".to_string(),
            registered_at: chrono::Utc::now(),
            last_heartbeat: chrono::Utc::now(),
            status: NodeStatus::Ready,
        };

        Mock::given(method("POST"))
            .and(path("/api/nodes/status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response))
            .mount(&mock_server)
            .await;

        let signer = Arc::new(MockSigner);
        let client = KelsRegistryClient::with_signer(&mock_server.uri(), signer);
        let result = client.update_status("node-1", NodeStatus::Ready).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_update_status_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/api/nodes/status"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock_server)
            .await;

        let signer = Arc::new(MockSigner);
        let client = KelsRegistryClient::with_signer(&mock_server.uri(), signer);
        let result = client.update_status("unknown", NodeStatus::Ready).await;

        assert!(matches!(result, Err(KelsError::KeyNotFound(_))));
    }

    #[tokio::test]
    async fn test_update_status_without_signer_fails() {
        let client = KelsRegistryClient::new("http://registry:8080");
        let result = client.update_status("node-1", NodeStatus::Ready).await;

        assert!(matches!(result, Err(KelsError::SigningFailed(_))));
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
            .and(path("/api/peers"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response))
            .mount(&mock_server)
            .await;

        let client = KelsRegistryClient::new(&mock_server.uri());
        let result = client.fetch_peers().await;

        assert!(result.is_ok());
        let (peers, _status_map) = result.unwrap();
        assert_eq!(peers.peers.len(), 1);
    }

    #[tokio::test]
    async fn test_fetch_peers_server_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/peers"))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "error": "Error",
                "code": "internal_error"
            })))
            .mount(&mock_server)
            .await;

        let client = KelsRegistryClient::new(&mock_server.uri());
        let result = client.fetch_peers().await;

        assert!(matches!(result, Err(KelsError::ServerError(..))));
    }

    // ==================== Registry KEL Tests ====================

    #[tokio::test]
    async fn test_fetch_registry_key_events_success() {
        let mock_server = MockServer::start().await;

        // Create a valid page for response
        let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(), None);
        let icp = builder.incept().await.unwrap();
        let page = crate::SignedKeyEventPage {
            events: vec![icp],
            has_more: false,
        };

        Mock::given(method("GET"))
            .and(path("/api/registry-kel"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&page))
            .mount(&mock_server)
            .await;

        let client = KelsRegistryClient::new(&mock_server.uri());
        let result = client
            .fetch_registry_key_events(None, crate::MAX_EVENTS_PER_KEL_RESPONSE)
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_fetch_registry_key_events_server_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/registry-kel"))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "error": "Error",
                "code": "internal_error"
            })))
            .mount(&mock_server)
            .await;

        let client = KelsRegistryClient::new(&mock_server.uri());
        let result = client
            .fetch_registry_key_events(None, crate::MAX_EVENTS_PER_KEL_RESPONSE)
            .await;

        assert!(matches!(result, Err(KelsError::ServerError(..))));
    }

    // ==================== MultiRegistryClient Tests ====================

    #[test]
    fn test_multi_client_new() {
        let client = MultiRegistryClient::new(vec!["http://registry:8080".to_string()]);
        assert_eq!(client.urls().len(), 1);
        assert!(client.signer.is_none());
    }

    #[test]
    fn test_multi_client_with_multiple_urls() {
        let client = MultiRegistryClient::new(vec![
            "http://registry-a:8080".to_string(),
            "http://registry-b:8080".to_string(),
            "http://registry-c:8080".to_string(),
        ]);
        assert_eq!(client.urls().len(), 3);
    }

    #[test]
    fn test_multi_client_with_timeout() {
        let client = MultiRegistryClient::with_timeout(
            vec!["http://registry:8080".to_string()],
            Duration::from_secs(30),
        );
        assert_eq!(client.timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_multi_client_with_signer() {
        let signer = Arc::new(MockSigner);
        let client =
            MultiRegistryClient::with_signer(vec!["http://registry:8080".to_string()], signer);
        assert!(client.signer.is_some());
    }

    // Note: Old failover tests removed - the new architecture uses prefix-based
    // routing where each registry is identified by its KEL prefix, not URL failover.

    #[tokio::test]
    async fn test_multi_client_all_kels_fail() {
        let server1 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/member-kels"))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "error": "Error 1",
                "code": "internal_error"
            })))
            .mount(&server1)
            .await;

        let server2 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/member-kels"))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "error": "Error 2",
                "code": "internal_error"
            })))
            .mount(&server2)
            .await;

        let mut client = MultiRegistryClient::new(vec![server1.uri(), server2.uri()]);

        let result = client.fetch_verified_member_key_events(false).await;

        assert!(matches!(result, Err(KelsError::RegistryFailure(_))));
    }
}
