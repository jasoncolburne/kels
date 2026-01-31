//! Bootstrap synchronization for new gossip nodes.
//!
//! When a new node joins the network, it needs to sync existing KELs from peers.
//! The bootstrap process handles the allowlist authorization check and avoids
//! missing events during the transition from unauthorized to authorized state.
//!
//! # Algorithm
//!
//! 1. **Authorization check**: Check if peer is in allowlist via `/api/peers`
//! 2. **If NOT authorized**: Loop:
//!    - Log alert with PeerId (so admin can add it)
//!    - **preload_kels()**: Sync KELs from Ready peers (read-only via HTTP)
//!    - Sleep 5 minutes and recheck allowlist
//! 3. **Once authorized**:
//!    - **discover_peers()**: Query registry, register as Bootstrapping
//!    - Start gossip swarm with discovered peers
//! 4. **If Ready peers exist**: Wait for first `PeerConnected` event
//!    - **resync_kels()**: Catch events missed between preload and connection
//! 5. **If no Ready peers**: Skip resync (we're the first/only node)
//! 6. **mark_ready()**: Update status to Ready
//!
//! The resync in step 4 is critical: while the node was unauthorized, it could
//! preload KELs via HTTP. But events occurring between the last preload and
//! joining the gossip network would be missed. The resync catches these events.

use crate::peer_store::PeerRepository;
use kels::{
    BatchKelsRequest, KelsClient, KelsError, KelsRegistryClient, NodeRegistration, NodeStatus,
    PrefixListResponse, PrefixState, SignedKeyEvent,
};
use rand::seq::SliceRandom;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use thiserror::Error;
use tokio::time::{interval, Duration};
use tracing::{debug, info, warn};

#[derive(Error, Debug)]
pub enum BootstrapError {
    #[error("KELS/Registry error: {0}")]
    Kels(#[from] KelsError),
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Bootstrap failed: {0}")]
    Failed(String),
}

/// Configuration for bootstrap sync
#[derive(Clone)]
pub struct BootstrapConfig {
    /// Node identifier
    pub node_id: String,
    /// Local KELS URL (for this node to use)
    pub kels_url: String,
    /// Advertised KELS URL for external clients
    pub kels_advertise_url: String,
    /// Advertised KELS URL for internal node-to-node sync (defaults to external if not set)
    pub kels_advertise_url_internal: Option<String>,
    /// Gossip multiaddr for registration
    pub gossip_multiaddr: String,
    /// Page size for prefix listing
    pub page_size: usize,
    /// Heartbeat interval in seconds
    pub heartbeat_interval_secs: u64,
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            node_id: String::new(),
            kels_url: String::new(),
            kels_advertise_url: String::new(),
            kels_advertise_url_internal: None,
            gossip_multiaddr: String::new(),
            page_size: 100,
            heartbeat_interval_secs: 30,
        }
    }
}

/// Result of peer discovery phase.
pub struct DiscoveryResult {
    pub peers: Vec<NodeRegistration>,
    pub registry_available: bool,
}

/// Handles bootstrap synchronization from existing peers.
pub struct BootstrapSync {
    config: BootstrapConfig,
    registry: KelsRegistryClient,
    peer_repo: Arc<PeerRepository>,
    http_client: reqwest::Client,
}

impl BootstrapSync {
    /// Create a new BootstrapSync with an existing registry client.
    pub fn new(
        config: BootstrapConfig,
        peer_repo: Arc<PeerRepository>,
        registry: KelsRegistryClient,
    ) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_default();

        Self {
            config,
            registry,
            peer_repo,
            http_client,
        }
    }

    /// Phase 1: Discover peers and register as Bootstrapping.
    /// Returns peers to connect to for gossip. Call this BEFORE starting the gossip swarm.
    ///
    /// Fallback logic:
    /// 1. Try to connect to registry
    /// 2. If registry unavailable, fall back to cached peers
    /// 3. Continue without bootstrap if no peers available (first node)
    pub async fn discover_peers(&self) -> Result<DiscoveryResult, BootstrapError> {
        info!("Discovering peers for node {}", self.config.node_id);

        let (peers, registry_available) =
            match self.registry.list_nodes(Some(&self.config.node_id)).await {
                Ok(nodes) => {
                    info!("Registry available, found {} node(s)", nodes.len());
                    self.peer_repo
                        .try_sync_from_registry(&nodes, &self.config.node_id)
                        .await;
                    (nodes, true)
                }
                Err(e) => {
                    warn!("Registry unavailable: {}. Falling back to cached peers.", e);
                    match self.peer_repo.get_active_peers().await {
                        Ok(cached) => {
                            let nodes: Vec<NodeRegistration> = cached
                                .into_iter()
                                .map(|p| NodeRegistration {
                                    node_id: p.node_id,
                                    node_type: kels::NodeType::Kels,
                                    kels_url: String::new(),
                                    kels_url_internal: None,
                                    gossip_multiaddr: p.gossip_multiaddr,
                                    registered_at: chrono::Utc::now(),
                                    last_heartbeat: chrono::Utc::now(),
                                    status: NodeStatus::Ready,
                                })
                                .collect();
                            info!("Loaded {} cached peer(s)", nodes.len());
                            (nodes, false)
                        }
                        Err(cache_err) => {
                            warn!(
                                "Failed to load cached peers: {}. Starting as first node.",
                                cache_err
                            );
                            (Vec::new(), false)
                        }
                    }
                }
            };

        if peers.is_empty() {
            info!("No existing nodes found - this is the first node");
            if registry_available {
                if let Err(e) = self
                    .registry
                    .register(
                        &self.config.node_id,
                        &self.config.kels_advertise_url,
                        self.config.kels_advertise_url_internal.as_deref(),
                        &self.config.gossip_multiaddr,
                        NodeStatus::Ready,
                    )
                    .await
                {
                    warn!("Failed to register with registry: {}", e);
                }
            }
            info!("Registered as Ready (first node)");
        } else {
            info!("Found {} bootstrap node(s)", peers.len());
            if registry_available {
                if let Err(e) = self
                    .registry
                    .register(
                        &self.config.node_id,
                        &self.config.kels_advertise_url,
                        self.config.kels_advertise_url_internal.as_deref(),
                        &self.config.gossip_multiaddr,
                        NodeStatus::Bootstrapping,
                    )
                    .await
                {
                    warn!("Failed to register as Bootstrapping: {}", e);
                } else {
                    info!("Registered as Bootstrapping");
                }
            }
        }

        Ok(DiscoveryResult {
            peers,
            registry_available,
        })
    }

    /// Preload KELs from Ready peers while not yet in the allowlist.
    ///
    /// This allows unauthorized nodes to stay in sync with KEL data while waiting
    /// to be added to the allowlist. Called in the unauthorized wait loop.
    /// No registration is performed - just HTTP-based KEL sync.
    pub async fn preload_kels(&self) -> Result<(), BootstrapError> {
        // Get current Ready peers via unauthenticated endpoint
        let peers = match self.registry.list_nodes(Some(&self.config.node_id)).await {
            Ok(nodes) => nodes
                .into_iter()
                .filter(|n| n.status == NodeStatus::Ready)
                .collect::<Vec<_>>(),
            Err(e) => {
                warn!("Failed to fetch Ready peers for preload: {}", e);
                return Ok(()); // Continue waiting, don't fail
            }
        };

        if peers.is_empty() {
            info!("No Ready peers found for preload");
            return Ok(());
        }

        info!("Preloading KELs from {} Ready peer(s)...", peers.len());
        self.sync_from_peers(&peers).await?;
        info!("KEL preload complete");

        Ok(())
    }

    /// Check if a peer is authorized in the allowlist.
    pub async fn is_peer_authorized(&self, peer_id: &str) -> Result<bool, BootstrapError> {
        Ok(self.registry.is_peer_authorized(peer_id).await?)
    }

    /// Check if there are Ready peers we should resync from.
    /// Queries /api/nodes/bootstrap to get current Ready peers.
    pub async fn has_ready_peers(&self) -> bool {
        match self.registry.list_nodes(Some(&self.config.node_id)).await {
            Ok(nodes) => !nodes.is_empty(),
            Err(e) => {
                warn!("Failed to check for ready peers: {}", e);
                false
            }
        }
    }

    /// Resync KELs after connecting to the gossip swarm.
    /// This catches any events that occurred between pre-load and joining gossip.
    /// Call this after receiving the first PeerConnected event.
    pub async fn resync_kels(&self) -> Result<(), BootstrapError> {
        // Get current Ready peers (may be different from initial discovery)
        let peers = match self.registry.list_nodes(Some(&self.config.node_id)).await {
            Ok(nodes) => nodes,
            Err(e) => {
                warn!("Failed to fetch peers for resync: {}", e);
                return Ok(());
            }
        };

        if peers.is_empty() {
            info!("No Ready peers found, skipping resync");
            return Ok(());
        }

        info!("Starting resync from {} Ready peer(s)...", peers.len());
        self.sync_from_peers(&peers).await?;
        info!("Resync complete");

        Ok(())
    }

    /// Phase 3: Mark node as Ready after sync completes.
    pub async fn mark_ready(&self, registry_available: bool) {
        if registry_available {
            if let Err(e) = self
                .registry
                .update_status(&self.config.node_id, NodeStatus::Ready)
                .await
            {
                warn!("Failed to update status to Ready: {}", e);
            }
        }
        info!("Bootstrap complete - registered as Ready");
    }

    /// Get the URL to use for node-to-node sync (internal if available, else external).
    fn get_sync_url(peer: &NodeRegistration) -> &str {
        peer.kels_url_internal.as_deref().unwrap_or(&peer.kels_url)
    }

    /// Sync KELs from bootstrap peers.
    ///
    /// This collects all unique prefixes from all peers, randomly assigns each
    /// prefix to one peer, then batch-fetches KELs (50 at a time) from each peer.
    async fn sync_from_peers(&self, peers: &[NodeRegistration]) -> Result<(), BootstrapError> {
        if peers.is_empty() {
            return Ok(());
        }

        let local_client = KelsClient::new(&self.config.kels_url);

        // Step 1: Collect all unique prefixes from all peers that need syncing
        info!("Collecting prefixes from {} peer(s)...", peers.len());
        let mut all_prefixes: HashSet<String> = HashSet::new();

        for peer in peers {
            let peer_url = Self::get_sync_url(peer);
            let mut cursor: Option<String> = None;

            loop {
                match self.fetch_prefix_page(peer_url, cursor.as_deref()).await {
                    Ok(page) => {
                        for state in &page.prefixes {
                            let needs = self.needs_sync(state, &local_client).await;
                            if needs {
                                all_prefixes.insert(state.prefix.clone());
                            }
                        }
                        cursor = page.next_cursor;
                        if cursor.is_none() {
                            break;
                        }
                    }
                    Err(e) => {
                        warn!("Failed to fetch prefixes from {}: {}", peer.node_id, e);
                        break;
                    }
                }
            }
        }

        let prefix_count = all_prefixes.len();
        if prefix_count == 0 {
            info!("No prefixes need syncing");
            return Ok(());
        }

        info!("Found {} unique prefixes needing sync", prefix_count);

        // Step 2: Randomly assign each prefix to one peer
        let mut rng = rand::thread_rng();
        let mut peer_assignments: HashMap<String, Vec<String>> = HashMap::new();

        for prefix in all_prefixes {
            let peer_option = peers.choose(&mut rng);
            if let Some(peer) = peer_option {
                let peer_url = Self::get_sync_url(peer).to_string();
                peer_assignments.entry(peer_url).or_default().push(prefix);
            } else {
                unreachable!("Inconsistent: found prefixes but have no peers?")
            }
        }

        info!("Assigned prefixes to {} peer(s)", peer_assignments.len());

        // Step 3: Batch fetch KELs from each peer (50 at a time) - all peers in parallel
        const BATCH_SIZE: usize = 50;

        // Build all batch tasks across all peers
        let mut batch_tasks = Vec::new();
        for (peer_url, prefixes) in peer_assignments {
            info!("Syncing {} prefixes from {}", prefixes.len(), peer_url);

            for chunk in prefixes.chunks(BATCH_SIZE) {
                let chunk_vec: Vec<String> = chunk.to_vec();
                batch_tasks.push((peer_url.clone(), chunk_vec));
            }
        }

        // Run all batch fetches in parallel
        let batch_futures: Vec<_> = batch_tasks
            .iter()
            .map(|(peer_url, chunk)| self.batch_fetch_and_submit(peer_url, chunk, &local_client))
            .collect();

        let all_results = futures::future::join_all(batch_futures).await;

        // Process results
        let mut total_synced = 0;
        let mut total_errors = 0;
        let mut total_not_found = 0;

        for (batch_idx, results) in all_results.into_iter().enumerate() {
            let (_peer_url, chunk) = &batch_tasks[batch_idx];
            for (i, result) in results.into_iter().enumerate() {
                match result {
                    Ok(true) => total_synced += 1,
                    Ok(false) => {
                        total_not_found += 1;
                    }
                    Err(e) => {
                        let prefix = chunk.get(i).map(|s| s.as_str()).unwrap_or("?");
                        warn!("Failed to sync prefix {}: {}", prefix, e);
                        total_errors += 1;
                    }
                }
            }
        }

        info!(
            "Bootstrap sync complete: {} KELs synced, {} not found, {} errors",
            total_synced, total_not_found, total_errors
        );

        Ok(())
    }

    /// Batch fetch KELs from a peer using the batch endpoint and submit to local KELS.
    /// Makes a single HTTP request to fetch all prefixes, then submits each KEL individually.
    async fn batch_fetch_and_submit(
        &self,
        peer_url: &str,
        prefixes: &[String],
        local_client: &KelsClient,
    ) -> Vec<Result<bool, BootstrapError>> {
        if prefixes.is_empty() {
            return vec![];
        }

        // Build batch request
        let request = BatchKelsRequest {
            prefixes: prefixes.to_vec(),
        };

        // Fetch all KELs in a single request
        let url = format!("{}/api/kels/kels", peer_url.trim_end_matches('/'));
        let response = match self.http_client.post(&url).json(&request).send().await {
            Ok(resp) => resp,
            Err(e) => {
                let err_msg = format!("HTTP request failed: {}", e);
                return prefixes
                    .iter()
                    .map(|_| Err(BootstrapError::Failed(err_msg.clone())))
                    .collect();
            }
        };

        if !response.status().is_success() {
            let err_msg = format!("Batch fetch failed: {}", response.status());
            return prefixes
                .iter()
                .map(|_| Err(BootstrapError::Failed(err_msg.clone())))
                .collect();
        }

        let events_map: HashMap<String, Vec<SignedKeyEvent>> = match response.json().await {
            Ok(map) => map,
            Err(e) => {
                let err_msg = format!("Failed to parse response: {}", e);
                return prefixes
                    .iter()
                    .map(|_| Err(BootstrapError::Failed(err_msg.clone())))
                    .collect();
            }
        };

        // Submit each KEL to local KELS
        let mut results = Vec::with_capacity(prefixes.len());
        for prefix in prefixes {
            let result = match events_map.get(prefix) {
                Some(events) if !events.is_empty() => {
                    debug!("Fetched {} events for {} from peer", events.len(), prefix);
                    match local_client.submit_events(events).await {
                        Ok(submit_result) => {
                            if submit_result.accepted {
                                info!("Synced KEL for {} ({} events)", prefix, events.len());
                                Ok(true)
                            } else {
                                warn!(
                                    "KEL for {} not accepted: diverged_at={:?}",
                                    prefix, submit_result.diverged_at
                                );
                                // Still consider it synced - divergence will be handled by gossip protocol
                                Ok(true)
                            }
                        }
                        Err(e) => Err(BootstrapError::Kels(e)),
                    }
                }
                Some(_) | None => Ok(false), // Peer doesn't have it or empty
            };
            results.push(result);
        }

        results
    }

    /// Fetch a single page of prefix states.
    async fn fetch_prefix_page(
        &self,
        kels_url: &str,
        cursor: Option<&str>,
    ) -> Result<PrefixListResponse, BootstrapError> {
        let mut url = format!(
            "{}/api/kels/prefixes?limit={}",
            kels_url.trim_end_matches('/'),
            self.config.page_size
        );
        if let Some(c) = cursor {
            url.push_str(&format!("&since={}", c));
        }

        let response: PrefixListResponse = self.http_client.get(&url).send().await?.json().await?;

        Ok(response)
    }

    /// Check if a prefix needs syncing by comparing with local state.
    async fn needs_sync(&self, remote_state: &PrefixState, local_client: &KelsClient) -> bool {
        match local_client.get_kel(&remote_state.prefix).await {
            Ok(kel) => {
                // Check if latest local SAID matches remote
                kel.events()
                    .last()
                    .map(|e| e.event.said != remote_state.said)
                    .unwrap_or(true) // Empty KEL = needs sync
            }
            Err(KelsError::KeyNotFound(_)) => true,
            Err(_) => true, // On error, try to sync anyway
        }
    }
}

/// Run heartbeat loop in the background.
/// This keeps the node registered as healthy in the registry.
/// If the node is not found, it will re-register with the provided config.
pub async fn run_heartbeat_loop(config: BootstrapConfig, client: KelsRegistryClient) {
    let mut ticker = interval(Duration::from_secs(config.heartbeat_interval_secs));

    info!(
        "Starting heartbeat loop for node {} (interval: {}s)",
        config.node_id, config.heartbeat_interval_secs
    );

    loop {
        ticker.tick().await;

        match client.heartbeat(&config.node_id).await {
            Ok(_) => {
                info!("Heartbeat sent successfully");
            }
            Err(KelsError::KeyNotFound(_)) => {
                // Node was removed from registry, re-register
                warn!("Node not found in registry, attempting re-registration");
                match client
                    .register(
                        &config.node_id,
                        &config.kels_advertise_url,
                        config.kels_advertise_url_internal.as_deref(),
                        &config.gossip_multiaddr,
                        NodeStatus::Ready,
                    )
                    .await
                {
                    Ok(_) => info!("Re-registered successfully"),
                    Err(e) => warn!(
                        "Re-registration failed (node may not be in allowlist yet): {}",
                        e
                    ),
                }
            }
            Err(e) => {
                warn!("Heartbeat failed (node may not be in allowlist yet): {}", e);
            }
        }
    }
}
