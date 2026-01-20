//! Bootstrap synchronization for new gossip nodes.
//!
//! When a new node joins the network, it needs to sync existing KELs from peers.
//! The bootstrap process:
//! 1. Query registry for existing ready nodes
//! 2. If no nodes exist, register immediately as Ready
//! 3. If nodes exist, register as Bootstrapping, sync from peers, then update to Ready

use crate::peer_store::PeerRepository;
use crate::registry_client::{NodeRegistration, NodeStatus, RegistryClient, RegistryError};
use kels::{KelsClient, KelsError, PrefixListResponse, PrefixState};
use std::sync::Arc;
use thiserror::Error;
use tokio::time::{interval, Duration};
use tracing::{debug, info, warn};

#[derive(Error, Debug)]
pub enum BootstrapError {
    #[error("Registry error: {0}")]
    Registry(#[from] RegistryError),
    #[error("KELS client error: {0}")]
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
    /// Advertised KELS URL (for other nodes to reach this node's KELS)
    pub kels_advertise_url: String,
    /// Gossip multiaddr for registration
    pub gossip_multiaddr: String,
    /// Registry service URL
    pub registry_url: String,
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
            gossip_multiaddr: String::new(),
            registry_url: String::new(),
            page_size: 100,
            heartbeat_interval_secs: 30,
        }
    }
}

/// Handles bootstrap synchronization from existing peers.
pub struct BootstrapSync {
    config: BootstrapConfig,
    registry: RegistryClient,
    peer_repo: Arc<PeerRepository>,
    http_client: reqwest::Client,
}

impl BootstrapSync {
    pub fn new(config: BootstrapConfig, peer_repo: Arc<PeerRepository>) -> Self {
        let registry = RegistryClient::new(&config.registry_url);
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

    /// Run the bootstrap process.
    /// Returns the list of peer nodes to connect to for gossip.
    ///
    /// Fallback logic:
    /// 1. Try to connect to registry
    /// 2. If registry unavailable, fall back to cached peers
    /// 3. Continue without bootstrap if no peers available (first node)
    pub async fn run(&self) -> Result<Vec<NodeRegistration>, BootstrapError> {
        info!("Starting bootstrap sync for node {}", self.config.node_id);

        // Try to get bootstrap nodes from registry
        let (bootstrap_nodes, registry_available) = match self
            .registry
            .get_bootstrap_nodes(Some(&self.config.node_id))
            .await
        {
            Ok(nodes) => {
                info!("Registry available, found {} node(s)", nodes.len());
                // Sync registry data to peer cache
                self.peer_repo
                    .try_sync_from_registry(&nodes, &self.config.node_id)
                    .await;
                (nodes, true)
            }
            Err(e) => {
                warn!("Registry unavailable: {}. Falling back to cached peers.", e);
                // Fall back to cached peers
                match self.peer_repo.get_active_peers().await {
                    Ok(peers) => {
                        let nodes: Vec<NodeRegistration> = peers
                            .into_iter()
                            .map(|p| NodeRegistration {
                                node_id: p.node_id,
                                kels_url: String::new(), // Not needed for gossip
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

        if bootstrap_nodes.is_empty() {
            info!("No existing nodes found - this is the first node");
            // Try to register as Ready if registry is available
            if registry_available {
                if let Err(e) = self
                    .registry
                    .register(
                        &self.config.node_id,
                        &self.config.kels_advertise_url,
                        &self.config.gossip_multiaddr,
                        NodeStatus::Ready,
                    )
                    .await
                {
                    warn!("Failed to register with registry: {}", e);
                }
            }
            info!("Registered as Ready (first node)");
            return Ok(Vec::new());
        }

        info!(
            "Found {} bootstrap node(s), starting sync",
            bootstrap_nodes.len()
        );

        // Register as Bootstrapping if registry available
        if registry_available {
            if let Err(e) = self
                .registry
                .register(
                    &self.config.node_id,
                    &self.config.kels_advertise_url,
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

        // Sync from all bootstrap nodes
        self.sync_from_peers(&bootstrap_nodes).await?;

        // Update status to Ready if registry available
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

        Ok(bootstrap_nodes)
    }

    /// Sync KELs from a single bootstrap peer using streaming pagination.
    /// Fetches pages of prefix states and syncs KELs concurrently.
    async fn sync_from_peer(
        &self,
        peer: &NodeRegistration,
    ) -> Result<(usize, usize), BootstrapError> {
        let local_client = KelsClient::new(&self.config.kels_url);
        let mut cursor: Option<String> = None;
        let mut pending_prefixes: Vec<String> = Vec::new();
        let mut synced_count = 0;
        let mut error_count = 0;
        let mut page_num = 0;

        loop {
            page_num += 1;
            // Take current batch to process
            let prefixes_to_sync = std::mem::take(&mut pending_prefixes);

            info!(
                "Bootstrap page {}: syncing {} prefixes, fetching with cursor={:?}",
                page_num,
                prefixes_to_sync.len(),
                cursor
            );

            // Concurrently: fetch next page AND sync current batch
            let (page_result, sync_results) = tokio::join!(
                self.fetch_prefix_page(&peer.kels_url, cursor.as_deref()),
                self.sync_prefixes(&prefixes_to_sync, peer, &local_client)
            );

            // Process sync results
            for (i, result) in sync_results.into_iter().enumerate() {
                match result {
                    Ok(true) => synced_count += 1,
                    Ok(false) => {} // Already in sync or peer doesn't have it
                    Err(e) => {
                        let prefix = prefixes_to_sync.get(i).map(|s| s.as_str()).unwrap_or("?");
                        warn!("Failed to sync prefix {}: {}", prefix, e);
                        error_count += 1;
                    }
                }
            }

            // Process page result
            match page_result {
                Ok(page) => {
                    let page_size = page.prefixes.len();
                    let mut needs_sync_count = 0;

                    // Filter to prefixes that need syncing
                    for state in page.prefixes {
                        if self.needs_sync(&state, &local_client).await {
                            needs_sync_count += 1;
                            pending_prefixes.push(state.prefix);
                        }
                    }

                    info!(
                        "Bootstrap page {}: fetched {} prefixes, {} need sync, next_cursor={:?}",
                        page_num, page_size, needs_sync_count, page.next_cursor
                    );

                    cursor = page.next_cursor;

                    // If no more pages and no pending work, we're done
                    if cursor.is_none() && pending_prefixes.is_empty() {
                        break;
                    }
                }
                Err(e) => {
                    warn!("Failed to fetch page from {}: {}", peer.node_id, e);
                    // Process remaining pending prefixes then exit
                    if pending_prefixes.is_empty() {
                        break;
                    }
                }
            }
        }

        info!(
            "Bootstrap sync from {} complete: {} synced, {} errors",
            peer.node_id, synced_count, error_count
        );

        Ok((synced_count, error_count))
    }

    /// Sync KELs from bootstrap peers.
    async fn sync_from_peers(&self, peers: &[NodeRegistration]) -> Result<(), BootstrapError> {
        let mut total_synced = 0;
        let mut total_errors = 0;

        for peer in peers {
            info!("Syncing from peer {}", peer.node_id);
            match self.sync_from_peer(peer).await {
                Ok((synced, errors)) => {
                    total_synced += synced;
                    total_errors += errors;
                    info!(
                        "Peer {}: {} synced, {} errors",
                        peer.node_id, synced, errors
                    );
                }
                Err(e) => {
                    warn!("Failed to sync from peer {}: {}", peer.node_id, e);
                }
            }
        }

        info!(
            "Bootstrap sync complete: {} KELs synced, {} errors",
            total_synced, total_errors
        );

        Ok(())
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
        match local_client.fetch_full_kel(&remote_state.prefix).await {
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

    /// Sync a batch of prefixes concurrently.
    async fn sync_prefixes(
        &self,
        prefixes: &[String],
        peer: &NodeRegistration,
        local_client: &KelsClient,
    ) -> Vec<Result<bool, BootstrapError>> {
        let futures: Vec<_> = prefixes
            .iter()
            .map(|prefix| self.fetch_and_submit_kel(&peer.kels_url, prefix, local_client))
            .collect();

        futures::future::join_all(futures).await
    }

    /// Fetch a KEL from a peer and submit to local KELS.
    /// Returns Ok(true) if successfully synced, Ok(false) if peer doesn't have it.
    async fn fetch_and_submit_kel(
        &self,
        peer_kels_url: &str,
        prefix: &str,
        local_client: &KelsClient,
    ) -> Result<bool, BootstrapError> {
        // Create a client for the peer
        let peer_client = KelsClient::new(peer_kels_url);

        // Fetch the full KEL from peer
        let kel = match peer_client.fetch_full_kel(prefix).await {
            Ok(kel) => kel,
            Err(KelsError::KeyNotFound(_)) => return Ok(false),
            Err(e) => return Err(BootstrapError::Kels(e)),
        };

        if kel.events().is_empty() {
            return Ok(false);
        }

        debug!(
            "Fetched {} events for {} from peer",
            kel.events().len(),
            prefix
        );

        // Submit to local KELS
        let result = local_client.submit_events(kel.events()).await?;
        if result.accepted {
            info!("Synced KEL for {} ({} events)", prefix, kel.events().len());
            Ok(true)
        } else {
            warn!(
                "KEL for {} not accepted: diverged_at={:?}",
                prefix, result.diverged_at
            );
            // Still consider it synced - divergence will be handled by gossip protocol
            Ok(true)
        }
    }
}

/// Run heartbeat loop in the background.
/// This keeps the node registered as healthy in the registry.
/// If the node is not found, it will re-register with the provided config.
pub async fn run_heartbeat_loop(config: BootstrapConfig) {
    let client = RegistryClient::new(&config.registry_url);
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
            Err(RegistryError::NotFound(_)) => {
                // Node was removed from registry, re-register
                warn!("Node not found in registry, re-registering");
                match client
                    .register(
                        &config.node_id,
                        &config.kels_advertise_url,
                        &config.gossip_multiaddr,
                        NodeStatus::Ready,
                    )
                    .await
                {
                    Ok(_) => info!("Re-registered successfully"),
                    Err(e) => warn!("Re-registration failed: {}", e),
                }
            }
            Err(e) => {
                warn!("Heartbeat failed: {}", e);
            }
        }
    }
}
