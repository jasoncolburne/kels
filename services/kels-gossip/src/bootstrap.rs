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

use kels::{
    BatchKelsRequest, KelsClient, KelsError, MultiRegistryClient, PrefixListResponse, PrefixState,
    SignedKeyEvent,
};
use rand::seq::SliceRandom;
use std::collections::{HashMap, HashSet};
use thiserror::Error;
use tokio::time::Duration;
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
    /// Page size for prefix listing
    pub page_size: usize,
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            node_id: String::new(),
            kels_url: String::new(),
            page_size: 100,
        }
    }
}

/// Result of peer discovery phase.
pub struct DiscoveryResult {
    pub peers: Vec<kels::Peer>,
}

/// Handles bootstrap synchronization from existing peers.
pub struct BootstrapSync {
    config: BootstrapConfig,
    registry: MultiRegistryClient,
    allowlist: crate::allowlist::SharedAllowlist,
    http_client: reqwest::Client,
}

impl BootstrapSync {
    /// Create a new BootstrapSync with an existing registry client and shared allowlist.
    pub fn new(
        config: BootstrapConfig,
        registry: MultiRegistryClient,
        allowlist: crate::allowlist::SharedAllowlist,
    ) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_default();

        Self {
            config,
            registry,
            allowlist,
            http_client,
        }
    }

    /// Phase 1: Discover peers from the allowlist.
    /// Returns peers to connect to for gossip. Call this BEFORE starting the gossip swarm.
    pub async fn discover_peers(&self) -> Result<DiscoveryResult, BootstrapError> {
        info!("Discovering peers for node {}", self.config.node_id);

        let allowlist = self.allowlist.read().await;
        let peers: Vec<kels::Peer> = allowlist.values().cloned().collect();
        info!("Found {} peer(s) in allowlist", peers.len());

        Ok(DiscoveryResult { peers })
    }

    /// Preload KELs from Ready peers while not yet in the allowlist.
    ///
    /// This allows unauthorized nodes to stay in sync with KEL data while waiting
    /// to be added to the allowlist. Called in the unauthorized wait loop.
    /// No registration is performed - just HTTP-based KEL sync.
    pub async fn preload_kels(&self) -> Result<(), BootstrapError> {
        // Get Ready peers from allowlist
        let ready_peers = self.get_ready_peers().await;

        if ready_peers.is_empty() {
            info!("No Ready peers found for preload");
            return Ok(());
        }

        info!(
            "Preloading KELs from {} Ready peer(s)...",
            ready_peers.len()
        );
        self.sync_from_peers(&ready_peers).await?;
        info!("KEL preload complete");

        Ok(())
    }

    /// Get peers from allowlist that are ready (respond to /ready with success).
    async fn get_ready_peers(&self) -> Vec<kels::Peer> {
        let allowlist = self.allowlist.read().await;
        let mut ready_peers = Vec::new();
        for peer in allowlist.values() {
            if self.is_peer_ready(peer).await {
                ready_peers.push(peer.clone());
            }
        }
        ready_peers
    }

    /// Check if a peer is authorized in the allowlist.
    pub async fn is_peer_authorized(&self, peer_id: &str) -> Result<bool, BootstrapError> {
        Ok(self.registry.is_peer_authorized(peer_id).await?)
    }

    /// Check if there are Ready peers we should resync from.
    /// Queries each peer's HTTP /ready endpoint directly.
    pub async fn has_ready_peers(&self) -> bool {
        let allowlist = self.allowlist.read().await;
        for peer in allowlist.values() {
            if self.is_peer_ready(peer).await {
                return true;
            }
        }
        false
    }

    /// Check if a peer is ready by querying its HTTP /ready endpoint.
    async fn is_peer_ready(&self, peer: &kels::Peer) -> bool {
        let http_url = match peer.gossip_http_url() {
            Some(url) => url,
            None => {
                warn!("Could not derive HTTP URL for peer {}", peer.peer_id);
                return false;
            }
        };

        let url = format!("{}/ready", http_url);
        match self.http_client.get(&url).send().await {
            Ok(response) => response.status().is_success(),
            Err(e) => {
                debug!("Peer {} not ready: {}", peer.peer_id, e);
                false
            }
        }
    }

    /// Resync KELs after connecting to the gossip swarm.
    /// This catches any events that occurred between pre-load and joining gossip.
    /// Call this after receiving the first PeerConnected event.
    pub async fn resync_kels(&self) -> Result<(), BootstrapError> {
        // Get Ready peers from allowlist
        let ready_peers = self.get_ready_peers().await;

        if ready_peers.is_empty() {
            info!("No Ready peers found, skipping resync");
            return Ok(());
        }

        info!(
            "Starting resync from {} Ready peer(s)...",
            ready_peers.len()
        );
        self.sync_from_peers(&ready_peers).await?;
        info!("Resync complete");

        Ok(())
    }

    /// Get the URL to use for node-to-node sync.
    fn get_sync_url(peer: &kels::Peer) -> &str {
        &peer.kels_url
    }

    /// Sync KELs from bootstrap peers.
    ///
    /// This collects all unique prefixes from all peers, randomly assigns each
    /// prefix to one peer, then batch-fetches KELs (50 at a time) from each peer.
    async fn sync_from_peers(&self, peers: &[kels::Peer]) -> Result<(), BootstrapError> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bootstrap_config_default() {
        let config = BootstrapConfig::default();
        assert!(config.node_id.is_empty());
        assert!(config.kels_url.is_empty());
        assert_eq!(config.page_size, 100);
    }

    #[test]
    fn test_bootstrap_config_custom() {
        let config = BootstrapConfig {
            node_id: "node-1".to_string(),
            kels_url: "http://localhost:8080".to_string(),
            page_size: 50,
        };
        assert_eq!(config.node_id, "node-1");
        assert_eq!(config.kels_url, "http://localhost:8080");
        assert_eq!(config.page_size, 50);
    }

    #[test]
    fn test_bootstrap_error_display() {
        let kels_error = BootstrapError::Kels(KelsError::ServerError(
            "test".to_string(),
            kels::ErrorCode::InternalError,
        ));
        assert!(kels_error.to_string().contains("KELS/Registry error"));

        let failed_error = BootstrapError::Failed("bootstrap failed".to_string());
        assert_eq!(
            failed_error.to_string(),
            "Bootstrap failed: bootstrap failed"
        );
    }

    #[test]
    fn test_bootstrap_error_from_kels_error() {
        let kels_error =
            KelsError::ServerError("server error".to_string(), kels::ErrorCode::InternalError);
        let bootstrap_error: BootstrapError = kels_error.into();
        assert!(matches!(bootstrap_error, BootstrapError::Kels(_)));
    }

    #[test]
    fn test_discovery_result_creation() {
        let result = DiscoveryResult { peers: vec![] };
        assert!(result.peers.is_empty());
    }

    #[test]
    fn test_get_sync_url() {
        let peer = kels::Peer {
            said: "test-said".to_string(),
            prefix: "test-prefix".to_string(),
            previous: None,
            version: 1,
            created_at: verifiable_storage::StorageDatetime::now(),
            peer_id: "test-peer".to_string(),
            node_id: "node-1".to_string(),
            authorizing_kel: "EAuthorizingKel_____________________________".to_string(),
            active: true,
            scope: kels::PeerScope::Core,
            kels_url: "http://kels:8080".to_string(),
            gossip_multiaddr: "/ip4/127.0.0.1/tcp/4001".to_string(),
        };
        assert_eq!(BootstrapSync::get_sync_url(&peer), "http://kels:8080");
    }
}
